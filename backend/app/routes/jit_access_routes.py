"""
JIT Access Routes
API endpoints for Just-in-Time access request management
"""

from flask import Blueprint, request, jsonify
from functools import wraps
from datetime import datetime, timedelta
import uuid

from app.services.auth_service import auth_service
from app.services.jit_access_service import get_jit_access_service, JITAccessRequest, JITAccessStatus
from app.models.user import get_user_by_id
from app.models.resource_segment import get_resource_segment_by_id, get_segments_by_role
from app.models.audit_log import create_audit_log
from app.models.notification import create_notification
from app.firebase_config import get_firestore_client
from app.middleware.security import rate_limit, sanitize_input, validate_request_size
import logging

logger = logging.getLogger(__name__)

bp = Blueprint('jit_access', __name__, url_prefix='/api/jit-access')


def require_auth(f):
    """Decorator to require authentication for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_token = request.cookies.get('session_token')
        
        if not session_token:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'AUTH_REQUIRED',
                    'message': 'Authentication required'
                }
            }), 401
        
        try:
            payload = auth_service.verify_session_token(session_token)
            request.user_id = payload['user_id']
            request.user_role = payload['role']
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'AUTH_INVALID_TOKEN',
                    'message': str(e)
                }
            }), 401
    
    return decorated_function


def get_client_ip():
    """Get client IP address from request"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr


def get_device_info():
    """Get device information from request headers"""
    return {
        'userAgent': request.headers.get('User-Agent', ''),
        'platform': request.headers.get('Sec-Ch-Ua-Platform', 'unknown'),
        'browser': request.headers.get('Sec-Ch-Ua', 'unknown')
    }


@bp.route('/request', methods=['POST'])
@require_auth
@rate_limit('access_request')  # Uses access_request rate limit configuration
@validate_request_size()
@sanitize_input()
def submit_jit_request():
    """
    Submit new JIT access request
    
    Request Body:
        - resourceSegmentId: Resource segment ID
        - justification: Detailed justification (minimum 50 characters)
        - duration: Duration in hours (1-24)
        - urgency: Urgency level (low, medium, high)
    
    Returns:
        JIT access decision with risk assessment and ML evaluation
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['resourceSegmentId', 'justification', 'duration', 'urgency']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'success': False,
                    'error': {
                        'code': 'VALIDATION_ERROR',
                        'message': f'Missing required field: {field}'
                    }
                }), 400
        
        # Validate field values
        duration = data.get('duration')
        if not isinstance(duration, int) or duration < 1 or duration > 24:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'VALIDATION_ERROR',
                    'message': 'Duration must be between 1 and 24 hours'
                }
            }), 400
        
        justification = data.get('justification', '').strip()
        if len(justification) < 50:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'VALIDATION_ERROR',
                    'message': 'Justification must be at least 50 characters'
                }
            }), 400
        
        urgency = data.get('urgency')
        if urgency not in ['low', 'medium', 'high']:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'VALIDATION_ERROR',
                    'message': 'Urgency must be low, medium, or high'
                }
            }), 400
        
        # Get authenticated user info
        user_id = request.user_id
        user_role = request.user_role
        
        # Get user from database
        db = get_firestore_client()
        user = get_user_by_id(db, user_id)
        
        if not user or not user.is_active:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'USER_INACTIVE',
                    'message': 'User account is not active'
                }
            }), 403
        
        # Get resource segment
        segment = get_resource_segment_by_id(db, data['resourceSegmentId'])
        if not segment:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'SEGMENT_NOT_FOUND',
                    'message': 'Resource segment not found'
                }
            }), 404
        
        # Check if segment requires JIT access
        if not segment.requires_jit:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'JIT_NOT_REQUIRED',
                    'message': 'This resource segment does not require JIT access'
                }
            }), 400
        
        # Get client metadata
        ip_address = get_client_ip()
        device_info = get_device_info()
        
        # Create JIT access request
        jit_request = JITAccessRequest(
            user_id=user_id,
            resource_segment_id=data['resourceSegmentId'],
            justification=justification,
            duration_hours=duration,
            urgency=urgency
        )
        
        # Prepare request data for evaluation
        request_data = {
            'userId': user_id,
            'resourceSegmentId': data['resourceSegmentId'],
            'justification': justification,
            'durationHours': duration,
            'urgency': urgency,
            'deviceInfo': device_info,
            'ipAddress': ip_address,
            'timestamp': datetime.utcnow()
        }
        
        # Evaluate request using JIT access service
        jit_service = get_jit_access_service(db)
        from app.utils.async_helper import run_async
        evaluation_result = run_async(jit_service.evaluate_jit_request(request_data))
        
        # Update JIT request with evaluation results
        jit_request.status = JITAccessStatus(evaluation_result['decision'])
        jit_request.risk_assessment = evaluation_result.get('riskAssessment', {})
        jit_request.ml_evaluation = evaluation_result.get('mlEvaluation', {})
        jit_request.confidence_score = evaluation_result.get('confidenceScore', 0)
        jit_request.approval_recommendations = evaluation_result.get('approvalRecommendations', [])
        
        # Set expiration if granted
        if evaluation_result['decision'] == 'granted':
            jit_request.granted_at = datetime.utcnow()
            jit_request.expires_at = datetime.utcnow() + timedelta(hours=duration)
            jit_request.granted_by = 'automated_system'
        elif evaluation_result['decision'] == 'denied':
            jit_request.denial_reason = evaluation_result.get('message', 'Access denied')
        
        # Store JIT request in Firestore
        jit_ref = db.collection('jitAccessRequests').document(jit_request.request_id)
        jit_ref.set(jit_request.to_dict())
        
        # Create audit log
        from app.utils.async_helper import run_async
        # Add sub_type to details since it's not a valid argument for create_audit_log
        audit_details = {
            'sub_type': 'request_submitted',
            'request_id': jit_request.request_id,
            'decision': evaluation_result['decision'],
            'confidence_score': evaluation_result.get('confidenceScore', 0),
            'duration_hours': duration,
            'urgency': urgency,
            'risk_score': evaluation_result.get('riskAssessment', {}).get('riskScore', 0)
        }
        
        create_audit_log(
            db,
            event_type='access_request',
            user_id=user_id,
            resource=data['resourceSegmentId'],
            action=f'JIT access request for {segment.name}',
            result='success',
            details=audit_details
        )
        
        # Create notification for user
        run_async(_create_jit_notification(
            db, user_id, jit_request.request_id, evaluation_result['decision'], segment.name
        ))
        
        # If requires approval, notify administrators
        if evaluation_result.get('requiresApproval', False):
            run_async(_notify_administrators_for_jit_approval(db, jit_request, segment))
        
        # Prepare response
        response_data = {
            'success': True,
            'requestId': jit_request.request_id,
            'decision': evaluation_result['decision'],
            'confidenceScore': evaluation_result.get('confidenceScore', 0),
            'message': evaluation_result.get('message', 'JIT access request processed'),
            'riskAssessment': evaluation_result.get('riskAssessment', {}),
            'mlEvaluation': evaluation_result.get('mlEvaluation', {}),
            'approvalRecommendations': evaluation_result.get('approvalRecommendations', []),
            'requiresApproval': evaluation_result.get('requiresApproval', False),
            'mfaRequired': evaluation_result.get('mfaRequired', False)
        }
        
        # Add expiration time if granted
        if jit_request.expires_at:
            response_data['expiresAt'] = jit_request.expires_at.isoformat()
        
        return jsonify(response_data), 201
        
    except Exception as e:
        error_message = str(e)
        status_code = 500
        
        if "validation" in error_message.lower():
            error_code = 'VALIDATION_ERROR'
            status_code = 400
        elif "not found" in error_message.lower():
            error_code = 'RESOURCE_NOT_FOUND'
            status_code = 404
        else:
            error_code = 'REQUEST_FAILED'
        
        return jsonify({
            'success': False,
            'error': {
                'code': error_code,
                'message': error_message
            }
        }), status_code


@bp.route('/history', methods=['GET'])
@require_auth
def get_jit_history():
    """
    Get user's JIT access request history
    
    Query Parameters:
        - status: Filter by status (optional)
        - limit: Maximum number of results (default: 50)
        - offset: Pagination offset (default: 0)
    
    Returns:
        List of JIT access requests
    """
    try:
        user_id = request.user_id
        
        # Get query parameters
        status_filter = request.args.get('status')
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
        
        # Get user's JIT requests
        db = get_firestore_client()
        requests_ref = db.collection('jitAccessRequests')
        
        # Build query
        query = requests_ref.where('userId', '==', user_id)
        
        # Apply status filter if provided
        if status_filter:
            query = query.where('status', '==', status_filter)
        
        # Get all requests (Firestore doesn't support offset without ordering)
        all_requests = []
        for doc in query.stream():
            request_data = doc.to_dict()
            
            # Convert timestamps to ISO format
            for field in ['requestedAt', 'grantedAt', 'expiresAt']:
                if field in request_data and isinstance(request_data[field], datetime):
                    request_data[field] = request_data[field].isoformat()
            
            # Add segment name for display
            segment = get_resource_segment_by_id(db, request_data.get('resourceSegmentId'))
            if segment:
                request_data['segmentName'] = segment.name
                request_data['securityLevel'] = segment.security_level
            
            all_requests.append(request_data)
        
        # Sort by requested date (newest first)
        all_requests.sort(
            key=lambda x: x.get('requestedAt', ''), 
            reverse=True
        )
        
        # Apply pagination
        total_count = len(all_requests)
        paginated_requests = all_requests[offset:offset + limit]
        
        return jsonify({
            'success': True,
            'requests': paginated_requests,
            'totalCount': total_count,
            'limit': limit,
            'offset': offset
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'HISTORY_FETCH_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('/<request_id>', methods=['GET'])
@require_auth
def get_jit_request_details(request_id):
    """
    Get detailed information about specific JIT access request
    
    Path Parameters:
        - request_id: JIT access request ID
    
    Returns:
        JIT access request details with risk assessment and ML evaluation
    """
    try:
        user_id = request.user_id
        user_role = request.user_role
        
        # Get JIT access request
        db = get_firestore_client()
        jit_ref = db.collection('jitAccessRequests').document(request_id)
        jit_doc = jit_ref.get()
        
        if not jit_doc.exists:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'REQUEST_NOT_FOUND',
                    'message': 'JIT access request not found'
                }
            }), 404
        
        jit_data = jit_doc.to_dict()
        
        # Check authorization (user can only view their own requests, admins can view all)
        if jit_data.get('userId') != user_id and user_role != 'admin':
            return jsonify({
                'success': False,
                'error': {
                    'code': 'INSUFFICIENT_PERMISSIONS',
                    'message': 'You do not have permission to view this request'
                }
            }), 403
        
        # Convert timestamps to ISO format
        for field in ['requestedAt', 'grantedAt', 'expiresAt']:
            if field in jit_data and isinstance(jit_data[field], datetime):
                jit_data[field] = jit_data[field].isoformat()
        
        # Add segment information
        segment = get_resource_segment_by_id(db, jit_data.get('resourceSegmentId'))
        if segment:
            jit_data['segmentInfo'] = {
                'name': segment.name,
                'description': segment.description,
                'securityLevel': segment.security_level,
                'category': segment.category
            }
        
        # Add user information if admin is viewing
        if user_role == 'admin' and jit_data.get('userId') != user_id:
            user = get_user_by_id(db, jit_data.get('userId'))
            if user:
                jit_data['userInfo'] = {
                    'name': user.name,
                    'email': user.email,
                    'role': user.role,
                    'department': user.department
                }
        
        return jsonify({
            'success': True,
            'request': jit_data
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'REQUEST_FETCH_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('/<request_id>/revoke', methods=['PUT'])
@require_auth
def revoke_jit_access(request_id):
    """
    Revoke active JIT access
    
    Path Parameters:
        - request_id: JIT access request ID
    
    Request Body:
        - reason: Revocation reason (optional)
    
    Returns:
        Revocation confirmation
    """
    try:
        user_id = request.user_id
        user_role = request.user_role
        
        data = request.get_json() or {}
        revocation_reason = data.get('reason', 'Manual revocation')
        
        # Get JIT access request
        db = get_firestore_client()
        jit_ref = db.collection('jitAccessRequests').document(request_id)
        jit_doc = jit_ref.get()
        
        if not jit_doc.exists:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'REQUEST_NOT_FOUND',
                    'message': 'JIT access request not found'
                }
            }), 404
        
        jit_data = jit_doc.to_dict()
        
        # Check authorization (user can revoke their own active access, admins can revoke any)
        if jit_data.get('userId') != user_id and user_role != 'admin':
            return jsonify({
                'success': False,
                'error': {
                    'code': 'INSUFFICIENT_PERMISSIONS',
                    'message': 'You do not have permission to revoke this access'
                }
            }), 403
        
        # Check if access is currently active
        if jit_data.get('status') != 'granted':
            return jsonify({
                'success': False,
                'error': {
                    'code': 'INVALID_STATUS',
                    'message': 'Only granted access can be revoked'
                }
            }), 400
        
        # Update request status
        update_data = {
            'status': 'revoked',
            'revokedAt': datetime.utcnow(),
            'revokedBy': user_id,
            'revocationReason': revocation_reason
        }
        
        jit_ref.update(update_data)
        
        # Create audit log
        segment = get_resource_segment_by_id(db, jit_data.get('resourceSegmentId'))
        create_audit_log(
            db,
            event_type='access_request',
            user_id=user_id,
            resource=jit_data.get('resourceSegmentId'),
            action=f'JIT access revoked for {segment.name if segment else "unknown segment"}',
            result='success',
            details={
                'sub_type': 'access_revoked',
                'request_id': request_id,
                'target_user_id': jit_data.get('userId'),
                'reason': revocation_reason,
                'revoked_by_role': user_role
            }
        )
        
        # Create notification for affected user (if admin revoked someone else's access)
        if jit_data.get('userId') != user_id:
            run_async(create_notification(
                db,
                user_id=jit_data.get('userId'),
                title='JIT Access Revoked',
                message=f'Your JIT access to {segment.name if segment else "resource"} has been revoked by an administrator',
                notification_type='access_revoked',
                priority='high',
                data={
                    'request_id': request_id,
                    'reason': revocation_reason
                }
            ))
        
        return jsonify({
            'success': True,
            'message': 'JIT access revoked successfully',
            'revokedAt': update_data['revokedAt'].isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'REVOCATION_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('/active', methods=['GET'])
@require_auth
def get_active_jit_access():
    """
    Get user's currently active JIT access grants
    
    Returns:
        List of active JIT access grants
    """
    try:
        user_id = request.user_id
        
        # Get active JIT requests
        db = get_firestore_client()
        requests_ref = db.collection('jitAccessRequests')
        query = requests_ref.where('userId', '==', user_id).where('status', '==', 'granted')
        
        active_requests = []
        current_time = datetime.utcnow()
        
        for doc in query.stream():
            request_data = doc.to_dict()
            
            # Check if access has expired
            expires_at = request_data.get('expiresAt')
            if expires_at and isinstance(expires_at, datetime) and expires_at < current_time:
                # Mark as expired
                doc.reference.update({'status': 'expired'})
                continue
            
            # Convert timestamps to ISO format
            for field in ['requestedAt', 'grantedAt', 'expiresAt']:
                if field in request_data and isinstance(request_data[field], datetime):
                    request_data[field] = request_data[field].isoformat()
            
            # Add segment information
            segment = get_resource_segment_by_id(db, request_data.get('resourceSegmentId'))
            if segment:
                request_data['segmentInfo'] = {
                    'name': segment.name,
                    'description': segment.description,
                    'securityLevel': segment.security_level,
                    'category': segment.category
                }
            
            # Calculate time remaining
            if expires_at and isinstance(expires_at, datetime):
                time_remaining = expires_at - current_time
                request_data['timeRemainingSeconds'] = max(0, int(time_remaining.total_seconds()))
            
            active_requests.append(request_data)
        
        return jsonify({
            'success': True,
            'activeRequests': active_requests,
            'count': len(active_requests)
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'ACTIVE_FETCH_FAILED',
                'message': str(e)
            }
        }), 500


async def _create_jit_notification(db, user_id: str, request_id: str, decision: str, segment_name: str):
    """Create notification for JIT access decision"""
    try:
        if decision == 'granted':
            title = 'JIT Access Granted'
            message = f'Your JIT access request for {segment_name} has been approved'
        elif decision == 'denied':
            title = 'JIT Access Denied'
            message = f'Your JIT access request for {segment_name} has been denied'
        elif decision == 'pending_approval':
            title = 'JIT Access Pending'
            message = f'Your JIT access request for {segment_name} is pending administrator approval'
        else:
            title = 'JIT Access Update'
            message = f'Your JIT access request for {segment_name} has been updated'
        
        run_async(create_notification(
            db=db,
            user_id=user_id,
            title=title,
            message=message,
            notification_type='jit_access_decision',
            priority='medium' if decision == 'granted' else 'high',
            data={
                'request_id': request_id,
                'decision': decision,
                'segment_name': segment_name
            }
        ))
        
    except Exception as e:
        logger.error(f"Error creating JIT notification: {str(e)}")


async def _notify_administrators_for_jit_approval(db, jit_request: JITAccessRequest, segment):
    """Notify administrators about JIT request requiring approval"""
    try:
        # Get all admin users
        users_ref = db.collection('users')
        admin_query = users_ref.where('role', '==', 'admin').where('isActive', '==', True)
        
        for admin_doc in admin_query.stream():
            admin_data = admin_doc.to_dict()
            
            run_async(create_notification(
                db,
                user_id=admin_data['userId'],
                title='JIT Access Approval Required',
                message=f'JIT access request for {segment.name} (Level {segment.security_level}) requires approval',
                notification_type='jit_approval_request',
                priority='high',
                data={
                    'request_id': jit_request.request_id,
                    'segment_id': jit_request.resource_segment_id,
                    'segment_name': segment.name,
                    'security_level': segment.security_level,
                    'user_id': jit_request.user_id,
                    'urgency': jit_request.urgency,
                    'confidence_score': jit_request.confidence_score
                }
            ))
        
    except Exception as e:
        logger.error(f"Error notifying administrators: {str(e)}")