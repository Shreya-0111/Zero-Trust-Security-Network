"""
Admin JIT Access Routes
API endpoints for administrator management of JIT access requests
"""

from flask import Blueprint, request, jsonify
from functools import wraps
from datetime import datetime, timedelta

from app.services.auth_service import auth_service
from app.services.jit_access_service import get_jit_access_service, JITAccessStatus
from app.models.user import get_user_by_id
from app.models.resource_segment import get_resource_segment_by_id
from app.models.audit_log import create_audit_log
from app.models.notification import create_notification
from app.firebase_config import get_firestore_client

bp = Blueprint('admin_jit', __name__, url_prefix='/api/admin/jit-access')


def require_admin(f):
    """Decorator to require admin authentication for routes"""
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
            
            # Check if user is admin
            if request.user_role != 'admin':
                return jsonify({
                    'success': False,
                    'error': {
                        'code': 'INSUFFICIENT_PERMISSIONS',
                        'message': 'Administrator privileges required'
                    }
                }), 403
            
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


@bp.route('/requests', methods=['GET'])
@require_admin
def get_all_jit_requests():
    """
    Get all JIT access requests for admin oversight
    
    Query Parameters:
        - status: Filter by status (optional)
        - user_id: Filter by user ID (optional)
        - segment_id: Filter by segment ID (optional)
        - limit: Maximum number of results (default: 100)
        - offset: Pagination offset (default: 0)
    
    Returns:
        List of JIT access requests with user and segment information
    """
    try:
        # Get query parameters
        status_filter = request.args.get('status')
        user_id_filter = request.args.get('user_id')
        segment_id_filter = request.args.get('segment_id')
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        
        # Get JIT requests from Firestore
        db = get_firestore_client()
        requests_ref = db.collection('jitAccessRequests')
        
        # Build query
        query = requests_ref
        
        # Apply filters
        if status_filter:
            query = query.where('status', '==', status_filter)
        if user_id_filter:
            query = query.where('userId', '==', user_id_filter)
        if segment_id_filter:
            query = query.where('resourceSegmentId', '==', segment_id_filter)
        
        # Get all matching requests
        all_requests = []
        for doc in query.stream():
            request_data = doc.to_dict()
            
            # Convert timestamps to ISO format
            for field in ['requestedAt', 'grantedAt', 'expiresAt', 'revokedAt']:
                if field in request_data and isinstance(request_data[field], datetime):
                    request_data[field] = request_data[field].isoformat()
            
            # Add user information
            user = get_user_by_id(db, request_data.get('userId'))
            if user:
                request_data['userInfo'] = {
                    'name': user.name,
                    'email': user.email,
                    'role': user.role,
                    'department': user.department
                }
            
            # Add segment information
            segment = get_resource_segment_by_id(db, request_data.get('resourceSegmentId'))
            if segment:
                request_data['segmentInfo'] = {
                    'name': segment.name,
                    'description': segment.description,
                    'securityLevel': segment.security_level,
                    'category': segment.category
                }
            
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
                'code': 'REQUESTS_FETCH_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('/<request_id>/approve', methods=['PUT'])
@require_admin
def approve_jit_request(request_id):
    """
    Approve a pending JIT access request
    
    Path Parameters:
        - request_id: JIT access request ID
    
    Request Body:
        - comments: Optional approval comments
        - duration_override: Optional duration override in hours
    
    Returns:
        Approval confirmation with access details
    """
    try:
        admin_id = request.user_id
        data = request.get_json() or {}
        comments = data.get('comments', '')
        duration_override = data.get('duration_override')
        
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
        
        # Check if request is pending approval
        if jit_data.get('status') != 'pending_approval':
            return jsonify({
                'success': False,
                'error': {
                    'code': 'INVALID_STATUS',
                    'message': 'Only pending requests can be approved'
                }
            }), 400
        
        # Get user and segment information
        user = get_user_by_id(db, jit_data.get('userId'))
        segment = get_resource_segment_by_id(db, jit_data.get('resourceSegmentId'))
        
        if not user or not segment:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'INVALID_REQUEST',
                    'message': 'User or segment not found'
                }
            }), 400
        
        # Calculate expiration time
        duration_hours = duration_override or jit_data.get('durationHours', 1)
        granted_at = datetime.utcnow()
        expires_at = granted_at + timedelta(hours=duration_hours)
        
        # Update request status
        update_data = {
            'status': 'granted',
            'grantedAt': granted_at,
            'expiresAt': expires_at,
            'grantedBy': admin_id,
            'approvalComments': comments
        }
        
        if duration_override:
            update_data['durationHours'] = duration_override
        
        jit_ref.update(update_data)
        
        # Create audit log
        from app.utils.async_helper import run_async
        run_async(create_audit_log(
            db,
            event_type='jit_access',
            sub_type='request_approved',
            user_id=admin_id,
            target_user_id=jit_data.get('userId'),
            resource_segment_id=jit_data.get('resourceSegmentId'),
            action=f'JIT access approved for {segment.name}',
            result='success',
            details={
                'request_id': request_id,
                'duration_hours': duration_hours,
                'comments': comments,
                'expires_at': expires_at.isoformat()
            }
        ))
        
        # Create notification for user
        run_async(create_notification(
            db,
            user_id=jit_data.get('userId'),
            title='JIT Access Approved',
            message=f'Your JIT access request for {segment.name} has been approved',
            notification_type='jit_access_approved',
            priority='medium',
            data={
                'request_id': request_id,
                'segment_name': segment.name,
                'duration_hours': duration_hours,
                'expires_at': expires_at.isoformat(),
                'comments': comments
            }
        ))
        
        return jsonify({
            'success': True,
            'message': 'JIT access request approved successfully',
            'grantedAt': granted_at.isoformat(),
            'expiresAt': expires_at.isoformat(),
            'durationHours': duration_hours
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'APPROVAL_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('/<request_id>/deny', methods=['PUT'])
@require_admin
def deny_jit_request(request_id):
    """
    Deny a pending JIT access request
    
    Path Parameters:
        - request_id: JIT access request ID
    
    Request Body:
        - reason: Denial reason (required)
        - comments: Optional additional comments
    
    Returns:
        Denial confirmation
    """
    try:
        admin_id = request.user_id
        data = request.get_json() or {}
        reason = data.get('reason', '').strip()
        comments = data.get('comments', '')
        
        if not reason:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'VALIDATION_ERROR',
                    'message': 'Denial reason is required'
                }
            }), 400
        
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
        
        # Check if request is pending approval
        if jit_data.get('status') != 'pending_approval':
            return jsonify({
                'success': False,
                'error': {
                    'code': 'INVALID_STATUS',
                    'message': 'Only pending requests can be denied'
                }
            }), 400
        
        # Get segment information
        segment = get_resource_segment_by_id(db, jit_data.get('resourceSegmentId'))
        
        # Update request status
        update_data = {
            'status': 'denied',
            'deniedAt': datetime.utcnow(),
            'deniedBy': admin_id,
            'denialReason': reason,
            'denialComments': comments
        }
        
        jit_ref.update(update_data)
        
        # Create audit log
        run_async(create_audit_log(
            db,
            event_type='jit_access',
            sub_type='request_denied',
            user_id=admin_id,
            target_user_id=jit_data.get('userId'),
            resource_segment_id=jit_data.get('resourceSegmentId'),
            action=f'JIT access denied for {segment.name if segment else "unknown segment"}',
            result='success',
            details={
                'request_id': request_id,
                'reason': reason,
                'comments': comments
            }
        ))
        
        # Create notification for user
        run_async(create_notification(
            db,
            user_id=jit_data.get('userId'),
            title='JIT Access Denied',
            message=f'Your JIT access request for {segment.name if segment else "resource"} has been denied',
            notification_type='jit_access_denied',
            priority='medium',
            data={
                'request_id': request_id,
                'segment_name': segment.name if segment else 'Unknown',
                'reason': reason,
                'comments': comments
            }
        ))
        
        return jsonify({
            'success': True,
            'message': 'JIT access request denied successfully',
            'deniedAt': update_data['deniedAt'].isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'DENIAL_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('/stats', methods=['GET'])
@require_admin
def get_jit_stats():
    """
    Get JIT access statistics for admin dashboard
    
    Returns:
        Statistics about JIT access requests and usage
    """
    try:
        db = get_firestore_client()
        
        # Get all JIT requests
        requests_ref = db.collection('jitAccessRequests')
        all_requests = []
        
        for doc in requests_ref.stream():
            request_data = doc.to_dict()
            all_requests.append(request_data)
        
        # Calculate statistics
        total_requests = len(all_requests)
        
        # Status breakdown
        status_counts = {}
        for request in all_requests:
            status = request.get('status', 'unknown')
            status_counts[status] = status_counts.get(status, 0) + 1
        
        # Recent activity (last 7 days)
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        recent_requests = [
            req for req in all_requests
            if req.get('requestedAt') and 
            (isinstance(req['requestedAt'], datetime) and req['requestedAt'] > seven_days_ago)
        ]
        
        # Urgency breakdown
        urgency_counts = {}
        for request in all_requests:
            urgency = request.get('urgency', 'unknown')
            urgency_counts[urgency] = urgency_counts.get(urgency, 0) + 1
        
        # Security level breakdown
        security_level_counts = {}
        for request in all_requests:
            # Get segment to determine security level
            segment_id = request.get('resourceSegmentId')
            if segment_id:
                segment = get_resource_segment_by_id(db, segment_id)
                if segment:
                    level = f"Level {segment.security_level}"
                    security_level_counts[level] = security_level_counts.get(level, 0) + 1
        
        # Average approval time (for approved requests)
        approved_requests = [
            req for req in all_requests
            if req.get('status') == 'granted' and 
            req.get('requestedAt') and req.get('grantedAt')
        ]
        
        avg_approval_time_hours = 0
        if approved_requests:
            total_approval_time = 0
            for req in approved_requests:
                requested_at = req['requestedAt']
                granted_at = req['grantedAt']
                
                if isinstance(requested_at, datetime) and isinstance(granted_at, datetime):
                    approval_time = granted_at - requested_at
                    total_approval_time += approval_time.total_seconds()
            
            if total_approval_time > 0:
                avg_approval_time_hours = total_approval_time / len(approved_requests) / 3600
        
        # Active sessions (currently granted and not expired)
        current_time = datetime.utcnow()
        active_sessions = []
        
        for request in all_requests:
            if (request.get('status') == 'granted' and 
                request.get('expiresAt') and
                isinstance(request.get('expiresAt'), datetime) and
                request['expiresAt'] > current_time):
                active_sessions.append(request)
        
        stats = {
            'totalRequests': total_requests,
            'statusBreakdown': status_counts,
            'recentActivity': {
                'last7Days': len(recent_requests),
                'requests': recent_requests[-10:]  # Last 10 recent requests
            },
            'urgencyBreakdown': urgency_counts,
            'securityLevelBreakdown': security_level_counts,
            'averageApprovalTimeHours': round(avg_approval_time_hours, 2),
            'activeSessions': {
                'count': len(active_sessions),
                'sessions': active_sessions[:5]  # Top 5 active sessions
            }
        }
        
        return jsonify({
            'success': True,
            'stats': stats
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'STATS_FETCH_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('/cleanup-expired', methods=['POST'])
@require_admin
def cleanup_expired_access():
    """
    Cleanup expired JIT access grants (mark as expired)
    
    Returns:
        Cleanup results
    """
    try:
        admin_id = request.user_id
        
        # Get expired but still active grants
        db = get_firestore_client()
        requests_ref = db.collection('jitAccessRequests')
        query = requests_ref.where('status', '==', 'granted')
        
        current_time = datetime.utcnow()
        expired_count = 0
        
        for doc in query.stream():
            request_data = doc.to_dict()
            expires_at = request_data.get('expiresAt')
            
            if expires_at and isinstance(expires_at, datetime) and expires_at < current_time:
                # Mark as expired
                doc.reference.update({
                    'status': 'expired',
                    'expiredAt': current_time,
                    'expiredBy': 'system_cleanup'
                })
                expired_count += 1
                
                # Create audit log
                run_async(create_audit_log(
                    db,
                    event_type='jit_access',
                    sub_type='access_expired',
                    user_id='system',
                    target_user_id=request_data.get('userId'),
                    resource_segment_id=request_data.get('resourceSegmentId'),
                    action='JIT access expired automatically',
                    result='success',
                    details={
                        'request_id': request_data.get('requestId'),
                        'expired_at': current_time.isoformat(),
                        'cleanup_triggered_by': admin_id
                    }
                ))
        
        return jsonify({
            'success': True,
            'message': f'Cleanup completed: {expired_count} expired access grants processed',
            'expiredCount': expired_count
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'CLEANUP_FAILED',
                'message': str(e)
            }
        }), 500