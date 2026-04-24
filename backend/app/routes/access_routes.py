"""
Access Request Routes
API endpoints for access request submission and management
"""

from flask import Blueprint, request, jsonify
from functools import wraps
from app.services.auth_service import auth_service
from app.services.policy_engine import policy_engine
from app.models.access_request import create_access_request, get_access_request_by_id, update_access_request
from app.models.user import get_user_by_id
from app.models.notification import create_notification
from app.firebase_config import get_firestore_client
from app.middleware.security import rate_limit, sanitize_input, validate_request_size, get_sanitized_data
from datetime import datetime, timedelta

bp = Blueprint('access', __name__, url_prefix='/api/access')

# Rate limiting storage (in-memory for simplicity, use Redis in production)
rate_limit_storage = {}


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


def require_auth(f):
    """Decorator to require authentication for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get session token from cookie
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
            # Verify session token
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


def check_rate_limit(user_id, limit=10, window_hours=1):
    """
    Check if user has exceeded rate limit for access requests
    
    Args:
        user_id (str): User ID
        limit (int): Maximum number of requests allowed
        window_hours (int): Time window in hours
        
    Returns:
        tuple: (is_allowed, remaining_requests)
    """
    now = datetime.utcnow()
    cutoff_time = now - timedelta(hours=window_hours)
    
    # Initialize user's request history if not exists
    if user_id not in rate_limit_storage:
        rate_limit_storage[user_id] = []
    
    # Remove old requests outside the time window
    rate_limit_storage[user_id] = [
        timestamp for timestamp in rate_limit_storage[user_id]
        if timestamp > cutoff_time
    ]
    
    # Check if limit exceeded
    current_count = len(rate_limit_storage[user_id])
    if current_count >= limit:
        return False, 0
    
    # Add current request timestamp
    rate_limit_storage[user_id].append(now)
    
    return True, limit - current_count - 1


@bp.route('/request', methods=['POST'])
@require_auth
@rate_limit('access_request')
@validate_request_size()
@sanitize_input()
def submit_access_request():
    """
    Submit new access request
    
    Request Body:
        - resource: Resource type being requested
        - intent: Intent description (minimum 20 characters, 5 words)
        - duration: Requested duration (e.g., '7 days', '1 month')
        - urgency: Urgency level (low, medium, high)
    
    Returns:
        Access request decision with confidence score
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['resource', 'intent', 'duration', 'urgency']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'success': False,
                    'error': {
                        'code': 'VALIDATION_ERROR',
                        'message': f'Missing required field: {field}'
                    }
                }), 400
        
        # Get authenticated user info
        user_id = request.user_id
        user_role = request.user_role
        
        # Check rate limit (10 requests per hour)
        is_allowed, remaining = check_rate_limit(user_id, limit=10, window_hours=1)
        if not is_allowed:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'RATE_LIMIT_EXCEEDED',
                    'message': 'You have exceeded the maximum number of access requests (10 per hour). Please try again later.'
                }
            }), 429
        
        # Get client metadata
        ip_address = get_client_ip()
        device_info = get_device_info()
        session_token = request.cookies.get('session_token')
        
        # Get user from database to ensure they're active
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
        
        # Create access request
        access_request = create_access_request(
            db=db,
            user_id=user_id,
            user_role=user_role,
            requested_resource=data['resource'],
            intent=data['intent'],
            duration=data['duration'],
            urgency=data['urgency'],
            ip_address=ip_address,
            device_info=device_info,
            session_id=session_token
        )
        
        # Prepare request data for policy engine evaluation
        request_data = {
            'userId': user_id,
            'userRole': user_role,
            'requestedResource': data['resource'],
            'intent': data['intent'],
            'duration': data['duration'],
            'urgency': data['urgency'],
            'ipAddress': ip_address,
            'deviceInfo': device_info,
            'timestamp': datetime.utcnow()
        }
        
        # Evaluate request using policy engine
        evaluation_result = policy_engine.evaluate_request(request_data)
        
        # Update access request with evaluation result
        access_request.set_evaluation_result(evaluation_result)
        
        # Prepare update data
        update_data = {
            'decision': access_request.decision,
            'confidenceScore': access_request.confidence_score,
            'confidenceBreakdown': access_request.confidence_breakdown,
            'policiesApplied': access_request.policies_applied,
            'denialReason': access_request.denial_reason
        }
        
        # Add contextual breakdown if available
        if 'contextualBreakdown' in evaluation_result:
            update_data['contextualBreakdown'] = evaluation_result['contextualBreakdown']
            update_data['contextualScore'] = evaluation_result.get('contextualScore', 0)
        
        # Update the request in Firestore
        update_access_request(db, access_request.request_id, update_data)
        
        # Create notification for user
        _create_access_request_notification(
            db=db,
            user_id=user_id,
            request_id=access_request.request_id,
            decision=access_request.decision,
            resource=data['resource']
        )
        
        # Prepare response
        response_data = {
            'success': True,
            'requestId': access_request.request_id,
            'decision': access_request.decision,
            'confidenceScore': access_request.confidence_score,
            'message': evaluation_result.get('message', 'Request processed successfully'),
            'mfaRequired': evaluation_result.get('mfaRequired', False),
            'stepUpAuthRequired': evaluation_result.get('stepUpAuthRequired', False),
            'confidenceBreakdown': access_request.confidence_breakdown,
            'policiesApplied': access_request.policies_applied
        }
        
        # Add contextual data if available
        if 'contextualBreakdown' in evaluation_result:
            response_data['contextualBreakdown'] = evaluation_result['contextualBreakdown']
            response_data['contextualScore'] = evaluation_result.get('contextualScore', 0)
        
        # Add expiration time if granted
        if access_request.expires_at:
            response_data['expiresAt'] = access_request.expires_at.isoformat()
        
        return jsonify(response_data), 201
    
    except Exception as e:
        error_message = str(e)
        status_code = 400
        
        if "validation failed" in error_message.lower():
            error_code = 'VALIDATION_ERROR'
        elif "rate limit" in error_message.lower():
            error_code = 'RATE_LIMIT_EXCEEDED'
            status_code = 429
        else:
            error_code = 'REQUEST_FAILED'
            status_code = 500
        
        return jsonify({
            'success': False,
            'error': {
                'code': error_code,
                'message': error_message
            }
        }), status_code


@bp.route('/history', methods=['GET'])
@require_auth
def get_access_history():
    """
    Get user's access request history
    
    Query Parameters:
        - status: Filter by status (optional)
        - startDate: Filter by start date (optional)
        - endDate: Filter by end date (optional)
        - limit: Maximum number of results (default: 50)
        - offset: Pagination offset (default: 0)
    
    Returns:
        List of access requests
    """
    try:
        user_id = request.user_id
        
        # Get query parameters
        status_filter = request.args.get('status')
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
        
        # Get user's access requests
        db = get_firestore_client()
        requests_ref = db.collection('accessRequests')
        
        # Build query
        query = requests_ref.where('userId', '==', user_id)
        
        # Apply status filter if provided
        if status_filter:
            query = query.where('decision', '==', status_filter)
        
        # Try to order by timestamp (requires Firestore index)
        # If it fails, we'll just return unordered results
        all_requests = []
        try:
            query = query.order_by('timestamp', direction='DESCENDING')
            for doc in query.stream():
                request_data = doc.to_dict()
                # Convert timestamp to ISO format if it's a datetime object
                if isinstance(request_data.get('timestamp'), datetime):
                    request_data['timestamp'] = request_data['timestamp'].isoformat()
                all_requests.append(request_data)
        except Exception as query_error:
            # If ordering fails (missing index), get without ordering
            print(f"Warning: Could not order by timestamp: {query_error}")
            query = requests_ref.where('userId', '==', user_id)
            if status_filter:
                query = query.where('decision', '==', status_filter)
            for doc in query.stream():
                request_data = doc.to_dict()
                if isinstance(request_data.get('timestamp'), datetime):
                    request_data['timestamp'] = request_data['timestamp'].isoformat()
                all_requests.append(request_data)
        
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
        print(f"Error fetching access history: {e}")
        return jsonify({
            'success': False,
            'error': {
                'code': 'HISTORY_FETCH_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('/<request_id>', methods=['GET'])
@require_auth
def get_request_details(request_id):
    """
    Get detailed information about specific access request
    
    Path Parameters:
        - request_id: Access request ID
    
    Returns:
        Access request details with confidence breakdown
    """
    try:
        user_id = request.user_id
        user_role = request.user_role
        
        # Get access request
        db = get_firestore_client()
        access_request = get_access_request_by_id(db, request_id)
        
        if not access_request:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'REQUEST_NOT_FOUND',
                    'message': 'Access request not found'
                }
            }), 404
        
        # Check authorization (user can only view their own requests, admins can view all)
        if access_request.user_id != user_id and user_role != 'admin':
            return jsonify({
                'success': False,
                'error': {
                    'code': 'INSUFFICIENT_PERMISSIONS',
                    'message': 'You do not have permission to view this request'
                }
            }), 403
        
        # Prepare response
        request_dict = access_request.to_dict()
        
        # Convert timestamp to ISO format if it's a datetime object
        if isinstance(request_dict.get('timestamp'), datetime):
            request_dict['timestamp'] = request_dict['timestamp'].isoformat()
        if isinstance(request_dict.get('expiresAt'), datetime):
            request_dict['expiresAt'] = request_dict['expiresAt'].isoformat()
        
        return jsonify({
            'success': True,
            'request': request_dict,
            'confidenceBreakdown': access_request.confidence_breakdown
        }), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'REQUEST_FETCH_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('/<request_id>/resubmit', methods=['PUT'])
@require_auth
@rate_limit('access_request')
@validate_request_size()
@sanitize_input()
def resubmit_access_request(request_id):
    """
    Resubmit a denied access request with updated information
    
    Path Parameters:
        - request_id: Original access request ID
    
    Request Body:
        - intent: Updated intent description (optional)
        - duration: Updated duration (optional)
        - urgency: Updated urgency level (optional)
    
    Returns:
        New access request with decision
    """
    try:
        user_id = request.user_id
        user_role = request.user_role
        
        # Get original access request
        db = get_firestore_client()
        original_request = get_access_request_by_id(db, request_id)
        
        if not original_request:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'REQUEST_NOT_FOUND',
                    'message': 'Original access request not found'
                }
            }), 404
        
        # Check authorization (user can only resubmit their own requests)
        if original_request.user_id != user_id:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'INSUFFICIENT_PERMISSIONS',
                    'message': 'You can only resubmit your own requests'
                }
            }), 403
        
        # Check if original request was denied
        if original_request.decision != 'denied':
            return jsonify({
                'success': False,
                'error': {
                    'code': 'INVALID_REQUEST_STATUS',
                    'message': 'Only denied requests can be resubmitted'
                }
            }), 400
        
        # Check rate limit (10 requests per hour)
        is_allowed, remaining = check_rate_limit(user_id, limit=10, window_hours=1)
        if not is_allowed:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'RATE_LIMIT_EXCEEDED',
                    'message': 'You have exceeded the maximum number of access requests (10 per hour). Please try again later.'
                }
            }), 429
        
        # Get updated data from request body
        data = request.get_json() or {}
        
        # Use updated values or fall back to original values
        resource = data.get('resource', original_request.requested_resource)
        intent = data.get('intent', original_request.intent)
        duration = data.get('duration', original_request.duration)
        urgency = data.get('urgency', original_request.urgency)
        
        # Get client metadata
        ip_address = get_client_ip()
        device_info = get_device_info()
        session_token = request.cookies.get('session_token')
        
        # Create new access request
        new_request = create_access_request(
            db=db,
            user_id=user_id,
            user_role=user_role,
            requested_resource=resource,
            intent=intent,
            duration=duration,
            urgency=urgency,
            ip_address=ip_address,
            device_info=device_info,
            session_id=session_token
        )
        
        # Prepare request data for policy engine evaluation
        request_data = {
            'userId': user_id,
            'userRole': user_role,
            'requestedResource': resource,
            'intent': intent,
            'duration': duration,
            'urgency': urgency,
            'ipAddress': ip_address,
            'deviceInfo': device_info,
            'timestamp': datetime.utcnow(),
            'isResubmission': True,
            'originalRequestId': request_id
        }
        
        # Evaluate request using policy engine
        evaluation_result = policy_engine.evaluate_request(request_data)
        
        # Update access request with evaluation result
        new_request.set_evaluation_result(evaluation_result)
        
        # Update the request in Firestore
        update_access_request(db, new_request.request_id, {
            'decision': new_request.decision,
            'confidenceScore': new_request.confidence_score,
            'confidenceBreakdown': new_request.confidence_breakdown,
            'policiesApplied': new_request.policies_applied,
            'denialReason': new_request.denial_reason
        })
        
        # Create notification for user
        _create_access_request_notification(
            db=db,
            user_id=user_id,
            request_id=new_request.request_id,
            decision=new_request.decision,
            resource=resource
        )
        
        # Prepare response
        response_data = {
            'success': True,
            'newRequestId': new_request.request_id,
            'decision': new_request.decision,
            'confidenceScore': new_request.confidence_score,
            'message': evaluation_result.get('message', 'Request resubmitted successfully'),
            'mfaRequired': evaluation_result.get('mfaRequired', False),
            'confidenceBreakdown': new_request.confidence_breakdown,
            'policiesApplied': new_request.policies_applied
        }
        
        # Add expiration time if granted
        if new_request.expires_at:
            response_data['expiresAt'] = new_request.expires_at.isoformat()
        
        return jsonify(response_data), 201
    
    except Exception as e:
        error_message = str(e)
        status_code = 400
        
        if "validation failed" in error_message.lower():
            error_code = 'VALIDATION_ERROR'
        elif "rate limit" in error_message.lower():
            error_code = 'RATE_LIMIT_EXCEEDED'
            status_code = 429
        else:
            error_code = 'RESUBMIT_FAILED'
            status_code = 500
        
        return jsonify({
            'success': False,
            'error': {
                'code': error_code,
                'message': error_message
            }
        }), status_code


def _create_access_request_notification(db, user_id, request_id, decision, resource):
    """
    Create notification for user about access request decision
    
    Args:
        db: Firestore client
        user_id (str): User ID
        request_id (str): Access request ID
        decision (str): Decision result
        resource (str): Resource name
    """
    try:
        # Determine notification message based on decision
        if decision == 'granted':
            title = 'Access Request Approved'
            message = f'Your request for {resource} has been approved.'
        elif decision == 'granted_with_mfa':
            title = 'Access Request Approved (MFA Required)'
            message = f'Your request for {resource} has been approved. MFA verification required.'
        elif decision == 'denied':
            title = 'Access Request Denied'
            message = f'Your request for {resource} has been denied.'
        else:
            title = 'Access Request Pending'
            message = f'Your request for {resource} is pending review.'
        
        # Create notification using the model function
        create_notification(
            db=db,
            user_id=user_id,
            notification_type='access_decision',
            title=title,
            message=message,
            related_resource_id=request_id
        )
        
    except Exception as e:
        # Log error but don't fail the request
        print(f"Error creating notification: {str(e)}")
