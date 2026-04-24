"""
User Routes
API endpoints for user profile and management
"""

from flask import Blueprint, request, jsonify
from app.middleware.authorization import require_auth, require_role, require_admin, get_current_user
from app.middleware.csrf_protection import require_csrf
from app.middleware.security import (
    sanitize_input, validate_request_size, validate_content_type, 
    validate_user_agent, apply_standard_security
)
from app.models.user import get_user_by_id, update_user
from app.firebase_config import get_firestore_client
from app.services.role_change_monitor import get_role_change_monitor

bp = Blueprint('users', __name__, url_prefix='/api/users')


@bp.route('/profile', methods=['GET'])
@require_auth
def get_profile():
    """
    Get current user's profile
    
    Returns:
        User profile data
    """
    try:
        current_user = get_current_user()
        user_id = current_user['user_id']
        
        db = get_firestore_client()
        user = get_user_by_id(db, user_id)
        
        if not user:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'USER_NOT_FOUND',
                    'message': 'User not found'
                }
            }), 404
        
        return jsonify({
            'success': True,
            'user': user.to_public_dict()
        }), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'PROFILE_FETCH_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('/profile', methods=['PUT'])
@require_auth
@require_csrf
@sanitize_input(allow_html=False, strict_mode=True)
@validate_request_size()
@validate_content_type(['application/json'])
def update_profile():
    """
    Update current user's profile
    
    Request Body:
        - name: User name (optional)
        - department: User department (optional)
    
    Returns:
        Updated user profile
    """
    try:
        current_user = get_current_user()
        user_id = current_user['user_id']
        
        data = request.get_json()
        
        # Only allow updating certain fields
        allowed_fields = ['name', 'department']
        update_data = {k: v for k, v in data.items() if k in allowed_fields}
        
        if not update_data:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'VALIDATION_ERROR',
                    'message': 'No valid fields to update'
                }
            }), 400
        
        db = get_firestore_client()
        update_user(db, user_id, update_data)
        
        # Get updated user
        user = get_user_by_id(db, user_id)
        
        return jsonify({
            'success': True,
            'user': user.to_public_dict(),
            'message': 'Profile updated successfully'
        }), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'PROFILE_UPDATE_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('/list', methods=['GET'])
@require_auth
@require_role('admin', 'faculty')
def list_users():
    """
    List all users (Admin and Faculty only)
    
    Query Parameters:
        - role: Filter by role (optional)
        - limit: Number of results (default: 50)
    
    Returns:
        List of users
    """
    try:
        db = get_firestore_client()
        
        # Get query parameters
        role_filter = request.args.get('role')
        limit = int(request.args.get('limit', 50))
        
        # Build query
        users_ref = db.collection('users')
        
        if role_filter:
            query = users_ref.where('role', '==', role_filter).limit(limit)
        else:
            query = users_ref.limit(limit)
        
        # Execute query
        users = []
        for doc in query.stream():
            user_data = doc.to_dict()
            # Remove sensitive fields
            user_data.pop('mfaSecret', None)
            user_data.pop('failedLoginAttempts', None)
            user_data.pop('lockoutUntil', None)
            users.append(user_data)
        
        return jsonify({
            'success': True,
            'users': users,
            'count': len(users)
        }), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'USER_LIST_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('/<user_id>', methods=['GET'])
@require_auth
@require_admin
def get_user(user_id):
    """
    Get user by ID (Admin only)
    
    Args:
        user_id: User ID
    
    Returns:
        User data
    """
    try:
        db = get_firestore_client()
        user = get_user_by_id(db, user_id)
        
        if not user:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'USER_NOT_FOUND',
                    'message': 'User not found'
                }
            }), 404
        
        return jsonify({
            'success': True,
            'user': user.to_public_dict()
        }), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'USER_FETCH_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('/<user_id>/deactivate', methods=['POST'])
@require_auth
@require_admin
async def deactivate_user(user_id):
    """
    Deactivate user account (Admin only)
    
    Args:
        user_id: User ID
    
    Request Body:
        reason: Reason for deactivation (optional)
    
    Returns:
        Success message with revocation summary
    """
    try:
        current_user = get_current_user()
        
        # Prevent self-deactivation
        if current_user['user_id'] == user_id:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'INVALID_OPERATION',
                    'message': 'Cannot deactivate your own account'
                }
            }), 400
        
        db = get_firestore_client()
        
        # Get current user status
        user = get_user_by_id(db, user_id)
        if not user:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'USER_NOT_FOUND',
                    'message': 'User not found'
                }
            }), 404
        
        old_status = user.is_active
        
        # Get reason from request body
        data = request.get_json() or {}
        reason = data.get('reason', 'Account deactivated by administrator')
        
        # Update user status
        update_user(db, user_id, {'isActive': False})
        
        # Monitor status change and revoke access if needed
        monitor = get_role_change_monitor(db)
        revocation_summary = await monitor.monitor_account_status_change(
            user_id, old_status, False, current_user['user_id'], reason
        )
        
        return jsonify({
            'success': True,
            'message': 'User deactivated successfully',
            'revocation_summary': revocation_summary
        }), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'USER_DEACTIVATE_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('/<user_id>/activate', methods=['POST'])
@require_auth
@require_admin
async def activate_user(user_id):
    """
    Activate user account (Admin only)
    
    Args:
        user_id: User ID
    
    Request Body:
        reason: Reason for activation (optional)
    
    Returns:
        Success message
    """
    try:
        current_user = get_current_user()
        db = get_firestore_client()
        
        # Get current user status
        user = get_user_by_id(db, user_id)
        if not user:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'USER_NOT_FOUND',
                    'message': 'User not found'
                }
            }), 404
        
        old_status = user.is_active
        
        # Get reason from request body
        data = request.get_json() or {}
        reason = data.get('reason', 'Account activated by administrator')
        
        # Update user status
        update_user(db, user_id, {'isActive': True})
        
        # Monitor status change (no revocation needed for activation)
        monitor = get_role_change_monitor(db)
        status_summary = await monitor.monitor_account_status_change(
            user_id, old_status, True, current_user['user_id'], reason
        )
        
        return jsonify({
            'success': True,
            'message': 'User activated successfully',
            'status_summary': status_summary
        }), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'USER_ACTIVATE_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('/<user_id>/role', methods=['PUT'])
@require_auth
@require_admin
async def change_user_role(user_id):
    """
    Change user role (Admin only)
    
    Args:
        user_id: User ID
    
    Request Body:
        role: New role (student, faculty, admin)
        reason: Reason for role change
    
    Returns:
        Success message with revocation summary
    """
    try:
        current_user = get_current_user()
        data = request.get_json()
        
        if not data or 'role' not in data:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'VALIDATION_ERROR',
                    'message': 'Role is required'
                }
            }), 400
        
        new_role = data['role']
        reason = data.get('reason', 'Role changed by administrator')
        
        # Validate role
        valid_roles = ['student', 'faculty', 'admin']
        if new_role not in valid_roles:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'VALIDATION_ERROR',
                    'message': f'Invalid role. Must be one of: {", ".join(valid_roles)}'
                }
            }), 400
        
        db = get_firestore_client()
        
        # Get current user
        user = get_user_by_id(db, user_id)
        if not user:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'USER_NOT_FOUND',
                    'message': 'User not found'
                }
            }), 404
        
        old_role = user.role
        
        # Prevent changing own role to non-admin
        if current_user['user_id'] == user_id and new_role != 'admin':
            return jsonify({
                'success': False,
                'error': {
                    'code': 'INVALID_OPERATION',
                    'message': 'Cannot change your own role to non-admin'
                }
            }), 400
        
        # No change needed
        if old_role == new_role:
            return jsonify({
                'success': True,
                'message': 'Role unchanged',
                'revocation_summary': {
                    'user_id': user_id,
                    'user_name': user.name,
                    'role_change': f'{old_role} -> {new_role}',
                    'action_taken': 'none',
                    'reason': 'No role change detected'
                }
            }), 200
        
        # Update user role
        update_user(db, user_id, {'role': new_role})
        
        # Monitor role change and revoke access if needed
        monitor = get_role_change_monitor(db)
        revocation_summary = await monitor.monitor_user_role_change(
            user_id, old_role, new_role, current_user['user_id'], reason
        )
        
        return jsonify({
            'success': True,
            'message': f'User role changed from {old_role} to {new_role}',
            'revocation_summary': revocation_summary
        }), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'ROLE_CHANGE_FAILED',
                'message': str(e)
            }
        }), 500
