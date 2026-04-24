"""
Notification Routes
API endpoints for notification management
"""

from flask import Blueprint, request, jsonify
from functools import wraps
from app.services.auth_service import auth_service
from app.models.notification import (
    get_user_notifications,
    get_notification_by_id,
    mark_notification_as_read,
    mark_all_notifications_as_read,
    get_unread_count
)
from app.firebase_config import get_firestore_client
from datetime import datetime

bp = Blueprint('notifications', __name__, url_prefix='/api/notifications')


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


@bp.route('/', methods=['GET'])
@require_auth
def get_notifications():
    """
    Get notifications for the authenticated user
    
    Query Parameters:
        - unreadOnly: Filter to only unread notifications (optional, default: false)
        - limit: Maximum number of notifications to return (optional, default: 50)
    
    Returns:
        List of notifications with unread count
    """
    try:
        user_id = request.user_id
        
        # Get query parameters
        unread_only = request.args.get('unreadOnly', 'false').lower() == 'true'
        limit = int(request.args.get('limit', 50))
        
        # Get notifications
        db = get_firestore_client()
        notifications = get_user_notifications(db, user_id, unread_only=unread_only, limit=limit)
        
        # Convert to dict and format timestamps
        notifications_data = []
        for notification in notifications:
            notif_dict = notification.to_dict()
            # Convert timestamps to ISO format
            if isinstance(notif_dict.get('timestamp'), datetime):
                notif_dict['timestamp'] = notif_dict['timestamp'].isoformat()
            if isinstance(notif_dict.get('expiresAt'), datetime):
                notif_dict['expiresAt'] = notif_dict['expiresAt'].isoformat()
            notifications_data.append(notif_dict)
        
        # Get unread count
        unread_count = get_unread_count(db, user_id)
        
        return jsonify({
            'success': True,
            'notifications': notifications_data,
            'unreadCount': unread_count
        }), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'NOTIFICATIONS_FETCH_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('', methods=['GET'])
@require_auth
def get_notifications_no_slash():
    return get_notifications()


@bp.route('/<notification_id>', methods=['GET'])
@require_auth
def get_notification(notification_id):
    """
    Get a specific notification by ID
    
    Path Parameters:
        - notification_id: Notification ID
    
    Returns:
        Notification details
    """
    try:
        user_id = request.user_id
        
        # Get notification
        db = get_firestore_client()
        notification = get_notification_by_id(db, notification_id)
        
        if not notification:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'NOTIFICATION_NOT_FOUND',
                    'message': 'Notification not found'
                }
            }), 404
        
        # Check authorization (user can only view their own notifications)
        if notification.user_id != user_id:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'INSUFFICIENT_PERMISSIONS',
                    'message': 'You do not have permission to view this notification'
                }
            }), 403
        
        # Convert to dict and format timestamps
        notif_dict = notification.to_dict()
        if isinstance(notif_dict.get('timestamp'), datetime):
            notif_dict['timestamp'] = notif_dict['timestamp'].isoformat()
        if isinstance(notif_dict.get('expiresAt'), datetime):
            notif_dict['expiresAt'] = notif_dict['expiresAt'].isoformat()
        
        return jsonify({
            'success': True,
            'notification': notif_dict
        }), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'NOTIFICATION_FETCH_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('/<notification_id>/read', methods=['PUT'])
@require_auth
def mark_as_read(notification_id):
    """
    Mark a notification as read
    
    Path Parameters:
        - notification_id: Notification ID
    
    Returns:
        Success status
    """
    try:
        user_id = request.user_id
        
        # Get notification to verify ownership
        db = get_firestore_client()
        notification = get_notification_by_id(db, notification_id)
        
        if not notification:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'NOTIFICATION_NOT_FOUND',
                    'message': 'Notification not found'
                }
            }), 404
        
        # Check authorization
        if notification.user_id != user_id:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'INSUFFICIENT_PERMISSIONS',
                    'message': 'You do not have permission to modify this notification'
                }
            }), 403
        
        # Mark as read
        success = mark_notification_as_read(db, notification_id)
        
        if not success:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'MARK_READ_FAILED',
                    'message': 'Failed to mark notification as read'
                }
            }), 500
        
        # Get updated unread count
        unread_count = get_unread_count(db, user_id)
        
        return jsonify({
            'success': True,
            'message': 'Notification marked as read',
            'unreadCount': unread_count
        }), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'MARK_READ_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('/read-all', methods=['PUT'])
@require_auth
def mark_all_as_read():
    """
    Mark all notifications for the authenticated user as read
    
    Returns:
        Success status with count of notifications marked
    """
    try:
        user_id = request.user_id
        
        # Mark all as read
        db = get_firestore_client()
        count = mark_all_notifications_as_read(db, user_id)
        
        return jsonify({
            'success': True,
            'message': f'{count} notifications marked as read',
            'count': count,
            'unreadCount': 0
        }), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'MARK_ALL_READ_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('/unread-count', methods=['GET'])
@require_auth
def get_unread_notification_count():
    """
    Get count of unread notifications for the authenticated user
    
    Returns:
        Unread notification count
    """
    try:
        user_id = request.user_id
        
        # Get unread count
        db = get_firestore_client()
        unread_count = get_unread_count(db, user_id)
        
        return jsonify({
            'success': True,
            'unreadCount': unread_count
        }), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'UNREAD_COUNT_FAILED',
                'message': str(e)
            }
        }), 500
