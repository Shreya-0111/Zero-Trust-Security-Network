"""
Notification Model
Represents a notification for a user about system events
"""

import uuid
from datetime import datetime, timedelta


class Notification:
    """Notification model for user notifications"""
    
    def __init__(
        self,
        user_id,
        notification_type,
        title,
        message,
        related_resource_id=None,
        notification_id=None,
        read=False,
        timestamp=None,
        expires_at=None
    ):
        """
        Initialize a Notification object
        
        Args:
            user_id (str): User ID
            notification_type (str): Type of notification
            title (str): Notification title
            message (str): Notification message
            related_resource_id (str, optional): Related resource ID (e.g., requestId)
            notification_id (str, optional): Notification ID (auto-generated if not provided)
            read (bool): Read status
            timestamp (datetime, optional): Timestamp (auto-generated if not provided)
            expires_at (datetime, optional): Expiration timestamp (auto-generated if not provided)
        """
        self.notification_id = notification_id or str(uuid.uuid4())
        self.user_id = user_id
        self.type = notification_type
        self.title = title
        self.message = message
        self.related_resource_id = related_resource_id
        self.read = read
        self.timestamp = timestamp or datetime.utcnow()
        self.expires_at = expires_at or (datetime.utcnow() + timedelta(days=30))
    
    def to_dict(self):
        """
        Convert notification to dictionary
        
        Returns:
            dict: Notification data
        """
        return {
            'notificationId': self.notification_id,
            'userId': self.user_id,
            'type': self.type,
            'title': self.title,
            'message': self.message,
            'relatedResourceId': self.related_resource_id,
            'read': self.read,
            'timestamp': self.timestamp,
            'expiresAt': self.expires_at
        }
    
    def validate(self):
        """
        Validate notification data
        
        Returns:
            tuple: (is_valid, error_message)
        """
        if not self.user_id:
            return False, "User ID is required"
        
        if not self.type:
            return False, "Notification type is required"
        
        valid_types = ['access_decision', 'security_alert', 'system_update']
        if self.type not in valid_types:
            return False, f"Invalid notification type. Must be one of: {', '.join(valid_types)}"
        
        if not self.title or len(self.title) < 1:
            return False, "Title is required"
        
        if not self.message or len(self.message) < 1:
            return False, "Message is required"
        
        return True, None
    
    def mark_as_read(self):
        """Mark notification as read"""
        self.read = True


def create_notification(
    db,
    user_id,
    notification_type,
    title,
    message,
    related_resource_id=None
):
    """
    Create a new notification in Firestore
    
    Args:
        db: Firestore client
        user_id (str): User ID
        notification_type (str): Type of notification
        title (str): Notification title
        message (str): Notification message
        related_resource_id (str, optional): Related resource ID
        
    Returns:
        Notification: Created notification object
    """
    notification = Notification(
        user_id=user_id,
        notification_type=notification_type,
        title=title,
        message=message,
        related_resource_id=related_resource_id
    )
    
    # Validate
    is_valid, error_message = notification.validate()
    if not is_valid:
        raise ValueError(f"Notification validation failed: {error_message}")
    
    # Save to Firestore
    notification_ref = db.collection('notifications').document(notification.notification_id)
    notification_ref.set(notification.to_dict())
    
    return notification


def get_notification_by_id(db, notification_id):
    """
    Get notification by ID
    
    Args:
        db: Firestore client
        notification_id (str): Notification ID
        
    Returns:
        Notification: Notification object or None if not found
    """
    doc = db.collection('notifications').document(notification_id).get()
    
    if not doc.exists:
        return None
    
    data = doc.to_dict()
    return Notification(
        notification_id=data['notificationId'],
        user_id=data['userId'],
        notification_type=data['type'],
        title=data['title'],
        message=data['message'],
        related_resource_id=data.get('relatedResourceId'),
        read=data.get('read', False),
        timestamp=data.get('timestamp'),
        expires_at=data.get('expiresAt')
    )


def get_user_notifications(db, user_id, unread_only=False, limit=50):
    """
    Get notifications for a user
    
    Args:
        db: Firestore client
        user_id (str): User ID
        unread_only (bool): Only return unread notifications
        limit (int): Maximum number of notifications to return
        
    Returns:
        list: List of Notification objects
    """
    try:
        query = db.collection('notifications').where('userId', '==', user_id)
        
        if unread_only:
            query = query.where('read', '==', False)
        
        # Order by timestamp descending (most recent first)
        # Note: This requires a Firestore index
        query = query.order_by('timestamp', direction='DESCENDING').limit(limit)
        
        notifications = []
        for doc in query.stream():
            data = doc.to_dict()
            notification = Notification(
                notification_id=data['notificationId'],
                user_id=data['userId'],
                notification_type=data['type'],
                title=data['title'],
                message=data['message'],
                related_resource_id=data.get('relatedResourceId'),
                read=data.get('read', False),
                timestamp=data.get('timestamp'),
                expires_at=data.get('expiresAt')
            )
            notifications.append(notification)
        
        return notifications
    except Exception as e:
        # If query fails (e.g., missing index), return empty list
        print(f"Error fetching notifications: {e}")
        return []


def mark_notification_as_read(db, notification_id):
    """
    Mark a notification as read
    
    Args:
        db: Firestore client
        notification_id (str): Notification ID
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        notification_ref = db.collection('notifications').document(notification_id)
        notification_ref.update({'read': True})
        return True
    except Exception as e:
        print(f"Error marking notification as read: {str(e)}")
        return False


def mark_all_notifications_as_read(db, user_id):
    """
    Mark all notifications for a user as read
    
    Args:
        db: Firestore client
        user_id (str): User ID
        
    Returns:
        int: Number of notifications marked as read
    """
    try:
        query = db.collection('notifications').where('userId', '==', user_id).where('read', '==', False)
        
        count = 0
        for doc in query.stream():
            doc.reference.update({'read': True})
            count += 1
        
        return count
    except Exception as e:
        print(f"Error marking all notifications as read: {str(e)}")
        return 0


def delete_expired_notifications(db):
    """
    Delete notifications older than 30 days
    
    Args:
        db: Firestore client
        
    Returns:
        int: Number of notifications deleted
    """
    try:
        cutoff_time = datetime.utcnow()
        query = db.collection('notifications').where('expiresAt', '<', cutoff_time)
        
        count = 0
        for doc in query.stream():
            doc.reference.delete()
            count += 1
        
        return count
    except Exception as e:
        print(f"Error deleting expired notifications: {str(e)}")
        return 0


def get_unread_count(db, user_id):
    """
    Get count of unread notifications for a user
    
    Args:
        db: Firestore client
        user_id (str): User ID
        
    Returns:
        int: Count of unread notifications
    """
    try:
        query = db.collection('notifications').where('userId', '==', user_id).where('read', '==', False)
        
        count = 0
        for _ in query.stream():
            count += 1
        
        return count
    except Exception as e:
        print(f"Error getting unread count: {str(e)}")
        return 0
