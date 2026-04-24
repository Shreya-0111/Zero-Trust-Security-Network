"""
Notification Cleanup Task
Scheduled task to delete notifications older than 30 days
"""

from app.firebase_config import get_firestore_client
from app.models.notification import delete_expired_notifications


def cleanup_expired_notifications():
    """
    Delete notifications that have expired (older than 30 days)
    
    This function should be called periodically (e.g., daily via cron job)
    
    Returns:
        int: Number of notifications deleted
    """
    try:
        db = get_firestore_client()
        count = delete_expired_notifications(db)
        print(f"Cleanup completed: {count} expired notifications deleted")
        return count
    except Exception as e:
        print(f"Error during notification cleanup: {str(e)}")
        return 0


if __name__ == '__main__':
    # Run cleanup when script is executed directly
    cleanup_expired_notifications()
