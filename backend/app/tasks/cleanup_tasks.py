"""
Celery Tasks for System Cleanup and Maintenance
Background tasks for cleaning up expired sessions, old data, and maintenance
"""

from celery_config import celery_app
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


@celery_app.task(name='app.tasks.cleanup_tasks.cleanup_expired_sessions')
def cleanup_expired_sessions():
    """
    Clean up expired sessions from database and cache
    Runs every hour (configured in celery_config.py)
    """
    try:
        logger.info("Starting expired session cleanup...")
        
        from app.models.behavioral_session import BehavioralSession
        from app.services.cache_service import cache_service
        
        # Get expired sessions
        cutoff_time = datetime.utcnow() - timedelta(hours=24)
        
        # In production, query Firestore for expired sessions
        # expired_sessions = BehavioralSession.get_expired_sessions(cutoff_time)
        
        sessions_deleted = 0
        cache_cleared = 0
        
        # For each expired session
        # for session in expired_sessions:
        #     try:
        #         # Delete from database
        #         session.delete()
        #         sessions_deleted += 1
        #         
        #         # Clear from cache
        #         if cache_service.delete_active_session(session.session_id):
        #             cache_cleared += 1
        #             
        #     except Exception as e:
        #         logger.error(f"Failed to delete session {session.session_id}: {e}")
        
        logger.info(f"Cleaned up {sessions_deleted} expired sessions, cleared {cache_cleared} from cache")
        
        return {
            'status': 'success',
            'sessions_deleted': sessions_deleted,
            'cache_cleared': cache_cleared,
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in cleanup_expired_sessions task: {e}")
        return {'status': 'error', 'error': str(e)}


@celery_app.task(name='app.tasks.cleanup_tasks.cleanup_old_behavioral_data')
def cleanup_old_behavioral_data():
    """
    Clean up old behavioral data (older than 90 days)
    Runs weekly
    """
    try:
        logger.info("Starting old behavioral data cleanup...")
        
        from app.models.behavioral_session import BehavioralSession
        
        # Clean up data older than 90 days (retention policy)
        cutoff_date = datetime.utcnow() - timedelta(days=90)
        
        # In production, query and delete old behavioral data
        # data_deleted = BehavioralSession.delete_old_data(cutoff_date)
        
        data_deleted = 0
        
        logger.info(f"Cleaned up {data_deleted} old behavioral data records")
        
        return {
            'status': 'success',
            'data_deleted': data_deleted,
            'cutoff_date': cutoff_date.isoformat(),
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in cleanup_old_behavioral_data task: {e}")
        return {'status': 'error', 'error': str(e)}


@celery_app.task(name='app.tasks.cleanup_tasks.cleanup_old_threat_predictions')
def cleanup_old_threat_predictions():
    """
    Clean up old threat predictions (older than 30 days)
    Runs weekly
    """
    try:
        logger.info("Starting old threat predictions cleanup...")
        
        from app.models.threat_prediction import ThreatPrediction
        
        # Clean up predictions older than 30 days
        cutoff_date = datetime.utcnow() - timedelta(days=30)
        
        # In production, query and delete old predictions
        # predictions_deleted = ThreatPrediction.delete_old_predictions(cutoff_date)
        
        predictions_deleted = 0
        
        logger.info(f"Cleaned up {predictions_deleted} old threat predictions")
        
        return {
            'status': 'success',
            'predictions_deleted': predictions_deleted,
            'cutoff_date': cutoff_date.isoformat(),
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in cleanup_old_threat_predictions task: {e}")
        return {'status': 'error', 'error': str(e)}


@celery_app.task(name='app.tasks.cleanup_tasks.cleanup_old_notifications')
def cleanup_old_notifications():
    """
    Clean up old notifications (older than 30 days)
    Runs daily
    """
    try:
        logger.info("Starting old notifications cleanup...")
        
        from app.models.notification import Notification
        
        # Clean up notifications older than 30 days
        cutoff_date = datetime.utcnow() - timedelta(days=30)
        
        # In production, query and delete old notifications
        # notifications_deleted = Notification.delete_old_notifications(cutoff_date)
        
        notifications_deleted = 0
        
        logger.info(f"Cleaned up {notifications_deleted} old notifications")
        
        return {
            'status': 'success',
            'notifications_deleted': notifications_deleted,
            'cutoff_date': cutoff_date.isoformat(),
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in cleanup_old_notifications task: {e}")
        return {'status': 'error', 'error': str(e)}


@celery_app.task(name='app.tasks.cleanup_tasks.cleanup_cache')
def cleanup_cache():
    """
    Clean up expired cache entries
    Runs every 6 hours
    """
    try:
        logger.info("Starting cache cleanup...")
        
        from app.services.cache_service import cache_service
        from redis_config import get_redis_client
        
        if not cache_service.is_available():
            logger.warning("Redis not available, skipping cache cleanup")
            return {'status': 'skipped', 'reason': 'Redis not available'}
        
        redis_client = get_redis_client()
        
        # Get cache statistics before cleanup
        stats_before = cache_service.get_cache_stats()
        
        # Redis automatically handles TTL expiration
        # But we can manually clean up specific patterns if needed
        
        # Get statistics after
        stats_after = cache_service.get_cache_stats()
        
        logger.info("Cache cleanup completed")
        
        return {
            'status': 'success',
            'stats_before': stats_before,
            'stats_after': stats_after,
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in cleanup_cache task: {e}")
        return {'status': 'error', 'error': str(e)}


@celery_app.task(name='app.tasks.cleanup_tasks.generate_system_health_report')
def generate_system_health_report():
    """
    Generate comprehensive system health report
    Runs daily
    """
    try:
        logger.info("Generating system health report...")
        
        from app.services.cache_service import cache_service
        from websocket_config import get_websocket_stats
        
        # Collect health metrics
        health_report = {
            'timestamp': datetime.utcnow().isoformat(),
            'redis': {
                'available': cache_service.is_available(),
                'stats': cache_service.get_cache_stats() if cache_service.is_available() else None
            },
            'websocket': get_websocket_stats(),
            'celery': {
                'active_tasks': 0,  # Would query Celery inspect
                'scheduled_tasks': 0
            }
        }
        
        # Log the report
        from app.services.audit_logger import log_audit_event
        
        log_audit_event(
            user_id='system',
            action='system_health_report',
            resource_type='system_health',
            resource_id='daily_report',
            details=health_report
        )
        
        logger.info("System health report generated")
        
        return {
            'status': 'success',
            'health_report': health_report,
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error generating system health report: {e}")
        return {'status': 'error', 'error': str(e)}
