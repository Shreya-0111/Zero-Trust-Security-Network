"""
Visitor Background Tasks

Celery tasks for visitor session management, expiration checking,
and automated cleanup operations.
"""

import logging
from datetime import datetime, timedelta
from celery import Celery
from ..services.visitor_service import visitor_service

logger = logging.getLogger(__name__)

# Initialize Celery
celery = Celery('visitor_tasks')


@celery.task(bind=True)
def check_expired_visitor_sessions(self):
    """
    Background task to check for and auto-terminate expired visitor sessions
    
    This task runs every 5 minutes to ensure timely session termination
    and proper cleanup of expired visitor access.
    """
    try:
        logger.info("Starting expired visitor session check")
        
        # Check for expired sessions
        expired_visitors = visitor_service.check_expired_sessions()
        
        if expired_visitors:
            logger.info(f"Auto-terminated {len(expired_visitors)} expired visitor sessions")
        else:
            logger.debug("No expired visitor sessions found")
        
        return {
            'success': True,
            'expired_count': len(expired_visitors),
            'expired_visitors': expired_visitors,
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in expired session check task: {str(e)}")
        # Retry the task with exponential backoff
        raise self.retry(exc=e, countdown=60, max_retries=3)


@celery.task(bind=True)
def send_session_expiration_warnings(self):
    """
    Background task to send warnings for sessions expiring soon
    
    Sends notifications to hosts when visitor sessions are within 30 minutes
    of expiration to allow for extension requests if needed.
    """
    try:
        logger.info("Checking for sessions requiring expiration warnings")
        
        from google.cloud import firestore
        db = firestore.Client()
        
        # Calculate warning threshold (30 minutes from now)
        warning_time = datetime.utcnow() + timedelta(minutes=30)
        current_time = datetime.utcnow()
        
        # Query for active visitors expiring within 30 minutes
        query = (db.collection('visitors')
                .where('status', '==', 'active')
                .where('expected_exit_time', '<=', warning_time)
                .where('expected_exit_time', '>', current_time))
        
        warning_count = 0
        docs = query.stream()
        
        for doc in docs:
            visitor_data = doc.to_dict()
            
            # Check if warning was already sent (to avoid spam)
            last_warning = visitor_data.get('last_expiration_warning')
            if last_warning:
                last_warning_time = datetime.fromisoformat(last_warning)
                if (current_time - last_warning_time).total_seconds() < 1800:  # 30 minutes
                    continue
            
            # Send expiration warning
            await visitor_service._notify_session_expiration_warning(visitor_data)
            
            # Update last warning timestamp
            doc.reference.update({
                'last_expiration_warning': current_time.isoformat()
            })
            
            warning_count += 1
        
        logger.info(f"Sent {warning_count} session expiration warnings")
        
        return {
            'success': True,
            'warnings_sent': warning_count,
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in expiration warning task: {str(e)}")
        raise self.retry(exc=e, countdown=60, max_retries=3)


@celery.task(bind=True)
def cleanup_old_visitor_records(self):
    """
    Background task to clean up old visitor records
    
    Removes visitor records older than 90 days to comply with data retention policies
    while preserving anonymized audit logs for compliance.
    """
    try:
        logger.info("Starting cleanup of old visitor records")
        
        from google.cloud import firestore
        db = firestore.Client()
        
        # Calculate cutoff date (90 days ago)
        cutoff_date = datetime.utcnow() - timedelta(days=90)
        
        # Query for old completed/terminated visitors
        query = (db.collection('visitors')
                .where('status', 'in', ['completed', 'terminated', 'expired'])
                .where('actual_exit_time', '<=', cutoff_date))
        
        cleanup_count = 0
        docs = query.stream()
        
        for doc in docs:
            visitor_data = doc.to_dict()
            
            # Create anonymized audit record before deletion
            anonymized_record = {
                'original_visitor_id': visitor_data['visitor_id'],
                'anonymized_at': datetime.utcnow().isoformat(),
                'session_duration': visitor_data.get('session_duration'),
                'compliance_score': visitor_data.get('route_compliance', {}).get('compliance_score'),
                'host_department': visitor_data.get('host_department'),
                'visit_purpose_category': _categorize_visit_purpose(visitor_data.get('visit_purpose', '')),
                'total_accesses': len(visitor_data.get('access_log', [])),
                'route_violations': len(visitor_data.get('route_compliance', {}).get('deviations', [])),
                'session_extensions': len(visitor_data.get('session_extensions', []))
            }
            
            # Store anonymized record
            db.collection('anonymized_visitor_records').add(anonymized_record)
            
            # Delete original visitor record
            doc.reference.delete()
            
            cleanup_count += 1
        
        logger.info(f"Cleaned up {cleanup_count} old visitor records")
        
        return {
            'success': True,
            'cleaned_count': cleanup_count,
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in cleanup task: {str(e)}")
        raise self.retry(exc=e, countdown=300, max_retries=2)  # 5 minute retry delay


@celery.task(bind=True)
def generate_daily_visitor_report(self):
    """
    Background task to generate daily visitor activity reports
    
    Creates summary reports of visitor activity for administrators
    and compliance officers.
    """
    try:
        logger.info("Generating daily visitor report")
        
        from google.cloud import firestore
        db = firestore.Client()
        
        # Calculate yesterday's date range
        today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        yesterday = today - timedelta(days=1)
        
        # Query visitors from yesterday
        query = (db.collection('visitors')
                .where('entry_time', '>=', yesterday)
                .where('entry_time', '<', today))
        
        visitors = list(query.stream())
        
        # Calculate metrics
        total_visitors = len(visitors)
        active_sessions = 0
        completed_sessions = 0
        terminated_sessions = 0
        total_compliance_score = 0
        total_violations = 0
        total_extensions = 0
        
        for doc in visitors:
            visitor_data = doc.to_dict()
            status = visitor_data.get('status')
            
            if status == 'active':
                active_sessions += 1
            elif status == 'completed':
                completed_sessions += 1
            elif status == 'terminated':
                terminated_sessions += 1
            
            # Compliance metrics
            compliance = visitor_data.get('route_compliance', {})
            total_compliance_score += compliance.get('compliance_score', 100)
            total_violations += len(compliance.get('deviations', []))
            
            # Extension metrics
            total_extensions += len(visitor_data.get('session_extensions', []))
        
        # Calculate averages
        avg_compliance = total_compliance_score / total_visitors if total_visitors > 0 else 100
        
        # Create report
        report = {
            'report_date': yesterday.isoformat(),
            'generated_at': datetime.utcnow().isoformat(),
            'summary': {
                'total_visitors': total_visitors,
                'active_sessions': active_sessions,
                'completed_sessions': completed_sessions,
                'terminated_sessions': terminated_sessions,
                'average_compliance_score': round(avg_compliance, 2),
                'total_route_violations': total_violations,
                'total_session_extensions': total_extensions
            },
            'compliance_metrics': {
                'high_compliance': sum(1 for doc in visitors 
                                     if doc.to_dict().get('route_compliance', {}).get('compliance_score', 100) >= 90),
                'medium_compliance': sum(1 for doc in visitors 
                                       if 70 <= doc.to_dict().get('route_compliance', {}).get('compliance_score', 100) < 90),
                'low_compliance': sum(1 for doc in visitors 
                                    if doc.to_dict().get('route_compliance', {}).get('compliance_score', 100) < 70)
            }
        }
        
        # Store report
        db.collection('daily_visitor_reports').add(report)
        
        logger.info(f"Generated daily visitor report: {total_visitors} visitors, {avg_compliance:.1f}% avg compliance")
        
        return report
        
    except Exception as e:
        logger.error(f"Error generating daily report: {str(e)}")
        raise self.retry(exc=e, countdown=300, max_retries=2)


def _categorize_visit_purpose(purpose):
    """
    Categorize visit purpose for anonymized reporting
    
    Args:
        purpose: Original visit purpose text
        
    Returns:
        str: Categorized purpose
    """
    purpose_lower = purpose.lower()
    
    if any(word in purpose_lower for word in ['meeting', 'conference', 'discussion']):
        return 'meeting'
    elif any(word in purpose_lower for word in ['research', 'lab', 'experiment']):
        return 'research'
    elif any(word in purpose_lower for word in ['class', 'lecture', 'teaching', 'student']):
        return 'academic'
    elif any(word in purpose_lower for word in ['maintenance', 'repair', 'service']):
        return 'maintenance'
    elif any(word in purpose_lower for word in ['delivery', 'pickup', 'vendor']):
        return 'delivery'
    else:
        return 'other'


# Celery beat schedule for periodic tasks
celery.conf.beat_schedule = {
    'check-expired-sessions': {
        'task': 'app.tasks.visitor_tasks.check_expired_visitor_sessions',
        'schedule': 300.0,  # Every 5 minutes
    },
    'send-expiration-warnings': {
        'task': 'app.tasks.visitor_tasks.send_session_expiration_warnings',
        'schedule': 600.0,  # Every 10 minutes
    },
    'cleanup-old-records': {
        'task': 'app.tasks.visitor_tasks.cleanup_old_visitor_records',
        'schedule': 86400.0,  # Daily at midnight
    },
    'generate-daily-report': {
        'task': 'app.tasks.visitor_tasks.generate_daily_visitor_report',
        'schedule': 86400.0,  # Daily at midnight
    },
}

celery.conf.timezone = 'UTC'