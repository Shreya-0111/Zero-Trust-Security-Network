"""
JIT Access Monitoring Tasks
Background tasks for monitoring and managing JIT access sessions
"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any
from celery import Celery

from ..firebase_config import get_firestore_client
from ..models.audit_log import create_audit_log
from ..models.notification import create_notification
from ..models.user import get_user_by_id
from ..models.resource_segment import get_resource_segment_by_id
from ..services.behavioral_biometrics import behavioral_service

logger = logging.getLogger(__name__)

# Initialize Celery (this would be configured in your main app)
celery_app = Celery('jit_monitoring')


@celery_app.task(bind=True)
def monitor_jit_access_sessions(self):
    """
    Monitor active JIT access sessions for anomalous behavior and automatic expiration
    
    This task runs every 5 minutes to:
    1. Check for expired sessions and mark them as expired
    2. Monitor active sessions for anomalous behavior
    3. Send expiration warnings
    4. Generate activity reports
    """
    try:
        db = get_firestore_client()
        current_time = datetime.utcnow()
        
        # Get all active JIT sessions
        requests_ref = db.collection('jitAccessRequests')
        active_query = requests_ref.where('status', '==', 'granted')
        
        expired_count = 0
        warning_count = 0
        anomaly_count = 0
        
        for doc in active_query.stream():
            request_data = doc.to_dict()
            request_id = request_data.get('requestId')
            user_id = request_data.get('userId')
            expires_at = request_data.get('expiresAt')
            
            if not expires_at or not isinstance(expires_at, datetime):
                continue
            
            # Check if session has expired
            if expires_at <= current_time:
                await _expire_jit_session(db, doc.reference, request_data, current_time)
                expired_count += 1
                continue
            
            # Check if session is expiring soon (within 30 minutes)
            time_until_expiry = expires_at - current_time
            if time_until_expiry <= timedelta(minutes=30):
                await _send_expiration_warning(db, request_data, time_until_expiry)
                warning_count += 1
            
            # Monitor for anomalous behavior
            anomaly_detected = await _monitor_session_behavior(db, request_data, current_time)
            if anomaly_detected:
                anomaly_count += 1
        
        # Log monitoring results
        logger.info(f"JIT monitoring completed: {expired_count} expired, {warning_count} warnings, {anomaly_count} anomalies")
        
        return {
            'success': True,
            'expired_sessions': expired_count,
            'expiration_warnings': warning_count,
            'anomalies_detected': anomaly_count,
            'timestamp': current_time.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in JIT monitoring task: {str(e)}")
        return {
            'success': False,
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }


@celery_app.task(bind=True)
def cleanup_expired_jit_sessions(self):
    """
    Cleanup task to mark expired JIT sessions and perform housekeeping
    
    This task runs every hour to:
    1. Mark expired sessions as expired
    2. Clean up old session data
    3. Generate cleanup reports
    """
    try:
        db = get_firestore_client()
        current_time = datetime.utcnow()
        
        # Get all granted sessions that should be expired
        requests_ref = db.collection('jitAccessRequests')
        granted_query = requests_ref.where('status', '==', 'granted')
        
        expired_count = 0
        
        for doc in granted_query.stream():
            request_data = doc.to_dict()
            expires_at = request_data.get('expiresAt')
            
            if expires_at and isinstance(expires_at, datetime) and expires_at <= current_time:
                await _expire_jit_session(db, doc.reference, request_data, current_time)
                expired_count += 1
        
        # Clean up old monitoring data (older than 30 days)
        await _cleanup_old_monitoring_data(db, current_time)
        
        logger.info(f"JIT cleanup completed: {expired_count} sessions expired")
        
        return {
            'success': True,
            'expired_sessions': expired_count,
            'timestamp': current_time.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in JIT cleanup task: {str(e)}")
        return {
            'success': False,
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }


@celery_app.task(bind=True)
def generate_jit_activity_report(self, period_hours: int = 24):
    """
    Generate JIT access activity report for the specified period
    
    Args:
        period_hours (int): Number of hours to include in the report
    
    Returns:
        dict: Activity report data
    """
    try:
        db = get_firestore_client()
        current_time = datetime.utcnow()
        start_time = current_time - timedelta(hours=period_hours)
        
        # Get JIT requests from the specified period
        requests_ref = db.collection('jitAccessRequests')
        
        # Get all requests in the time period
        all_requests = []
        for doc in requests_ref.stream():
            request_data = doc.to_dict()
            requested_at = request_data.get('requestedAt')
            
            if (requested_at and isinstance(requested_at, datetime) and 
                requested_at >= start_time):
                all_requests.append(request_data)
        
        # Generate report statistics
        report = _generate_activity_statistics(all_requests, start_time, current_time)
        
        # Store report in Firestore
        report_id = f"jit_report_{current_time.strftime('%Y%m%d_%H%M%S')}"
        reports_ref = db.collection('jitActivityReports').document(report_id)
        reports_ref.set({
            'reportId': report_id,
            'generatedAt': current_time,
            'periodHours': period_hours,
            'startTime': start_time,
            'endTime': current_time,
            'statistics': report
        })
        
        logger.info(f"JIT activity report generated: {report_id}")
        
        return {
            'success': True,
            'report_id': report_id,
            'statistics': report,
            'timestamp': current_time.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error generating JIT activity report: {str(e)}")
        return {
            'success': False,
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }


async def _expire_jit_session(db, doc_ref, request_data: Dict[str, Any], current_time: datetime):
    """Expire a JIT session and create audit log"""
    try:
        request_id = request_data.get('requestId')
        user_id = request_data.get('userId')
        resource_segment_id = request_data.get('resourceSegmentId')
        
        # Update session status
        doc_ref.update({
            'status': 'expired',
            'expiredAt': current_time,
            'expiredBy': 'automatic_expiration'
        })
        
        # Create audit log
        await create_audit_log(
            db,
            event_type='jit_access',
            sub_type='session_expired',
            user_id='system',
            target_user_id=user_id,
            resource_segment_id=resource_segment_id,
            action='JIT access session expired automatically',
            result='success',
            details={
                'request_id': request_id,
                'expired_at': current_time.isoformat(),
                'expiration_type': 'automatic'
            }
        )
        
        # Get segment name for notification
        segment = get_resource_segment_by_id(db, resource_segment_id)
        segment_name = segment.name if segment else 'Unknown Resource'
        
        # Create notification for user
        await create_notification(
            db,
            user_id=user_id,
            title='JIT Access Expired',
            message=f'Your JIT access to {segment_name} has expired',
            notification_type='jit_access_expired',
            priority='low',
            data={
                'request_id': request_id,
                'segment_name': segment_name,
                'expired_at': current_time.isoformat()
            }
        )
        
        logger.info(f"JIT session expired: {request_id}")
        
    except Exception as e:
        logger.error(f"Error expiring JIT session: {str(e)}")


async def _send_expiration_warning(db, request_data: Dict[str, Any], time_remaining: timedelta):
    """Send expiration warning to user"""
    try:
        user_id = request_data.get('userId')
        request_id = request_data.get('requestId')
        resource_segment_id = request_data.get('resourceSegmentId')
        
        # Check if warning already sent (to avoid spam)
        warnings_ref = db.collection('jitExpirationWarnings')
        existing_warning = warnings_ref.where('requestId', '==', request_id).limit(1).get()
        
        if existing_warning:
            return  # Warning already sent
        
        # Get segment name
        segment = get_resource_segment_by_id(db, resource_segment_id)
        segment_name = segment.name if segment else 'Unknown Resource'
        
        # Calculate remaining time in minutes
        minutes_remaining = int(time_remaining.total_seconds() / 60)
        
        # Create notification
        await create_notification(
            db,
            user_id=user_id,
            title='JIT Access Expiring Soon',
            message=f'Your JIT access to {segment_name} will expire in {minutes_remaining} minutes',
            notification_type='jit_access_warning',
            priority='medium',
            data={
                'request_id': request_id,
                'segment_name': segment_name,
                'minutes_remaining': minutes_remaining
            }
        )
        
        # Record that warning was sent
        warnings_ref.add({
            'requestId': request_id,
            'userId': user_id,
            'sentAt': datetime.utcnow(),
            'minutesRemaining': minutes_remaining
        })
        
        logger.info(f"Expiration warning sent for JIT session: {request_id}")
        
    except Exception as e:
        logger.error(f"Error sending expiration warning: {str(e)}")


async def _monitor_session_behavior(db, request_data: Dict[str, Any], current_time: datetime) -> bool:
    """Monitor JIT session for anomalous behavior"""
    try:
        user_id = request_data.get('userId')
        request_id = request_data.get('requestId')
        resource_segment_id = request_data.get('resourceSegmentId')
        
        # Get recent user activity for this session
        # This would integrate with your activity monitoring system
        
        # For now, we'll use behavioral biometrics to check for anomalies
        session_data = {
            'user_id': user_id,
            'session_start': request_data.get('grantedAt'),
            'current_time': current_time,
            'resource_segment_id': resource_segment_id
        }
        
        # Check for behavioral anomalies
        behavioral_result = behavioral_service.analyze_session_behavior(user_id, session_data)
        
        if behavioral_result.get('anomaly_detected', False):
            # Flag anomalous behavior
            await _flag_anomalous_behavior(db, request_data, behavioral_result, current_time)
            return True
        
        return False
        
    except Exception as e:
        logger.error(f"Error monitoring session behavior: {str(e)}")
        return False


async def _flag_anomalous_behavior(db, request_data: Dict[str, Any], 
                                 behavioral_result: Dict[str, Any], current_time: datetime):
    """Flag anomalous behavior during JIT session"""
    try:
        user_id = request_data.get('userId')
        request_id = request_data.get('requestId')
        resource_segment_id = request_data.get('resourceSegmentId')
        
        # Create audit log for anomaly
        await create_audit_log(
            db,
            event_type='jit_access',
            sub_type='anomaly_detected',
            user_id='system',
            target_user_id=user_id,
            resource_segment_id=resource_segment_id,
            action='Anomalous behavior detected during JIT session',
            result='warning',
            details={
                'request_id': request_id,
                'anomaly_type': behavioral_result.get('anomaly_type', 'behavioral'),
                'confidence': behavioral_result.get('confidence', 0),
                'detected_at': current_time.isoformat(),
                'behavioral_factors': behavioral_result.get('factors', [])
            }
        )
        
        # Get segment and user information
        segment = get_resource_segment_by_id(db, resource_segment_id)
        user = get_user_by_id(db, user_id)
        
        # Notify administrators for high-confidence anomalies
        if behavioral_result.get('confidence', 0) > 0.8:
            # Get all admin users
            users_ref = db.collection('users')
            admin_query = users_ref.where('role', '==', 'admin').where('isActive', '==', True)
            
            for admin_doc in admin_query.stream():
                admin_data = admin_doc.to_dict()
                
                await create_notification(
                    db,
                    user_id=admin_data['userId'],
                    title='JIT Session Anomaly Detected',
                    message=f'Anomalous behavior detected in JIT session for {user.name if user else "unknown user"} accessing {segment.name if segment else "unknown resource"}',
                    notification_type='jit_anomaly_alert',
                    priority='high',
                    data={
                        'request_id': request_id,
                        'user_id': user_id,
                        'user_name': user.name if user else 'Unknown',
                        'segment_name': segment.name if segment else 'Unknown',
                        'anomaly_confidence': behavioral_result.get('confidence', 0),
                        'detected_at': current_time.isoformat()
                    }
                )
        
        logger.warning(f"Anomalous behavior flagged for JIT session: {request_id}")
        
    except Exception as e:
        logger.error(f"Error flagging anomalous behavior: {str(e)}")


async def _cleanup_old_monitoring_data(db, current_time: datetime):
    """Clean up old monitoring data to prevent database bloat"""
    try:
        # Clean up old expiration warnings (older than 7 days)
        cutoff_time = current_time - timedelta(days=7)
        
        warnings_ref = db.collection('jitExpirationWarnings')
        old_warnings = warnings_ref.where('sentAt', '<', cutoff_time).stream()
        
        deleted_count = 0
        for doc in old_warnings:
            doc.reference.delete()
            deleted_count += 1
        
        # Clean up old activity reports (older than 30 days)
        report_cutoff = current_time - timedelta(days=30)
        
        reports_ref = db.collection('jitActivityReports')
        old_reports = reports_ref.where('generatedAt', '<', report_cutoff).stream()
        
        for doc in old_reports:
            doc.reference.delete()
            deleted_count += 1
        
        logger.info(f"Cleaned up {deleted_count} old monitoring records")
        
    except Exception as e:
        logger.error(f"Error cleaning up old monitoring data: {str(e)}")


def _generate_activity_statistics(requests: List[Dict[str, Any]], 
                                start_time: datetime, end_time: datetime) -> Dict[str, Any]:
    """Generate activity statistics from JIT requests"""
    try:
        total_requests = len(requests)
        
        # Status breakdown
        status_counts = {}
        for request in requests:
            status = request.get('status', 'unknown')
            status_counts[status] = status_counts.get(status, 0) + 1
        
        # Urgency breakdown
        urgency_counts = {}
        for request in requests:
            urgency = request.get('urgency', 'unknown')
            urgency_counts[urgency] = urgency_counts.get(urgency, 0) + 1
        
        # User activity (top 10 most active users)
        user_activity = {}
        for request in requests:
            user_id = request.get('userId')
            if user_id:
                user_activity[user_id] = user_activity.get(user_id, 0) + 1
        
        top_users = sorted(user_activity.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Resource segment activity
        segment_activity = {}
        for request in requests:
            segment_id = request.get('resourceSegmentId')
            if segment_id:
                segment_activity[segment_id] = segment_activity.get(segment_id, 0) + 1
        
        top_segments = sorted(segment_activity.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Average session duration for granted requests
        granted_requests = [req for req in requests if req.get('status') == 'granted']
        avg_duration = 0
        if granted_requests:
            total_duration = sum(req.get('durationHours', 0) for req in granted_requests)
            avg_duration = total_duration / len(granted_requests)
        
        # Approval rate
        approval_rate = 0
        if total_requests > 0:
            approved_count = len([req for req in requests if req.get('status') in ['granted']])
            approval_rate = (approved_count / total_requests) * 100
        
        return {
            'totalRequests': total_requests,
            'statusBreakdown': status_counts,
            'urgencyBreakdown': urgency_counts,
            'topUsers': top_users,
            'topSegments': top_segments,
            'averageDurationHours': round(avg_duration, 2),
            'approvalRate': round(approval_rate, 2),
            'periodStart': start_time.isoformat(),
            'periodEnd': end_time.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error generating activity statistics: {str(e)}")
        return {
            'error': str(e),
            'totalRequests': 0
        }


# Celery beat schedule configuration (add this to your celery configuration)
CELERY_BEAT_SCHEDULE = {
    'monitor-jit-sessions': {
        'task': 'app.tasks.jit_monitoring_tasks.monitor_jit_access_sessions',
        'schedule': 300.0,  # Every 5 minutes
    },
    'cleanup-expired-jit-sessions': {
        'task': 'app.tasks.jit_monitoring_tasks.cleanup_expired_jit_sessions',
        'schedule': 3600.0,  # Every hour
    },
    'generate-daily-jit-report': {
        'task': 'app.tasks.jit_monitoring_tasks.generate_jit_activity_report',
        'schedule': 86400.0,  # Every 24 hours
        'kwargs': {'period_hours': 24}
    },
}