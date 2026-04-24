"""
Celery Tasks for Session Monitoring
Periodic tasks to monitor behavioral risk scores and continuous authentication
"""

from celery_config import celery_app
from app.services.session_monitor import session_monitor
from app.services.continuous_auth_service import continuous_auth_service
from app.models.behavioral_session import BehavioralSession
from app.firebase_config import db
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


@celery_app.task(name='app.tasks.session_monitoring_tasks.monitor_active_sessions')
def monitor_active_sessions():
    """
    Monitor all active sessions for behavioral risk
    Runs every 30 seconds (configured in celery_config.py)
    """
    try:
        print("Starting active session monitoring...")
        
        # Get all sessions active in the last 5 minutes
        # In a real implementation, you would query Firestore for active sessions
        # For now, this is a placeholder
        
        session_monitor.monitor_all_active_sessions()
        
        print("Active session monitoring completed")
        return {'status': 'success', 'timestamp': datetime.utcnow().isoformat()}
        
    except Exception as e:
        print(f"Error in monitor_active_sessions task: {e}")
        return {'status': 'error', 'error': str(e)}


@celery_app.task(name='app.tasks.session_monitoring_tasks.continuous_auth_monitoring')
def continuous_auth_monitoring():
    """
    Monitor all active sessions for continuous authentication
    Updates risk scores every 5 minutes with contributing factor logging
    """
    try:
        logger.info("Starting continuous authentication monitoring...")
        
        # Get all active continuous authentication sessions
        cutoff_time = datetime.utcnow() - timedelta(hours=1)  # Sessions active in last hour
        
        sessions_query = db.collection('continuousAuthSessions')\
            .where('status', '==', 'active')\
            .where('lastActivity', '>=', cutoff_time)
        
        sessions = sessions_query.get()
        monitored_count = 0
        actions_taken = {
            'continue_normal': 0,
            'monitor_closely': 0,
            'require_mfa': 0,
            'terminate_session': 0
        }
        
        for session_doc in sessions:
            try:
                session_id = session_doc.id
                session_data = session_doc.to_dict()
                
                # Monitor the session
                result = continuous_auth_service.monitor_user_session(session_id)
                
                if result.get('success'):
                    monitored_count += 1
                    action = result.get('action_required', 'continue_normal')
                    actions_taken[action] = actions_taken.get(action, 0) + 1
                    
                    # Send real-time update via WebSocket
                    _send_risk_score_update(session_data.get('userId'), result)
                    
                    # Handle high-risk sessions
                    risk_score = result.get('risk_score', 0)
                    if risk_score >= 85:
                        # Terminate session
                        continuous_auth_service.terminate_suspicious_session(
                            session_id, 
                            f"Risk score exceeded threshold: {risk_score}"
                        )
                    elif risk_score >= 70:
                        # Trigger re-authentication
                        continuous_auth_service.trigger_reauthentication(
                            session_id, 
                            "high" if risk_score >= 80 else "medium"
                        )
                
            except Exception as e:
                logger.error(f"Error monitoring session {session_id}: {str(e)}")
                continue
        
        logger.info(f"Continuous authentication monitoring completed: {monitored_count} sessions monitored")
        logger.info(f"Actions taken: {actions_taken}")
        
        return {
            'status': 'success',
            'timestamp': datetime.utcnow().isoformat(),
            'sessions_monitored': monitored_count,
            'actions_taken': actions_taken
        }
        
    except Exception as e:
        logger.error(f"Error in continuous_auth_monitoring task: {str(e)}")
        return {'status': 'error', 'error': str(e)}


@celery_app.task(name='app.tasks.session_monitoring_tasks.check_session_risk')
def check_session_risk(user_id: str, session_id: str):
    """
    Check risk score for a specific session
    Can be called on-demand or scheduled
    """
    try:
        result = session_monitor.check_session_risk(user_id, session_id)
        return {
            'status': 'success',
            'user_id': user_id,
            'session_id': session_id,
            'result': result
        }
        
    except Exception as e:
        print(f"Error checking session risk: {e}")
        return {
            'status': 'error',
            'user_id': user_id,
            'session_id': session_id,
            'error': str(e)
        }


@celery_app.task(name='app.tasks.session_monitoring_tasks.update_behavioral_baselines')
def update_behavioral_baselines():
    """
    Update behavioral baselines for users with sufficient session data
    Runs daily to establish and refine user behavioral patterns
    """
    try:
        logger.info("Starting behavioral baseline updates...")
        
        # Get users who need baseline updates
        # This would query users with recent session activity
        users_query = db.collection('users').where('isActive', '==', True)
        users = users_query.get()
        
        updated_count = 0
        
        for user_doc in users:
            try:
                user_data = user_doc.to_dict()
                user_id = user_data.get('userId')
                
                if not user_id:
                    continue
                
                # Get recent behavioral sessions for this user
                sessions_query = db.collection('behavioralSessions')\
                    .where('user_id', '==', user_id)\
                    .where('session_start', '>=', datetime.utcnow() - timedelta(days=30))\
                    .limit(50)
                
                sessions = sessions_query.get()
                
                if len(sessions) >= 5:  # Minimum sessions for baseline
                    # Calculate behavioral baseline
                    baseline_data = _calculate_behavioral_baseline([doc.to_dict() for doc in sessions])
                    
                    # Store baseline
                    baseline_ref = db.collection('behavioralBaselines').document(user_id)
                    baseline_ref.set({
                        'userId': user_id,
                        'sessionCount': len(sessions),
                        'lastUpdated': datetime.utcnow(),
                        'baseline': baseline_data,
                        'confidence': min(len(sessions) / 20.0, 1.0)  # Max confidence at 20 sessions
                    })
                    
                    updated_count += 1
                
            except Exception as e:
                logger.error(f"Error updating baseline for user {user_id}: {str(e)}")
                continue
        
        logger.info(f"Behavioral baseline updates completed: {updated_count} users updated")
        
        return {
            'status': 'success',
            'timestamp': datetime.utcnow().isoformat(),
            'baselines_updated': updated_count
        }
        
    except Exception as e:
        logger.error(f"Error in update_behavioral_baselines task: {str(e)}")
        return {'status': 'error', 'error': str(e)}


def _send_risk_score_update(user_id: str, monitoring_result: dict):
    """Send real-time risk score update via WebSocket"""
    try:
        from websocket_config import socketio
        
        if socketio:
            room = f'user_{user_id}'
            socketio.emit('risk_score_update', {
                'user_id': user_id,
                'risk_score': monitoring_result.get('risk_score'),
                'risk_factors': monitoring_result.get('risk_factors'),
                'action_required': monitoring_result.get('action_required'),
                'baseline_available': monitoring_result.get('baseline_available'),
                'timestamp': datetime.utcnow().isoformat()
            }, room=room)
            
    except Exception as e:
        logger.error(f"Error sending risk score update: {str(e)}")


def _calculate_behavioral_baseline(sessions: list) -> dict:
    """Calculate behavioral baseline from session data"""
    try:
        # This is a simplified baseline calculation
        # In a real system, this would use more sophisticated analysis
        
        total_keystrokes = 0
        total_mouse_movements = 0
        total_clicks = 0
        session_durations = []
        access_hours = {}
        
        for session in sessions:
            # Aggregate keystroke data
            keystrokes = session.get('keystroke_data', [])
            total_keystrokes += len(keystrokes)
            
            # Aggregate mouse data
            mouse_data = session.get('mouse_data', [])
            total_mouse_movements += len(mouse_data)
            
            # Aggregate click data
            clicks = session.get('click_data', [])
            total_clicks += len(clicks)
            
            # Calculate session duration
            start_time = session.get('session_start')
            last_activity = session.get('last_activity')
            if start_time and last_activity:
                if isinstance(start_time, str):
                    start_time = datetime.fromisoformat(start_time)
                if isinstance(last_activity, str):
                    last_activity = datetime.fromisoformat(last_activity)
                
                duration = (last_activity - start_time).total_seconds() / 60  # minutes
                session_durations.append(duration)
                
                # Track access hours
                hour = start_time.hour
                access_hours[hour] = access_hours.get(hour, 0) + 1
        
        # Calculate averages
        num_sessions = len(sessions)
        avg_keystrokes_per_session = total_keystrokes / num_sessions if num_sessions > 0 else 0
        avg_mouse_movements_per_session = total_mouse_movements / num_sessions if num_sessions > 0 else 0
        avg_clicks_per_session = total_clicks / num_sessions if num_sessions > 0 else 0
        avg_session_duration = sum(session_durations) / len(session_durations) if session_durations else 0
        
        # Calculate typical access hours (normalize frequencies)
        total_accesses = sum(access_hours.values())
        typical_hours = {}
        for hour, count in access_hours.items():
            typical_hours[str(hour)] = count / total_accesses if total_accesses > 0 else 0
        
        return {
            'avg_keystrokes_per_session': avg_keystrokes_per_session,
            'avg_mouse_movements_per_session': avg_mouse_movements_per_session,
            'avg_clicks_per_session': avg_clicks_per_session,
            'avg_session_duration_minutes': avg_session_duration,
            'typical_access_hours': typical_hours,
            'total_sessions_analyzed': num_sessions
        }
        
    except Exception as e:
        logger.error(f"Error calculating behavioral baseline: {str(e)}")
        return {}