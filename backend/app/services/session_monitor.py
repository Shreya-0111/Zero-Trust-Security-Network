"""
Session Monitoring Service
Monitors behavioral risk scores and takes appropriate actions
"""

import os
from datetime import datetime
from typing import Dict, Optional
from app.models.behavioral_session import BehavioralSession
from app.services.behavioral_biometrics import behavioral_service
from app.services.audit_logger import log_audit_event
from app.models.notification import create_notification

# Risk thresholds
RISK_THRESHOLD_CRITICAL = 80  # Terminate session immediately
RISK_THRESHOLD_HIGH = 61      # Require re-authentication
RISK_THRESHOLD_MEDIUM = 31    # Monitor closely
RISK_THRESHOLD_LOW = 0        # Continue normally

# Monitoring interval (seconds)
MONITORING_INTERVAL = int(os.getenv('RISK_SCORE_UPDATE_INTERVAL', '30'))


class SessionMonitor:
    """Service for monitoring session risk scores and taking actions"""
    
    def __init__(self):
        self.monitoring_enabled = os.getenv('BEHAVIORAL_TRACKING_ENABLED', 'false').lower() == 'true'
    
    def check_session_risk(self, user_id: str, session_id: str) -> Dict:
        """
        Check session risk score and determine required action
        
        Returns:
            Dict with action, risk_score, risk_level, and message
        """
        if not self.monitoring_enabled:
            return {
                'action': 'continue',
                'risk_score': 0,
                'risk_level': 'unknown',
                'message': 'Behavioral monitoring is disabled'
            }
        
        try:
            # Get session
            session = BehavioralSession.get_by_session_id(session_id)
            
            if not session:
                return {
                    'action': 'continue',
                    'risk_score': 0,
                    'risk_level': 'unknown',
                    'message': 'Session not found'
                }
            
            # Calculate risk score
            risk_data = behavioral_service.calculate_risk_score(user_id, session)
            risk_score = risk_data.get('risk_score', 0)
            risk_level = risk_data.get('risk_level', 'unknown')
            
            # Determine action based on risk score
            if risk_score >= RISK_THRESHOLD_CRITICAL:
                action = 'terminate'
                message = 'Session terminated due to critical risk level'
                self._handle_critical_risk(user_id, session_id, risk_score, risk_data)
                
            elif risk_score >= RISK_THRESHOLD_HIGH:
                action = 'reauthenticate'
                message = 'Re-authentication required due to high risk level'
                self._handle_high_risk(user_id, session_id, risk_score, risk_data)
                
            elif risk_score >= RISK_THRESHOLD_MEDIUM:
                action = 'monitor'
                message = 'Session under close monitoring due to medium risk level'
                self._handle_medium_risk(user_id, session_id, risk_score, risk_data)
                
            else:
                action = 'continue'
                message = 'Session risk level is acceptable'
                self._handle_low_risk(user_id, session_id, risk_score, risk_data)
            
            # Update session with risk score
            session.update_risk_score(risk_score)
            
            # Log audit event
            log_audit_event(
                user_id=user_id,
                action='session_risk_check',
                resource_type='behavioral_session',
                resource_id=str(session_id),
                details={
                    'risk_score': risk_score,
                    'risk_level': risk_level,
                    'action_taken': action,
                    'component_scores': risk_data.get('component_scores', {})
                }
            )
            
            return {
                'action': action,
                'risk_score': risk_score,
                'risk_level': risk_level,
                'message': message,
                'component_scores': risk_data.get('component_scores', {}),
                'baseline_available': risk_data.get('baseline_available', False)
            }
            
        except Exception as e:
            print(f"Error checking session risk: {e}")
            return {
                'action': 'continue',
                'risk_score': 0,
                'risk_level': 'error',
                'message': f'Error checking risk: {str(e)}'
            }
    
    def _handle_critical_risk(self, user_id: str, session_id: str, risk_score: float, risk_data: Dict):
        """Handle critical risk level (>= 80) - Terminate session immediately"""
        try:
            # Emit session termination via WebSocket
            from websocket_config import emit_session_terminated
            emit_session_terminated(
                user_id=user_id,
                session_id=session_id,
                reason=f'Critical behavioral risk detected (score: {risk_score})'
            )
            
            # Create notification for user
            create_notification(
                user_id=user_id,
                title='Session Terminated',
                message=f'Your session was terminated due to unusual behavioral patterns (risk score: {risk_score}).',
                notification_type='security_alert',
                priority='high'
            )
            
            # Log security event
            log_audit_event(
                user_id=user_id,
                action='session_terminated_risk',
                resource_type='behavioral_session',
                resource_id=str(session_id),
                details={
                    'risk_score': risk_score,
                    'reason': 'critical_behavioral_risk',
                    'component_scores': risk_data.get('component_scores', {})
                },
                severity='high'
            )
            
            print(f"Session {session_id} terminated for user {user_id} due to critical risk: {risk_score}")
            
        except Exception as e:
            print(f"Error handling critical risk: {e}")
    
    def _handle_high_risk(self, user_id: str, session_id: str, risk_score: float, risk_data: Dict):
        """Handle high risk level (61-80) - Require re-authentication"""
        try:
            # Emit re-authentication requirement via WebSocket
            from websocket_config import socketio
            if socketio:
                room = f'user_{user_id}'
                socketio.emit('reauthentication_required', {
                    'session_id': session_id,
                    'risk_score': risk_score,
                    'reason': 'High behavioral risk detected',
                    'timestamp': datetime.utcnow().isoformat()
                }, room=room)
            
            # Create notification for user
            create_notification(
                user_id=user_id,
                title='Re-authentication Required',
                message=f'Please re-authenticate due to unusual behavioral patterns (risk score: {risk_score}).',
                notification_type='security_alert',
                priority='medium'
            )
            
            # Log security event
            log_audit_event(
                user_id=user_id,
                action='reauthentication_required',
                resource_type='behavioral_session',
                resource_id=str(session_id),
                details={
                    'risk_score': risk_score,
                    'reason': 'high_behavioral_risk',
                    'component_scores': risk_data.get('component_scores', {})
                },
                severity='medium'
            )
            
            print(f"Re-authentication required for user {user_id} due to high risk: {risk_score}")
            
        except Exception as e:
            print(f"Error handling high risk: {e}")
    
    def _handle_medium_risk(self, user_id: str, session_id: str, risk_score: float, risk_data: Dict):
        """Handle medium risk level (31-60) - Monitor closely"""
        try:
            # Emit monitoring alert via WebSocket
            from websocket_config import socketio
            if socketio:
                room = f'user_{user_id}'
                socketio.emit('session_monitoring', {
                    'session_id': session_id,
                    'risk_score': risk_score,
                    'risk_level': 'medium',
                    'message': 'Your session is being monitored for security',
                    'timestamp': datetime.utcnow().isoformat()
                }, room=room)
            
            # Log monitoring event
            log_audit_event(
                user_id=user_id,
                action='session_monitoring_increased',
                resource_type='behavioral_session',
                resource_id=str(session_id),
                details={
                    'risk_score': risk_score,
                    'reason': 'medium_behavioral_risk',
                    'component_scores': risk_data.get('component_scores', {})
                },
                severity='low'
            )
            
            print(f"Increased monitoring for user {user_id} due to medium risk: {risk_score}")
            
        except Exception as e:
            print(f"Error handling medium risk: {e}")
    
    def _handle_low_risk(self, user_id: str, session_id: str, risk_score: float, risk_data: Dict):
        """Handle low risk level (< 31) - Continue normally"""
        # Just log for tracking purposes
        print(f"Session {session_id} for user {user_id} has low risk: {risk_score}")
    
    def monitor_all_active_sessions(self):
        """
        Monitor all active sessions (called periodically by background task)
        
        This would be called by a Celery task every MONITORING_INTERVAL seconds
        """
        if not self.monitoring_enabled:
            return
        
        try:
            # This would need to query all active sessions from Firestore
            # For now, this is a placeholder for the Celery task
            print("Monitoring all active sessions...")
            
            # In a real implementation:
            # 1. Query all active sessions from Firestore
            # 2. For each session, check risk score
            # 3. Take appropriate action based on risk level
            
        except Exception as e:
            print(f"Error monitoring active sessions: {e}")


# Global monitor instance
session_monitor = SessionMonitor()
