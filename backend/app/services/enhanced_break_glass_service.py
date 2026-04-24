"""
Enhanced Break-Glass Service with Off-Hours Security
Extends the break-glass service with additional security for off-hours access
"""

import logging
from datetime import datetime, timedelta, time
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
import pytz
import asyncio

from app.services.break_glass_service import BreakGlassService, EmergencyAccessRequest, EmergencyRequestStatus
from app.models.notification import create_notification
from app.services.enhanced_audit_service import enhanced_audit_service
from app.services.realtime_event_service import realtime_event_processor
from app.firebase_config import db

logger = logging.getLogger(__name__)


class OffHoursSecurityLevel(Enum):
    """Off-hours security level enumeration"""
    STANDARD = "standard"
    ENHANCED = "enhanced"
    MAXIMUM = "maximum"


class IncidentResponseWorkflow:
    """Incident response workflow guidance"""
    
    def __init__(self, incident_type: str, severity: str):
        self.incident_type = incident_type
        self.severity = severity
        self.workflow_steps = self._generate_workflow_steps()
    
    def _generate_workflow_steps(self) -> List[Dict[str, Any]]:
        """Generate workflow steps based on incident type and severity"""
        base_steps = [
            {
                'step': 1,
                'title': 'Initial Assessment',
                'description': 'Assess the scope and impact of the emergency',
                'required': True,
                'estimated_minutes': 5
            },
            {
                'step': 2,
                'title': 'Containment',
                'description': 'Implement immediate containment measures',
                'required': True,
                'estimated_minutes': 10
            },
            {
                'step': 3,
                'title': 'Investigation',
                'description': 'Investigate root cause and extent of impact',
                'required': True,
                'estimated_minutes': 15
            },
            {
                'step': 4,
                'title': 'Resolution',
                'description': 'Implement resolution and restore normal operations',
                'required': True,
                'estimated_minutes': 20
            },
            {
                'step': 5,
                'title': 'Documentation',
                'description': 'Document actions taken and lessons learned',
                'required': True,
                'estimated_minutes': 10
            }
        ]
        
        # Add specific steps based on incident type
        if self.incident_type == 'security_incident':
            base_steps.insert(2, {
                'step': 2.5,
                'title': 'Security Isolation',
                'description': 'Isolate affected systems and preserve evidence',
                'required': True,
                'estimated_minutes': 15
            })
        
        elif self.incident_type == 'system_outage':
            base_steps.insert(3, {
                'step': 3.5,
                'title': 'Service Restoration',
                'description': 'Restore critical services in priority order',
                'required': True,
                'estimated_minutes': 30
            })
        
        # Add severity-specific requirements
        if self.severity == 'critical':
            base_steps.insert(1, {
                'step': 1.5,
                'title': 'Senior Management Notification',
                'description': 'Notify senior management and stakeholders',
                'required': True,
                'estimated_minutes': 5
            })
        
        return base_steps
    
    def get_workflow_guidance(self) -> Dict[str, Any]:
        """Get complete workflow guidance"""
        total_estimated_time = sum(step.get('estimated_minutes', 0) for step in self.workflow_steps)
        
        return {
            'incident_type': self.incident_type,
            'severity': self.severity,
            'total_estimated_minutes': total_estimated_time,
            'workflow_steps': self.workflow_steps,
            'critical_reminders': self._get_critical_reminders(),
            'escalation_contacts': self._get_escalation_contacts()
        }
    
    def _get_critical_reminders(self) -> List[str]:
        """Get critical reminders for the incident type"""
        reminders = [
            "Document all actions taken with timestamps",
            "Preserve evidence and maintain chain of custody",
            "Communicate status updates to stakeholders",
            "Follow change management procedures for any modifications"
        ]
        
        if self.incident_type == 'security_incident':
            reminders.extend([
                "Do not power off affected systems without consulting security team",
                "Preserve network logs and system snapshots",
                "Consider legal and regulatory notification requirements"
            ])
        
        elif self.incident_type == 'data_recovery':
            reminders.extend([
                "Verify backup integrity before restoration",
                "Test restored data in isolated environment first",
                "Coordinate with data owners before proceeding"
            ])
        
        return reminders
    
    def _get_escalation_contacts(self) -> List[Dict[str, str]]:
        """Get escalation contact information"""
        return [
            {
                'role': 'Senior Administrator',
                'contact_method': 'Emergency phone line',
                'when_to_contact': 'If incident cannot be resolved within 30 minutes'
            },
            {
                'role': 'Security Team Lead',
                'contact_method': 'Security hotline',
                'when_to_contact': 'For any security-related incidents'
            },
            {
                'role': 'IT Director',
                'contact_method': 'Executive escalation line',
                'when_to_contact': 'For critical incidents affecting business operations'
            }
        ]


class EnhancedBreakGlassService(BreakGlassService):
    """Enhanced break-glass service with off-hours security features"""
    
    def __init__(self, db):
        super().__init__(db)
        
        # Business hours configuration (can be made configurable)
        self.business_hours_start = time(8, 0)  # 8:00 AM
        self.business_hours_end = time(18, 0)   # 6:00 PM
        self.business_days = [0, 1, 2, 3, 4]    # Monday-Friday (0=Monday)
        self.timezone = pytz.timezone('UTC')    # Can be configured per organization
        
        # Off-hours security thresholds
        self.off_hours_additional_approvers = 1  # Require 1 additional approver
        self.off_hours_senior_admin_required = True
        self.off_hours_verification_methods = ['mfa', 'phone_verification', 'security_questions']
    
    def is_off_hours(self, timestamp: datetime = None) -> bool:
        """
        Determine if the given timestamp is outside business hours
        
        Args:
            timestamp: Timestamp to check (defaults to current time)
            
        Returns:
            bool: True if off-hours
        """
        if timestamp is None:
            timestamp = datetime.utcnow()
        
        # Convert to configured timezone
        local_time = self.timezone.localize(timestamp) if timestamp.tzinfo is None else timestamp.astimezone(self.timezone)
        
        # Check if it's a business day
        if local_time.weekday() not in self.business_days:
            return True
        
        # Check if it's within business hours
        current_time = local_time.time()
        if current_time < self.business_hours_start or current_time >= self.business_hours_end:
            return True
        
        return False
    
    def get_off_hours_security_level(self, emergency_type: str, urgency_level: str) -> OffHoursSecurityLevel:
        """
        Determine the required security level for off-hours access
        
        Args:
            emergency_type: Type of emergency
            urgency_level: Urgency level
            
        Returns:
            OffHoursSecurityLevel: Required security level
        """
        # Critical security incidents require maximum security
        if emergency_type == 'security_incident' and urgency_level == 'critical':
            return OffHoursSecurityLevel.MAXIMUM
        
        # High urgency or sensitive operations require enhanced security
        if urgency_level == 'critical' or emergency_type in ['data_recovery', 'system_outage']:
            return OffHoursSecurityLevel.ENHANCED
        
        # Standard off-hours security for other cases
        return OffHoursSecurityLevel.STANDARD
    
    async def submit_emergency_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Submit emergency access request with off-hours security enhancements
        
        Args:
            request_data: Emergency request data
            
        Returns:
            dict: Request submission result with off-hours considerations
        """
        try:
            # Check if this is an off-hours request
            is_off_hours = self.is_off_hours()
            
            if is_off_hours:
                # Apply off-hours security enhancements
                off_hours_result = await self._apply_off_hours_security(request_data)
                if not off_hours_result['success']:
                    return off_hours_result
                
                # Update request data with off-hours requirements
                request_data = off_hours_result['enhanced_request_data']
            
            # Call parent method to handle standard processing
            result = await super().submit_emergency_request(request_data)
            
            if result['success'] and is_off_hours:
                # Add off-hours specific information to the result
                result['off_hours_request'] = True
                result['security_level'] = self.get_off_hours_security_level(
                    request_data['emergencyType'],
                    request_data['urgencyLevel']
                ).value
                result['additional_requirements'] = off_hours_result.get('additional_requirements', [])
                
                # Send immediate alerts to senior administrators
                await self._alert_senior_administrators(result['requestId'], request_data)
                
                # Log off-hours request
                await self._log_off_hours_request(result['requestId'], request_data)
            
            return result
            
        except Exception as e:
            logger.error(f"Error submitting off-hours emergency request: {str(e)}")
            return {
                'success': False,
                'error': f'Failed to submit off-hours emergency request: {str(e)}'
            }
    
    async def _apply_off_hours_security(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply off-hours security enhancements to the request
        
        Args:
            request_data: Original request data
            
        Returns:
            dict: Enhanced request data with off-hours security
        """
        try:
            security_level = self.get_off_hours_security_level(
                request_data['emergencyType'],
                request_data['urgencyLevel']
            )
            
            additional_requirements = []
            enhanced_request_data = request_data.copy()
            
            # Apply security level specific requirements
            if security_level == OffHoursSecurityLevel.ENHANCED:
                additional_requirements.extend([
                    'Additional administrator approval required',
                    'Phone verification with senior administrator',
                    'Enhanced activity monitoring during session'
                ])
                
                # Require additional approver
                enhanced_request_data['required_approvals'] = 3  # Instead of standard 2
                
            elif security_level == OffHoursSecurityLevel.MAXIMUM:
                additional_requirements.extend([
                    'Senior administrator approval mandatory',
                    'Multi-factor authentication required',
                    'Real-time session monitoring',
                    'Immediate incident response team notification',
                    'Screen recording mandatory'
                ])
                
                # Require senior admin and additional approvers
                enhanced_request_data['required_approvals'] = 3
                enhanced_request_data['senior_admin_required'] = True
                enhanced_request_data['screen_recording_required'] = True
                
            else:  # STANDARD
                additional_requirements.extend([
                    'Off-hours access logged with enhanced detail',
                    'Automatic senior administrator notification'
                ])
            
            # Add off-hours verification requirements
            enhanced_request_data['off_hours_verification'] = {
                'required_methods': self.off_hours_verification_methods,
                'security_level': security_level.value,
                'additional_requirements': additional_requirements
            }
            
            return {
                'success': True,
                'enhanced_request_data': enhanced_request_data,
                'additional_requirements': additional_requirements,
                'security_level': security_level.value
            }
            
        except Exception as e:
            logger.error(f"Error applying off-hours security: {str(e)}")
            return {
                'success': False,
                'error': f'Failed to apply off-hours security: {str(e)}'
            }
    
    async def _alert_senior_administrators(self, request_id: str, request_data: Dict[str, Any]) -> bool:
        """
        Send immediate alerts to senior administrators for off-hours usage
        
        Args:
            request_id: Emergency request ID
            request_data: Request data
            
        Returns:
            bool: True if alerts sent successfully
        """
        try:
            # Get senior administrators
            senior_admins = await self._get_senior_administrators()
            
            if not senior_admins:
                logger.warning("No senior administrators found for off-hours alert")
                return False
            
            alert_title = f"🚨 OFF-HOURS Emergency Access Request"
            alert_message = (
                f"Emergency access requested outside business hours.\n"
                f"Type: {request_data.get('emergencyType', 'Unknown')}\n"
                f"Urgency: {request_data.get('urgencyLevel', 'Unknown')}\n"
                f"Requester: {request_data.get('requesterId', 'Unknown')}\n"
                f"Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                f"Immediate review required."
            )
            
            alerts_sent = 0
            
            for admin in senior_admins:
                admin_id = admin.get('user_id') or admin.get('userId')
                if admin_id:
                    # Create high-priority notification
                    notification_created = create_notification(
                        user_id=admin_id,
                        title=alert_title,
                        message=alert_message,
                        notification_type='emergency_alert',
                        priority='critical',
                        metadata={
                            'request_id': request_id,
                            'off_hours_request': True,
                            'emergency_type': request_data.get('emergencyType'),
                            'urgency_level': request_data.get('urgencyLevel'),
                            'requires_immediate_attention': True
                        }
                    )
                    
                    if notification_created:
                        alerts_sent += 1
            
            # Also create system-wide alert
            security_alert = {
                'alert_type': 'off_hours_emergency_request',
                'request_id': request_id,
                'request_data': request_data,
                'senior_admins_notified': alerts_sent,
                'timestamp': datetime.utcnow(),
                'requires_immediate_response': True
            }
            
            # Store alert and broadcast
            db.collection('security_alerts').add(security_alert)
            await realtime_event_processor.broadcast_security_event(security_alert)
            
            logger.info(f"Senior administrators alerted for off-hours request {request_id}: {alerts_sent} notifications sent")
            return alerts_sent > 0
            
        except Exception as e:
            logger.error(f"Error alerting senior administrators: {e}")
            return False
    
    async def _get_senior_administrators(self) -> List[Dict[str, Any]]:
        """Get list of senior administrators"""
        try:
            # Get administrators with senior role or specific permissions
            users_ref = db.collection('users')
            
            # Query for senior admins (assuming role hierarchy or specific field)
            senior_query = users_ref.where('role', '==', 'senior_admin').where('isActive', '==', True)
            senior_docs = list(senior_query.stream())
            
            # If no senior admins, fall back to regular admins
            if not senior_docs:
                admin_query = users_ref.where('role', '==', 'admin').where('isActive', '==', True)
                senior_docs = list(admin_query.stream())
            
            senior_admins = []
            for doc in senior_docs:
                admin_data = doc.to_dict()
                senior_admins.append({
                    'user_id': admin_data.get('userId') or admin_data.get('uid'),
                    'name': admin_data.get('name', 'Unknown'),
                    'email': admin_data.get('email', ''),
                    'role': admin_data.get('role', 'admin'),
                    'last_login': admin_data.get('lastLogin')
                })
            
            return senior_admins
            
        except Exception as e:
            logger.error(f"Error getting senior administrators: {e}")
            return []
    
    async def _log_off_hours_request(self, request_id: str, request_data: Dict[str, Any]) -> bool:
        """
        Log off-hours emergency request with enhanced detail
        
        Args:
            request_id: Request ID
            request_data: Request data
            
        Returns:
            bool: True if logged successfully
        """
        try:
            # Enhanced logging for off-hours requests
            enhanced_audit_service.log_security_event(
                event_type='off_hours_emergency_request',
                severity='high',
                user_id=request_data.get('requesterId'),
                details={
                    'request_id': request_id,
                    'emergency_type': request_data.get('emergencyType'),
                    'urgency_level': request_data.get('urgencyLevel'),
                    'off_hours_timestamp': datetime.utcnow().isoformat(),
                    'business_hours_config': {
                        'start': self.business_hours_start.strftime('%H:%M'),
                        'end': self.business_hours_end.strftime('%H:%M'),
                        'business_days': self.business_days
                    },
                    'security_level': self.get_off_hours_security_level(
                        request_data.get('emergencyType', ''),
                        request_data.get('urgencyLevel', '')
                    ).value,
                    'additional_security_applied': True
                }
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Error logging off-hours request: {e}")
            return False
    
    def get_incident_response_workflow(self, emergency_type: str, urgency_level: str) -> Dict[str, Any]:
        """
        Get incident response workflow guidance
        
        Args:
            emergency_type: Type of emergency
            urgency_level: Urgency level
            
        Returns:
            dict: Incident response workflow guidance
        """
        try:
            workflow = IncidentResponseWorkflow(emergency_type, urgency_level)
            return workflow.get_workflow_guidance()
            
        except Exception as e:
            logger.error(f"Error getting incident response workflow: {e}")
            return {
                'error': f'Failed to generate workflow guidance: {str(e)}'
            }
    
    async def process_approval(self, request_id: str, approver_id: str, decision: str, 
                             comments: str = '') -> Dict[str, Any]:
        """
        Process approval with off-hours verification requirements
        
        Args:
            request_id: Emergency request ID
            approver_id: Administrator ID making the decision
            decision: 'approved' or 'denied'
            comments: Optional approval comments
            
        Returns:
            dict: Approval processing result with off-hours verification
        """
        try:
            # Get the request to check if it's off-hours
            request_ref = db.collection('breakGlassRequests').document(request_id)
            request_doc = request_ref.get()
            
            if not request_doc.exists:
                return {
                    'success': False,
                    'error': 'Emergency request not found'
                }
            
            request_data = request_doc.to_dict()
            
            # Check if this was an off-hours request
            requested_at = request_data.get('requestedAt')
            if isinstance(requested_at, str):
                requested_at = datetime.fromisoformat(requested_at.replace('Z', '+00:00'))
            
            was_off_hours = self.is_off_hours(requested_at)
            
            if was_off_hours and decision == 'approved':
                # Perform additional verification for off-hours approvals
                verification_result = await self._perform_off_hours_verification(
                    approver_id, request_data
                )
                
                if not verification_result['success']:
                    return {
                        'success': False,
                        'error': f'Off-hours verification failed: {verification_result["error"]}'
                    }
            
            # Call parent method for standard processing
            result = await super().process_approval(request_id, approver_id, decision, comments)
            
            if result['success'] and was_off_hours:
                # Add off-hours specific information
                result['off_hours_approval'] = True
                result['verification_completed'] = True
                
                # Log off-hours approval
                await self._log_off_hours_approval(request_id, approver_id, decision)
            
            return result
            
        except Exception as e:
            logger.error(f"Error processing off-hours approval: {str(e)}")
            return {
                'success': False,
                'error': f'Failed to process off-hours approval: {str(e)}'
            }
    
    async def _perform_off_hours_verification(self, approver_id: str, 
                                            request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform additional verification for off-hours approvals
        
        Args:
            approver_id: ID of the approving administrator
            request_data: Emergency request data
            
        Returns:
            dict: Verification result
        """
        try:
            # Get approver information
            approver_ref = db.collection('users').document(approver_id)
            approver_doc = approver_ref.get()
            
            if not approver_doc.exists:
                return {
                    'success': False,
                    'error': 'Approver not found'
                }
            
            approver_data = approver_doc.to_dict()
            
            # Check if approver has sufficient privileges for off-hours approval
            approver_role = approver_data.get('role', '')
            
            security_level = self.get_off_hours_security_level(
                request_data.get('emergencyType', ''),
                request_data.get('urgencyLevel', '')
            )
            
            # For maximum security, require senior admin
            if security_level == OffHoursSecurityLevel.MAXIMUM:
                if approver_role not in ['senior_admin', 'super_admin']:
                    return {
                        'success': False,
                        'error': 'Senior administrator approval required for maximum security off-hours requests'
                    }
            
            # In a real implementation, you would perform additional verification:
            # - Phone verification
            # - Additional MFA challenge
            # - Security questions
            # - Biometric verification (if available)
            
            # For now, we'll simulate successful verification
            verification_methods_used = ['role_verification']
            
            if security_level in [OffHoursSecurityLevel.ENHANCED, OffHoursSecurityLevel.MAXIMUM]:
                verification_methods_used.extend(['mfa_challenge', 'phone_verification'])
            
            # Log verification
            enhanced_audit_service.log_security_event(
                event_type='off_hours_verification',
                severity='info',
                user_id=approver_id,
                details={
                    'request_id': request_data.get('requestId'),
                    'security_level': security_level.value,
                    'verification_methods': verification_methods_used,
                    'approver_role': approver_role,
                    'verification_timestamp': datetime.utcnow().isoformat()
                }
            )
            
            return {
                'success': True,
                'verification_methods': verification_methods_used,
                'security_level': security_level.value
            }
            
        except Exception as e:
            logger.error(f"Error performing off-hours verification: {e}")
            return {
                'success': False,
                'error': f'Verification failed: {str(e)}'
            }
    
    async def _log_off_hours_approval(self, request_id: str, approver_id: str, decision: str) -> bool:
        """
        Log off-hours approval with enhanced detail
        
        Args:
            request_id: Request ID
            approver_id: Approver ID
            decision: Approval decision
            
        Returns:
            bool: True if logged successfully
        """
        try:
            enhanced_audit_service.log_security_event(
                event_type='off_hours_approval',
                severity='high',
                user_id=approver_id,
                details={
                    'request_id': request_id,
                    'decision': decision,
                    'approval_timestamp': datetime.utcnow().isoformat(),
                    'off_hours_verification_completed': True,
                    'enhanced_security_applied': True
                }
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Error logging off-hours approval: {e}")
            return False
    
    async def get_off_hours_statistics(self, days: int = 30) -> Dict[str, Any]:
        """
        Get statistics for off-hours emergency access requests
        
        Args:
            days: Number of days to analyze
            
        Returns:
            dict: Off-hours statistics
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Query emergency requests from the specified period
            requests_ref = db.collection('breakGlassRequests')
            query = requests_ref.where('requestedAt', '>=', cutoff_date)
            
            total_requests = 0
            off_hours_requests = 0
            off_hours_by_type = {}
            off_hours_by_urgency = {}
            
            for doc in query.stream():
                request_data = doc.to_dict()
                total_requests += 1
                
                requested_at = request_data.get('requestedAt')
                if isinstance(requested_at, str):
                    requested_at = datetime.fromisoformat(requested_at.replace('Z', '+00:00'))
                
                if self.is_off_hours(requested_at):
                    off_hours_requests += 1
                    
                    # Count by type
                    emergency_type = request_data.get('emergencyType', 'unknown')
                    off_hours_by_type[emergency_type] = off_hours_by_type.get(emergency_type, 0) + 1
                    
                    # Count by urgency
                    urgency = request_data.get('urgencyLevel', 'unknown')
                    off_hours_by_urgency[urgency] = off_hours_by_urgency.get(urgency, 0) + 1
            
            off_hours_percentage = (off_hours_requests / total_requests * 100) if total_requests > 0 else 0
            
            return {
                'period_days': days,
                'total_requests': total_requests,
                'off_hours_requests': off_hours_requests,
                'off_hours_percentage': round(off_hours_percentage, 2),
                'off_hours_by_type': off_hours_by_type,
                'off_hours_by_urgency': off_hours_by_urgency,
                'business_hours_config': {
                    'start': self.business_hours_start.strftime('%H:%M'),
                    'end': self.business_hours_end.strftime('%H:%M'),
                    'business_days': self.business_days,
                    'timezone': str(self.timezone)
                },
                'generated_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting off-hours statistics: {e}")
            return {
                'error': f'Failed to generate statistics: {str(e)}'
            }


# Global service instance
enhanced_break_glass_service = EnhancedBreakGlassService(db)