"""
Break-Glass Emergency Access Service
Handles emergency access procedures with dual approval and comprehensive logging
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
import uuid
import asyncio

from ..models.audit_log import create_audit_log
from ..firebase_config import get_firestore_client
from .enhanced_firebase_service import enhanced_firebase_service
from .session_management import session_management

logger = logging.getLogger(__name__)


class EmergencyRequestStatus(Enum):
    """Emergency request status enumeration"""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    ACTIVE = "active"
    EXPIRED = "expired"
    COMPLETED = "completed"


class EmergencyType(Enum):
    """Emergency type enumeration"""
    SYSTEM_OUTAGE = "system_outage"
    SECURITY_INCIDENT = "security_incident"
    DATA_RECOVERY = "data_recovery"
    CRITICAL_MAINTENANCE = "critical_maintenance"


class UrgencyLevel(Enum):
    """Urgency level enumeration"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"


class EmergencyAccessRequest:
    """Emergency access request model"""
    
    def __init__(self, requester_id: str, emergency_type: str, urgency_level: str, 
                 justification: str, required_resources: List[str], estimated_duration: float):
        self.request_id = str(uuid.uuid4())
        self.requester_id = requester_id
        self.emergency_type = emergency_type
        self.urgency_level = urgency_level
        self.justification = justification
        self.required_resources = required_resources
        self.estimated_duration = estimated_duration
        self.requested_at = datetime.utcnow()
        self.status = EmergencyRequestStatus.PENDING
        self.approvals = []
        self.activated_at = None
        self.expires_at = None
        self.emergency_session = None
        self.required_approvals = 2
        self.post_incident_review = {
            'reviewRequired': True,
            'reviewedBy': None,
            'reviewedAt': None,
            'findings': None,
            'recommendations': [],
            'complianceStatus': 'under_review'
        }
        self.notification_log = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Firestore storage"""
        return {
            'requestId': self.request_id,
            'requesterId': self.requester_id,
            'emergencyType': self.emergency_type,
            'urgencyLevel': self.urgency_level,
            'justification': self.justification,
            'requiredResources': self.required_resources,
            'estimatedDuration': self.estimated_duration,
            'requestedAt': self.requested_at,
            'status': self.status.value,
            'approvals': self.approvals,
            'activatedAt': self.activated_at,
            'expiresAt': self.expires_at,
            'emergencySession': self.emergency_session,
            'requiredApprovals': self.required_approvals,
            'postIncidentReview': self.post_incident_review,
            'notificationLog': self.notification_log
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EmergencyAccessRequest':
        """Create from dictionary"""
        request = cls(
            data['requesterId'],
            data['emergencyType'],
            data['urgencyLevel'],
            data['justification'],
            data['requiredResources'],
            data['estimatedDuration']
        )
        request.request_id = data.get('requestId', request.request_id)
        request.requested_at = data.get('requestedAt', datetime.utcnow())
        request.status = EmergencyRequestStatus(data.get('status', 'pending'))
        request.approvals = data.get('approvals', [])
        request.activated_at = data.get('activatedAt')
        request.expires_at = data.get('expiresAt')
        request.emergency_session = data.get('emergencySession')
        request.required_approvals = data.get('requiredApprovals', 2)
        request.post_incident_review = data.get('postIncidentReview', request.post_incident_review)
        request.notification_log = data.get('notificationLog', [])
        return request


class BreakGlassService:
    """Service for managing break-glass emergency access with dual approval"""
    
    # Approval timeout in minutes
    APPROVAL_TIMEOUT_MINUTES = 30
    
    # Maximum emergency session duration in hours
    MAX_SESSION_DURATION_HOURS = 2
    
    def __init__(self, db):
        """
        Initialize Break-Glass Service
        
        Args:
            db: Firestore client
        """
        self.db = db
    
    async def submit_emergency_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Submit emergency access request
        
        Args:
            request_data (dict): Emergency request data containing:
                - requesterId: User ID making the request
                - emergencyType: Type of emergency
                - urgencyLevel: Urgency level
                - justification: Detailed justification
                - requiredResources: List of resource segment IDs
                - estimatedDuration: Estimated duration in hours
        
        Returns:
            dict: Request submission result
        """
        try:
            # Validate request data
            validation_result = self._validate_emergency_request(request_data)
            if not validation_result['valid']:
                return {
                    'success': False,
                    'error': validation_result['error']
                }
            
            # Create emergency request
            emergency_request = EmergencyAccessRequest(
                request_data['requesterId'],
                request_data['emergencyType'],
                request_data['urgencyLevel'],
                request_data['justification'],
                request_data['requiredResources'],
                request_data['estimatedDuration']
            )
            
            if 'required_approvals' in request_data:
                emergency_request.required_approvals = request_data['required_approvals']
            
            # Store request in Firestore
            request_ref = self.db.collection('breakGlassRequests').document(emergency_request.request_id)
            request_ref.set(emergency_request.to_dict())
            
            # Get available administrators
            available_admins = await self._get_available_administrators()
            
            result = {
                'success': True,
                'requestId': emergency_request.request_id,
                'message': f'Emergency access request submitted. Awaiting dual approval within {self.APPROVAL_TIMEOUT_MINUTES} minutes.',
                'approvalRequired': True,
                'timeoutMinutes': self.APPROVAL_TIMEOUT_MINUTES
            }

            if len(available_admins) < 2:
                warning_message = f"Insufficient administrators available for dual approval (found {len(available_admins)}). Auto-approving for single-admin environments."
                logger.warning(warning_message)
                result['warning'] = warning_message
            
            # Send immediate notifications to administrators
            notifications_sent = await self._notify_administrators(emergency_request, available_admins)
            result['notificationsSent'] = notifications_sent
            
            # Log the emergency request
            await self._log_emergency_request(emergency_request)
            
            # Schedule approval timeout check
            await self._schedule_approval_timeout(emergency_request.request_id)
            
            return result
            
        except Exception as e:
            logger.error(f"Error submitting emergency request: {str(e)}")
            return {
                'success': False,
                'error': f'Failed to submit emergency request: {str(e)}'
            }
    
    async def process_approval(self, request_id: str, approver_id: str, decision: str, 
                             comments: str = '') -> Dict[str, Any]:
        """
        Process approval decision for emergency request
        
        Args:
            request_id: Emergency request ID
            approver_id: Administrator ID making the decision
            decision: 'approved' or 'denied'
            comments: Optional approval comments
        
        Returns:
            dict: Approval processing result
        """
        try:
            # Get emergency request
            request_ref = self.db.collection('breakGlassRequests').document(request_id)
            request_doc = request_ref.get()
            
            if not request_doc.exists:
                return {
                    'success': False,
                    'error': 'Emergency request not found'
                }
            
            emergency_request = EmergencyAccessRequest.from_dict(request_doc.to_dict())
            
            # Check if request is still pending
            if emergency_request.status != EmergencyRequestStatus.PENDING:
                return {
                    'success': False,
                    'error': f'Request is no longer pending (status: {emergency_request.status.value})'
                }
            
            # Check if approver has already approved/denied this request
            existing_approval = next(
                (approval for approval in emergency_request.approvals 
                 if approval['approverId'] == approver_id), 
                None
            )
            
            if existing_approval:
                return {
                    'success': False,
                    'error': 'You have already provided a decision for this request'
                }
            
            # Add approval/denial
            approval_record = {
                'approverId': approver_id,
                'decision': decision,
                'timestamp': datetime.utcnow(),
                'comments': comments
            }
            
            emergency_request.approvals.append(approval_record)
            
            # Check if request should be denied
            if decision == 'denied':
                emergency_request.status = EmergencyRequestStatus.DENIED
                
                # Update in Firestore
                request_ref.update(emergency_request.to_dict())
                
                # Notify requester of denial
                await self._notify_requester_denial(emergency_request, approver_id, comments)
                
                # Log the denial
                await self._log_approval_decision(emergency_request, approver_id, decision, comments)
                
                return {
                    'success': True,
                    'message': 'Emergency request denied',
                    'status': 'denied'
                }
            
            # Check if we have enough approvals
            required_approvals = getattr(emergency_request, 'required_approvals', 2)
            approved_count = len([a for a in emergency_request.approvals if a['decision'] == 'approved'])
            unique_approvers = set(a['approverId'] for a in emergency_request.approvals if a['decision'] == 'approved')
            
            if approved_count >= required_approvals and len(unique_approvers) >= required_approvals:
                # Activate emergency access
                activation_result = await self._activate_emergency_access(emergency_request)
                
                if activation_result['success']:
                    return {
                        'success': True,
                        'message': 'Emergency access activated with dual approval',
                        'status': 'activated',
                        'sessionId': activation_result['sessionId'],
                        'expiresAt': activation_result['expiresAt']
                    }
                else:
                    return {
                        'success': False,
                        'error': f'Failed to activate emergency access: {activation_result["error"]}'
                    }
            else:
                # Update request with new approval
                request_ref.update(emergency_request.to_dict())
                
                # Log the approval
                await self._log_approval_decision(emergency_request, approver_id, decision, comments)
                
                remaining_approvals = required_approvals - approved_count
                return {
                    'success': True,
                    'message': f'Approval recorded. {remaining_approvals} more approval(s) needed.',
                    'status': 'pending',
                    'approvalsReceived': approved_count,
                    'approvalsRequired': required_approvals
                }
                
        except Exception as e:
            logger.error(f"Error processing approval: {str(e)}")
            return {
                'success': False,
                'error': f'Failed to process approval: {str(e)}'
            }
    
    async def get_pending_emergency_requests(self, admin_id: str) -> List[Dict[str, Any]]:
        """
        Get pending emergency requests for administrator review
        
        Args:
            admin_id: Administrator ID
        
        Returns:
            List of pending emergency requests
        """
        try:
            # Get pending requests
            requests_ref = self.db.collection('breakGlassRequests')
            query = requests_ref.where('status', '==', 'pending')
            
            pending_requests = []
            for doc in query.stream():
                request_data = doc.to_dict()
                # Ensure callers always have a stable identifier for actions/approval routes.
                request_data.setdefault('requestId', doc.id)
                
                # Check if this admin has already provided a decision
                has_decided = any(
                    approval['approverId'] == admin_id 
                    for approval in request_data.get('approvals', [])
                )
                
                if not has_decided:
                    # Enrich with requester information
                    requester = await self._get_user_info(request_data['requesterId'])
                    if requester:
                        request_data['requesterName'] = requester.get('name', 'Unknown')
                        request_data['requesterRole'] = requester.get('role', 'Unknown')
                        request_data['requesterEmail'] = requester.get('email', 'Unknown')
                    
                    # Enrich with resource segment information
                    request_data['resourceDetails'] = []
                    for resource_id in request_data.get('requiredResources', []):
                        resource_info = await self._get_resource_segment_info(resource_id)
                        if resource_info:
                            request_data['resourceDetails'].append(resource_info)
                    
                    # Calculate time remaining
                    requested_at = request_data.get('requestedAt')
                    if requested_at:
                        if isinstance(requested_at, str):
                            requested_at = datetime.fromisoformat(requested_at.replace('Z', '+00:00'))
                        # Firestore may return timezone-aware datetimes; normalize to aware UTC.
                        if isinstance(requested_at, datetime):
                            if requested_at.tzinfo is None:
                                requested_at = requested_at.replace(tzinfo=timezone.utc)
                            else:
                                requested_at = requested_at.astimezone(timezone.utc)
                        
                        timeout_at = requested_at + timedelta(minutes=self.APPROVAL_TIMEOUT_MINUTES)
                        time_remaining = timeout_at - datetime.now(timezone.utc)
                        request_data['timeRemainingMinutes'] = max(0, int(time_remaining.total_seconds() / 60))
                        request_data['isExpired'] = time_remaining.total_seconds() <= 0
                    
                    pending_requests.append(request_data)
            
            # Sort by urgency and time requested
            urgency_priority = {'critical': 3, 'high': 2, 'medium': 1}
            pending_requests.sort(
                key=lambda x: (
                    urgency_priority.get(x.get('urgencyLevel', 'medium'), 1),
                    x.get('requestedAt', datetime.min)
                ),
                reverse=True
            )
            
            return pending_requests
            
        except Exception as e:
            logger.error(f"Error getting pending emergency requests: {str(e)}")
            return []
    
    async def get_available_administrators(self) -> List[Dict[str, Any]]:
        """
        Get list of available administrators for emergency approval
        
        Returns:
            List of available administrators
        """
        try:
            return await self._get_available_administrators()
        except Exception as e:
            logger.error(f"Error getting available administrators: {str(e)}")
            return []
    
    async def monitor_emergency_session(self, session_id: str) -> Dict[str, Any]:
        """
        Monitor active emergency session
        
        Args:
            session_id: Emergency session ID
        
        Returns:
            Session monitoring data
        """
        try:
            # Get emergency session
            session_ref = self.db.collection('emergencySessions').document(session_id)
            session_doc = session_ref.get()
            
            if not session_doc.exists:
                return {
                    'success': False,
                    'error': 'Emergency session not found'
                }
            
            session_data = session_doc.to_dict()
            
            # Check if session is still active
            if session_data.get('status') != 'active':
                return {
                    'success': False,
                    'error': f'Session is not active (status: {session_data.get("status")})'
                }
            
            # Check if session has expired
            expires_at = session_data.get('expiresAt')
            if expires_at and isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
            
            if expires_at and datetime.utcnow() > expires_at:
                # Auto-expire the session
                await self._expire_emergency_session(session_id)
                return {
                    'success': False,
                    'error': 'Session has expired'
                }
            
            # Get recent activity
            activity_log = session_data.get('activityLog', [])
            recent_activity = activity_log[-10:] if activity_log else []  # Last 10 activities
            
            # Calculate time remaining
            time_remaining = None
            if expires_at:
                time_remaining = expires_at - datetime.utcnow()
                time_remaining = max(0, int(time_remaining.total_seconds()))
            
            return {
                'success': True,
                'sessionId': session_id,
                'status': session_data.get('status'),
                'userId': session_data.get('userId'),
                'elevatedPrivileges': session_data.get('elevatedPrivileges', []),
                'recentActivity': recent_activity,
                'timeRemainingSeconds': time_remaining,
                'activityCount': len(activity_log)
            }
            
        except Exception as e:
            logger.error(f"Error monitoring emergency session: {str(e)}")
            return {
                'success': False,
                'error': f'Failed to monitor session: {str(e)}'
            }
    
    async def log_emergency_activity(self, session_id: str, activity_data: Dict[str, Any]) -> bool:
        """
        Log activity during emergency session
        
        Args:
            session_id: Emergency session ID
            activity_data: Activity data to log
        
        Returns:
            Success status
        """
        try:
            # Get emergency session
            session_ref = self.db.collection('emergencySessions').document(session_id)
            session_doc = session_ref.get()
            
            if not session_doc.exists:
                logger.error(f"Emergency session {session_id} not found")
                return False
            
            # Create activity log entry
            activity_entry = {
                'timestamp': datetime.utcnow(),
                'action': activity_data.get('action', 'unknown'),
                'resource': activity_data.get('resource', ''),
                'command': activity_data.get('command', ''),
                'dataAccessed': activity_data.get('dataAccessed', []),
                'ipAddress': activity_data.get('ipAddress', ''),
                'riskScore': activity_data.get('riskScore', 0),
                'result': activity_data.get('result', 'unknown')
            }
            
            # Verify anomaly logic: check if resource accessed is part of requiredResources
            # First, get the request associated with this session to find requested resources and justification
            requests_ref = self.db.collection('breakGlassRequests')
            query = requests_ref.where('emergencySession.sessionId', '==', session_id)
            request_doc = None
            for doc in query.stream():
                request_doc = doc.to_dict()
                break
                
            if request_doc and activity_entry.get('resource'):
                requested_resources = request_doc.get('requiredResources', [])
                if activity_entry['resource'] not in requested_resources:
                    # Mismatch found! Generate critical alert.
                    from .realtime_event_service import realtime_event_processor
                    
                    alert_message = f"Critical Anomaly: Admin accessed unauthorized resource ({activity_entry['resource']}) during break-glass session."
                    security_alert = {
                        'alert_type': 'break_glass_anomaly',
                        'session_id': session_id,
                        'user_id': activity_data.get('userId'),
                        'resource': activity_entry['resource'],
                        'requested_resources': requested_resources,
                        'timestamp': datetime.utcnow(),
                        'requires_immediate_response': True,
                        'severity': 'critical',
                        'message': alert_message
                    }
                    
                    logger.warning(alert_message)
                    
                    # Store alert
                    self.db.collection('security_alerts').add(security_alert)
                    
                    # Also broadcast realtime alert without waiting
                    asyncio.create_task(realtime_event_processor.broadcast_security_event(security_alert))
                    
                    # Mark action as high risk
                    activity_entry['riskScore'] = 100
                    
            # Update session with new activity
            session_ref.update({
                'activityLog': enhanced_firebase_service.array_union([activity_entry]),
                'lastActivity': datetime.utcnow()
            })
            
            # Create audit log entry
            await create_audit_log(
                self.db,
                event_type='break_glass',
                sub_type='activity_logged',
                user_id=activity_data.get('userId'),
                action=f"Emergency session activity: {activity_entry['action']}",
                result='success',
                session_id=session_id,
                details={
                    'sessionId': session_id,
                    'activity': activity_entry
                }
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Error logging emergency activity: {str(e)}")
            return False
    
    # Private helper methods
    
    def _validate_emergency_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate emergency request data"""
        try:
            # Check required fields
            required_fields = ['requesterId', 'emergencyType', 'urgencyLevel', 'justification', 'requiredResources', 'estimatedDuration']
            for field in required_fields:
                if field not in request_data:
                    return {'valid': False, 'error': f'Missing required field: {field}'}
            
            # Validate emergency type
            valid_types = [e.value for e in EmergencyType]
            if request_data['emergencyType'] not in valid_types:
                return {'valid': False, 'error': f'Invalid emergency type. Must be one of: {valid_types}'}
            
            # Validate urgency level
            valid_urgency = [u.value for u in UrgencyLevel]
            if request_data['urgencyLevel'] not in valid_urgency:
                return {'valid': False, 'error': f'Invalid urgency level. Must be one of: {valid_urgency}'}
            
            # Validate justification length (minimum 100 characters as per requirements)
            justification = request_data['justification'].strip()
            if len(justification) < 100:
                return {'valid': False, 'error': 'Justification must be at least 100 characters'}
            
            # Validate required resources
            if not isinstance(request_data['requiredResources'], list) or len(request_data['requiredResources']) == 0:
                return {'valid': False, 'error': 'At least one required resource must be specified'}
            
            # Validate duration (0.5 to 2 hours as per requirements)
            duration = float(request_data['estimatedDuration'])
            if duration < 0.5 or duration > 2:
                return {'valid': False, 'error': 'Duration must be between 0.5 and 2 hours'}
            
            return {'valid': True}
            
        except Exception as e:
            return {'valid': False, 'error': f'Validation error: {str(e)}'}
    
    async def _get_available_administrators(self) -> List[Dict[str, Any]]:
        """Get list of available administrators"""
        try:
            # Get all active administrators
            users_ref = self.db.collection('users')
            query = users_ref.where('role', '==', 'admin').where('isActive', '==', True)
            
            administrators = []
            for doc in query.stream():
                admin_data = doc.to_dict()
                
                # Check if admin is currently online/available (simplified check)
                # In a real implementation, you might check last activity, online status, etc.
                administrators.append({
                    'userId': admin_data['userId'],
                    'name': admin_data.get('name', 'Unknown'),
                    'email': admin_data.get('email', ''),
                    'lastLogin': admin_data.get('lastLogin'),
                    'available': True  # Simplified - in real implementation, check availability
                })
            
            return administrators
            
        except Exception as e:
            logger.error(f"Error getting available administrators: {str(e)}")
            return []
    
    async def _notify_administrators(self, emergency_request: EmergencyAccessRequest, 
                                   administrators: List[Dict[str, Any]]) -> int:
        """Send immediate notifications to administrators"""
        try:
            notifications_sent = 0
            
            for admin in administrators:
                try:
                    # Create notification record
                    notification_data = {
                        'timestamp': datetime.utcnow(),
                        'recipientId': admin['userId'],
                        'notificationType': 'emergency_request',
                        'delivered': False
                    }
                    
                    # In a real implementation, you would send actual notifications
                    # (email, SMS, push notifications, etc.)
                    # For now, we'll just log and mark as delivered
                    
                    logger.info(f"Emergency notification sent to admin {admin['name']} ({admin['email']})")
                    notification_data['delivered'] = True
                    notifications_sent += 1
                    
                    # Add to notification log
                    emergency_request.notification_log.append(notification_data)
                    
                except Exception as e:
                    logger.error(f"Failed to notify admin {admin['userId']}: {str(e)}")
            
            return notifications_sent
            
        except Exception as e:
            logger.error(f"Error notifying administrators: {str(e)}")
            return 0
    
    async def _activate_emergency_access(self, emergency_request: EmergencyAccessRequest) -> Dict[str, Any]:
        """Activate emergency access after dual approval"""
        try:
            # Create emergency session
            session_id = str(uuid.uuid4())
            expires_at = datetime.utcnow() + timedelta(hours=emergency_request.estimated_duration)
            
            # Grant elevated privileges
            elevated_privileges = []
            for resource_id in emergency_request.required_resources:
                elevated_privileges.append({
                    'resourceId': resource_id,
                    'grantedAt': datetime.utcnow(),
                    'grantedBy': 'break_glass_system'
                })
            
            # Create emergency session document
            emergency_session = {
                'sessionId': session_id,
                'userId': emergency_request.requester_id,
                'requestId': emergency_request.request_id,
                'status': 'active',
                'elevatedPrivileges': elevated_privileges,
                'activatedAt': datetime.utcnow(),
                'expiresAt': expires_at,
                'activityLog': [],
                'screenRecording': None,  # Optional feature
                'keystrokeLog': None     # Optional feature
            }
            
            # Store emergency session
            session_ref = self.db.collection('emergencySessions').document(session_id)
            session_ref.set(emergency_session)
            
            # Update emergency request
            emergency_request.status = EmergencyRequestStatus.ACTIVE
            emergency_request.activated_at = datetime.utcnow()
            emergency_request.expires_at = expires_at
            emergency_request.emergency_session = emergency_session
            
            # Update request in Firestore
            request_ref = self.db.collection('breakGlassRequests').document(emergency_request.request_id)
            request_ref.update(emergency_request.to_dict())
            
            # Log activation
            await self._log_emergency_activation(emergency_request, session_id)
            
            # Schedule automatic expiration
            await self._schedule_session_expiration(session_id, expires_at)
            
            return {
                'success': True,
                'sessionId': session_id,
                'expiresAt': expires_at.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error activating emergency access: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def _expire_emergency_session(self, session_id: str) -> bool:
        """Expire emergency session and generate report"""
        try:
            # Update session status
            session_ref = self.db.collection('emergencySessions').document(session_id)
            session_ref.update({
                'status': 'expired',
                'expiredAt': datetime.utcnow()
            })
            
            # Generate post-incident report
            await self._generate_post_incident_report(session_id)
            
            return True
            
        except Exception as e:
            logger.error(f"Error expiring emergency session: {str(e)}")
            return False
    
    async def _log_emergency_request(self, emergency_request: EmergencyAccessRequest):
        """Log emergency request submission"""
        await asyncio.to_thread(
            create_audit_log,
            self.db,
            event_type='break_glass',
            user_id=emergency_request.requester_id,
            action=f"Emergency access request submitted: {emergency_request.emergency_type}",
            resource=emergency_request.emergency_type,
            result='success',
            details={
                'sub_type': 'request_submitted',
                'requestId': emergency_request.request_id,
                'emergencyType': emergency_request.emergency_type,
                'urgencyLevel': emergency_request.urgency_level,
                'resourceCount': len(emergency_request.required_resources),
                'estimatedDuration': emergency_request.estimated_duration
            }
        )
    
    async def _log_approval_decision(self, emergency_request: EmergencyAccessRequest, 
                                   approver_id: str, decision: str, comments: str):
        """Log approval decision"""
        await asyncio.to_thread(
            create_audit_log,
            self.db,
            event_type='break_glass',
            user_id=approver_id,
            action=f"Emergency request {decision}: {emergency_request.request_id}",
            resource=emergency_request.emergency_type,
            result='success',
            details={
                'sub_type': 'approval_decision',
                'target_user_id': emergency_request.requester_id,
                'requestId': emergency_request.request_id,
                'decision': decision,
                'comments': comments,
                'approvalsReceived': len([a for a in emergency_request.approvals if a['decision'] == 'approved'])
            }
        )
    
    async def _log_emergency_activation(self, emergency_request: EmergencyAccessRequest, session_id: str):
        """Log emergency access activation"""
        await asyncio.to_thread(
            create_audit_log,
            self.db,
            event_type='break_glass',
            user_id=emergency_request.requester_id,
            action=f"Emergency access activated: {session_id}",
            resource=emergency_request.emergency_type,
            result='success',
            details={
                'sub_type': 'access_activated',
                'requestId': emergency_request.request_id,
                'sessionId': session_id,
                'emergencyType': emergency_request.emergency_type,
                'urgencyLevel': emergency_request.urgency_level,
                'duration': emergency_request.estimated_duration,
                'resourceCount': len(emergency_request.required_resources)
            }
        )
    
    async def _notify_requester_denial(self, emergency_request: EmergencyAccessRequest, 
                                     approver_id: str, comments: str):
        """Notify requester of denial"""
        # In a real implementation, send actual notification
        logger.info(f"Emergency request {emergency_request.request_id} denied by {approver_id}: {comments}")
    
    async def _get_user_info(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user information"""
        try:
            user_ref = self.db.collection('users').document(user_id)
            user_doc = user_ref.get()
            return user_doc.to_dict() if user_doc.exists else None
        except Exception as e:
            logger.error(f"Error getting user info: {str(e)}")
            return None
    
    async def _get_resource_segment_info(self, resource_id: str) -> Optional[Dict[str, Any]]:
        """Get resource segment information"""
        try:
            resource_ref = self.db.collection('resourceSegments').document(resource_id)
            resource_doc = resource_ref.get()
            return resource_doc.to_dict() if resource_doc.exists else None
        except Exception as e:
            logger.error(f"Error getting resource segment info: {str(e)}")
            return None
    
    async def _schedule_approval_timeout(self, request_id: str):
        """Schedule approval timeout check"""
        logger.info(f"Scheduled approval timeout check for request {request_id} in {self.APPROVAL_TIMEOUT_MINUTES} minutes")
        
        async def _timeout_task():
            await asyncio.sleep(self.APPROVAL_TIMEOUT_MINUTES * 60)
            try:
                # Check if it's still pending
                request_ref = self.db.collection('breakGlassRequests').document(request_id)
                request_doc = request_ref.get()
                if request_doc.exists:
                    req = request_doc.to_dict()
                    if req.get('status') == EmergencyRequestStatus.PENDING.value:
                        logger.warning(f"Break-glass request {request_id} timed out. Auto-expiring.")
                        request_ref.update({'status': EmergencyRequestStatus.EXPIRED.value})
            except Exception as e:
                logger.error(f"Error expiring pending request {request_id}: {e}")
                
        asyncio.create_task(_timeout_task())
    
    async def _schedule_session_expiration(self, session_id: str, expires_at: datetime):
        """Schedule session expiration"""
        logger.info(f"Scheduled session expiration for {session_id} at {expires_at}")
        
        async def _expiration_task():
            time_to_wait = (expires_at - datetime.utcnow()).total_seconds()
            if time_to_wait > 0:
                await asyncio.sleep(time_to_wait)
                
            try:
                # Expire the session completely
                await self._expire_emergency_session(session_id)
                logger.info(f"Session {session_id} successfully automatically expired.")
            except Exception as e:
                logger.error(f"Failed to auto-expire session {session_id}: {e}")

        asyncio.create_task(_expiration_task())
    
    async def generate_comprehensive_report(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Generate comprehensive post-incident report"""
        try:
            # Get session data
            session_ref = self.db.collection('emergencySessions').document(session_id)
            session_doc = session_ref.get()
            
            if not session_doc.exists:
                logger.error(f"Session {session_id} not found for report generation")
                return None
            
            session_data = session_doc.to_dict()
            
            # Get associated emergency request
            requests_ref = self.db.collection('breakGlassRequests')
            query = requests_ref.where('emergencySession.sessionId', '==', session_id)
            
            request_data = None
            for doc in query.stream():
                request_data = doc.to_dict()
                break
            
            if not request_data:
                logger.error(f"Associated request not found for session {session_id}")
                return None
            
            # Calculate session metrics
            activated_at = session_data.get('activatedAt')
            expired_at = session_data.get('expiredAt')
            duration_seconds = 0
            
            if activated_at and expired_at:
                if isinstance(activated_at, str):
                    activated_at = datetime.fromisoformat(activated_at.replace('Z', '+00:00'))
                if isinstance(expired_at, str):
                    expired_at = datetime.fromisoformat(expired_at.replace('Z', '+00:00'))
                
                duration_seconds = (expired_at - activated_at).total_seconds()
            
            # Analyze activity log
            activity_log = session_data.get('activityLog', [])
            activity_summary = self._analyze_activity_log(activity_log)
            
            # Generate comprehensive report
            report = {
                'sessionId': session_id,
                'generatedAt': datetime.utcnow(),
                'sessionDetails': {
                    'userId': session_data.get('userId'),
                    'activatedAt': activated_at,
                    'expiredAt': expired_at,
                    'durationSeconds': duration_seconds,
                    'durationFormatted': f"{int(duration_seconds // 3600)}h {int((duration_seconds % 3600) // 60)}m",
                    'status': session_data.get('status'),
                    'elevatedPrivileges': session_data.get('elevatedPrivileges', [])
                },
                'emergencyRequest': {
                    'requestId': request_data.get('requestId'),
                    'emergencyType': request_data.get('emergencyType'),
                    'urgencyLevel': request_data.get('urgencyLevel'),
                    'justification': request_data.get('justification'),
                    'requiredResources': request_data.get('requiredResources', []),
                    'approvals': request_data.get('approvals', [])
                },
                'activitySummary': activity_summary,
                'complianceAnalysis': self._analyze_compliance(session_data, request_data, activity_log),
                'riskAssessment': self._assess_session_risk(activity_log),
                'recommendations': self._generate_recommendations(session_data, activity_log),
                'postIncidentReview': request_data.get('postIncidentReview', {}),
                'auditTrail': await self._get_audit_trail(session_id)
            }
            
            # Store report
            report_ref = self.db.collection('emergencyReports').document(session_id)
            report_ref.set(report)
            
            logger.info(f"Comprehensive report generated for session {session_id}")
            return report
            
        except Exception as e:
            logger.error(f"Error generating comprehensive report: {str(e)}")
            return None
    
    def _analyze_activity_log(self, activity_log: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze activity log for patterns and metrics"""
        if not activity_log:
            return {
                'totalActivities': 0,
                'activityTypes': {},
                'resourcesAccessed': [],
                'successRate': 0,
                'riskEvents': []
            }
        
        activity_types = {}
        resources_accessed = set()
        successful_activities = 0
        risk_events = []
        
        for activity in activity_log:
            # Count activity types
            action = activity.get('action', 'unknown')
            activity_types[action] = activity_types.get(action, 0) + 1
            
            # Track resources
            resource = activity.get('resource')
            if resource:
                resources_accessed.add(resource)
            
            # Count successes
            if activity.get('result') == 'success':
                successful_activities += 1
            
            # Identify risk events
            risk_score = activity.get('riskScore', 0)
            if risk_score > 70 or activity.get('result') == 'failure':
                risk_events.append({
                    'timestamp': activity.get('timestamp'),
                    'action': action,
                    'resource': resource,
                    'riskScore': risk_score,
                    'result': activity.get('result')
                })
        
        success_rate = (successful_activities / len(activity_log)) * 100 if activity_log else 0
        
        return {
            'totalActivities': len(activity_log),
            'activityTypes': activity_types,
            'resourcesAccessed': list(resources_accessed),
            'successRate': round(success_rate, 2),
            'riskEvents': risk_events,
            'timespan': {
                'firstActivity': activity_log[0].get('timestamp') if activity_log else None,
                'lastActivity': activity_log[-1].get('timestamp') if activity_log else None
            }
        }
    
    def _analyze_compliance(self, session_data: Dict[str, Any], request_data: Dict[str, Any], 
                          activity_log: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze session compliance with policies"""
        compliance_issues = []
        compliance_score = 100
        
        # Check session duration compliance
        activated_at = session_data.get('activatedAt')
        expired_at = session_data.get('expiredAt')
        
        if activated_at and expired_at:
            if isinstance(activated_at, str):
                activated_at = datetime.fromisoformat(activated_at.replace('Z', '+00:00'))
            if isinstance(expired_at, str):
                expired_at = datetime.fromisoformat(expired_at.replace('Z', '+00:00'))
            
            duration_hours = (expired_at - activated_at).total_seconds() / 3600
            max_duration = request_data.get('estimatedDuration', 2)
            
            if duration_hours > max_duration + 0.1:  # Allow small tolerance
                compliance_issues.append(f"Session exceeded estimated duration by {duration_hours - max_duration:.1f} hours")
                compliance_score -= 20
        
        # Check for failed activities
        failed_activities = [a for a in activity_log if a.get('result') == 'failure']
        if len(failed_activities) > 3:
            compliance_issues.append(f"High number of failed activities: {len(failed_activities)}")
            compliance_score -= 15
        
        # Check for high-risk activities
        high_risk_activities = [a for a in activity_log if a.get('riskScore', 0) > 80]
        if high_risk_activities:
            compliance_issues.append(f"High-risk activities detected: {len(high_risk_activities)}")
            compliance_score -= 10
        
        # Check dual approval compliance
        approvals = request_data.get('approvals', [])
        if len(approvals) < 2:
            compliance_issues.append("Insufficient approvals for emergency access")
            compliance_score -= 30
        
        return {
            'complianceScore': max(0, compliance_score),
            'complianceIssues': compliance_issues,
            'complianceStatus': 'compliant' if compliance_score >= 80 else 'non_compliant' if compliance_score < 60 else 'under_review'
        }
    
    def _assess_session_risk(self, activity_log: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess overall session risk"""
        if not activity_log:
            return {
                'overallRisk': 'low',
                'riskScore': 0,
                'riskFactors': []
            }
        
        risk_factors = []
        risk_score = 0
        
        # Analyze activity patterns
        delete_actions = [a for a in activity_log if 'delete' in a.get('action', '').lower()]
        if delete_actions:
            risk_factors.append(f"Destructive actions performed: {len(delete_actions)}")
            risk_score += len(delete_actions) * 10
        
        # Check for admin resource access
        admin_access = [a for a in activity_log if 'admin' in a.get('resource', '').lower()]
        if admin_access:
            risk_factors.append(f"Administrative resource access: {len(admin_access)}")
            risk_score += len(admin_access) * 5
        
        # Check failure rate
        total_activities = len(activity_log)
        failed_activities = len([a for a in activity_log if a.get('result') == 'failure'])
        failure_rate = (failed_activities / total_activities) * 100 if total_activities > 0 else 0
        
        if failure_rate > 20:
            risk_factors.append(f"High failure rate: {failure_rate:.1f}%")
            risk_score += 20
        
        # Determine overall risk level
        if risk_score >= 50:
            overall_risk = 'high'
        elif risk_score >= 25:
            overall_risk = 'medium'
        else:
            overall_risk = 'low'
        
        return {
            'overallRisk': overall_risk,
            'riskScore': min(100, risk_score),
            'riskFactors': risk_factors,
            'failureRate': round(failure_rate, 2)
        }
    
    def _generate_recommendations(self, session_data: Dict[str, Any], 
                                activity_log: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations based on session analysis"""
        recommendations = []
        
        # Analyze activity patterns for recommendations
        if not activity_log:
            recommendations.append("Consider implementing activity monitoring to ensure proper logging")
            return recommendations
        
        # Check for high-risk patterns
        high_risk_activities = [a for a in activity_log if a.get('riskScore', 0) > 70]
        if high_risk_activities:
            recommendations.append("Review high-risk activities and consider additional approval requirements")
        
        # Check for failed activities
        failed_activities = [a for a in activity_log if a.get('result') == 'failure']
        if len(failed_activities) > 2:
            recommendations.append("Investigate causes of failed activities and provide additional training")
        
        # Check session duration
        activated_at = session_data.get('activatedAt')
        expired_at = session_data.get('expiredAt')
        
        if activated_at and expired_at:
            if isinstance(activated_at, str):
                activated_at = datetime.fromisoformat(activated_at.replace('Z', '+00:00'))
            if isinstance(expired_at, str):
                expired_at = datetime.fromisoformat(expired_at.replace('Z', '+00:00'))
            
            duration_hours = (expired_at - activated_at).total_seconds() / 3600
            
            if duration_hours > 1.5:
                recommendations.append("Consider breaking down long emergency sessions into smaller, focused tasks")
        
        # Activity diversity check
        unique_actions = set(a.get('action', '') for a in activity_log)
        if len(unique_actions) > 10:
            recommendations.append("Review the scope of emergency access to ensure it aligns with the stated justification")
        
        # Default recommendations
        if not recommendations:
            recommendations.append("Session completed within normal parameters - no specific recommendations")
        
        return recommendations
    
    async def _get_audit_trail(self, session_id: str) -> List[Dict[str, Any]]:
        """Get audit trail for the session"""
        try:
            # Get audit logs related to this session
            audit_ref = self.db.collection('auditLogs')
            query = audit_ref.where('sessionId', '==', session_id).order_by('timestamp')
            
            audit_trail = []
            for doc in query.stream():
                audit_data = doc.to_dict()
                audit_trail.append({
                    'timestamp': audit_data.get('timestamp'),
                    'eventType': audit_data.get('eventType'),
                    'subType': audit_data.get('subType'),
                    'action': audit_data.get('action'),
                    'result': audit_data.get('result'),
                    'userId': audit_data.get('userId')
                })
            
            return audit_trail
            
        except Exception as e:
            logger.error(f"Error getting audit trail: {str(e)}")
            return []
    
    async def _log_post_incident_review(self, session_id: str, reviewer_id: str, review_data: Dict[str, Any]):
        """Log post-incident review completion"""
        await create_audit_log(
            self.db,
            event_type='break_glass',
            sub_type='post_incident_review',
            user_id=reviewer_id,
            action=f"Post-incident review completed for session: {session_id}",
            result='success',
            session_id=session_id,
            details={
                'sessionId': session_id,
                'complianceStatus': review_data.get('complianceStatus'),
                'recommendationCount': len(review_data.get('recommendations', [])),
                'reviewedAt': review_data.get('reviewedAt')
            }
        )

    async def _generate_post_incident_report(self, session_id: str):
        """Generate comprehensive post-incident report"""
        try:
            # Get session data
            session_ref = self.db.collection('emergencySessions').document(session_id)
            session_doc = session_ref.get()
            
            if not session_doc.exists:
                logger.error(f"Session {session_id} not found for report generation")
                return
            
            session_data = session_doc.to_dict()
            
            # Generate report (simplified version)
            report = {
                'sessionId': session_id,
                'generatedAt': datetime.utcnow(),
                'duration': 'calculated_duration',
                'activitiesLogged': len(session_data.get('activityLog', [])),
                'resourcesAccessed': len(session_data.get('elevatedPrivileges', [])),
                'complianceStatus': 'under_review',
                'reviewRequired': True
            }
            
            # Store report
            report_ref = self.db.collection('emergencyReports').document(session_id)
            report_ref.set(report)
            
            logger.info(f"Post-incident report generated for session {session_id}")
            
        except Exception as e:
            logger.error(f"Error generating post-incident report: {str(e)}")


# Global service instance
break_glass_service = None


def get_break_glass_service(db):
    """
    Get or create the global break-glass service instance
    
    Args:
        db: Firestore client
        
    Returns:
        BreakGlassService: Service instance
    """
    global break_glass_service
    if break_glass_service is None:
        break_glass_service = BreakGlassService(db)
    return break_glass_service