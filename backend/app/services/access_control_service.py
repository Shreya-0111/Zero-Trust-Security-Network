"""
Access Control Service
Handles role-based access control enforcement and dual approval workflows
"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum

from ..models.resource_segment import get_resource_segment_by_id
from ..models.user import get_user_by_id
from ..models.audit_log import create_audit_log
from ..firebase_config import get_firestore_client

logger = logging.getLogger(__name__)


class AccessRequestStatus(Enum):
    """Access request status enumeration"""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    REVOKED = "revoked"


class AccessRequest:
    """Access request model for dual approval workflow"""
    
    def __init__(self, request_id: str, user_id: str, segment_id: str, 
                 justification: str, duration_hours: int, requested_by: str):
        self.request_id = request_id
        self.user_id = user_id
        self.segment_id = segment_id
        self.justification = justification
        self.duration_hours = duration_hours
        self.requested_by = requested_by
        self.requested_at = datetime.utcnow()
        self.status = AccessRequestStatus.PENDING
        self.approvals = []
        self.denials = []
        self.approved_at = None
        self.expires_at = None
        self.granted_access = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Firestore storage"""
        return {
            'requestId': self.request_id,
            'userId': self.user_id,
            'segmentId': self.segment_id,
            'justification': self.justification,
            'durationHours': self.duration_hours,
            'requestedBy': self.requested_by,
            'requestedAt': self.requested_at,
            'status': self.status.value,
            'approvals': self.approvals,
            'denials': self.denials,
            'approvedAt': self.approved_at,
            'expiresAt': self.expires_at,
            'grantedAccess': self.granted_access
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AccessRequest':
        """Create from dictionary"""
        request = cls(
            data['requestId'],
            data['userId'],
            data['segmentId'],
            data['justification'],
            data['durationHours'],
            data['requestedBy']
        )
        request.requested_at = data.get('requestedAt', datetime.utcnow())
        request.status = AccessRequestStatus(data.get('status', 'pending'))
        request.approvals = data.get('approvals', [])
        request.denials = data.get('denials', [])
        request.approved_at = data.get('approvedAt')
        request.expires_at = data.get('expiresAt')
        request.granted_access = data.get('grantedAccess')
        return request


class AccessControlService:
    """Service for role-based access control and dual approval workflows"""
    
    def __init__(self, db):
        """
        Initialize Access Control Service
        
        Args:
            db: Firestore client
        """
        self.db = db
    
    async def validate_access_request(self, user_id: str, segment_id: str, 
                                    action: str = 'access') -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validate user access request against Resource_Segment permissions
        
        Args:
            user_id (str): User ID requesting access
            segment_id (str): Resource segment ID
            action (str): Action being performed
            
        Returns:
            Tuple[bool, str, Dict]: (is_valid, reason, validation_details)
        """
        try:
            # Get user and segment
            user = get_user_by_id(self.db, user_id)
            segment = get_resource_segment_by_id(self.db, segment_id)
            
            if not user:
                return False, "User not found", {}
            
            if not segment:
                return False, "Resource segment not found", {}
            
            if not segment.is_active:
                return False, "Resource segment is not active", {}
            
            # Get user's security clearance level
            security_clearance = self._get_user_security_clearance(user)
            
            validation_details = {
                'user_role': user.role,
                'security_clearance': security_clearance,
                'segment_security_level': segment.security_level,
                'segment_name': segment.name,
                'requires_jit': segment.requires_jit,
                'requires_dual_approval': segment.requires_dual_approval,
                'allowed_roles': segment.allowed_roles
            }
            
            # Check role permission
            if user.role not in segment.allowed_roles:
                return False, f"Role '{user.role}' not allowed for this segment", validation_details
            
            # Check security clearance level
            if security_clearance < segment.security_level:
                return False, f"Security clearance level {security_clearance} insufficient for level {segment.security_level} segment", validation_details
            
            # Check time restrictions
            if not self._check_time_restrictions(segment.access_restrictions.get('timeWindows', [])):
                return False, "Access not allowed during current time window", validation_details
            
            # Check device requirements
            device_requirements = segment.access_restrictions.get('deviceRequirements', {})
            if device_requirements.get('requiresRegisteredDevice', False):
                # This would need integration with device fingerprint service
                # For now, we'll assume device is registered if user has logged in
                pass
            
            return True, "Access validation passed", validation_details
            
        except Exception as e:
            logger.error(f"Error validating access request: {str(e)}")
            return False, f"Validation error: {str(e)}", {}
    
    async def enforce_security_clearance_requirements(self, user_id: str, 
                                                    segment_id: str) -> Tuple[bool, str]:
        """
        Enforce security clearance level requirements
        
        Args:
            user_id (str): User ID
            segment_id (str): Resource segment ID
            
        Returns:
            Tuple[bool, str]: (meets_requirements, reason)
        """
        try:
            user = get_user_by_id(self.db, user_id)
            segment = get_resource_segment_by_id(self.db, segment_id)
            
            if not user or not segment:
                return False, "User or segment not found"
            
            user_clearance = self._get_user_security_clearance(user)
            required_clearance = segment.security_level
            
            if user_clearance >= required_clearance:
                return True, f"User clearance level {user_clearance} meets requirement {required_clearance}"
            else:
                return False, f"User clearance level {user_clearance} insufficient for requirement {required_clearance}"
                
        except Exception as e:
            logger.error(f"Error enforcing security clearance: {str(e)}")
            return False, f"Error checking clearance: {str(e)}"
    
    async def create_dual_approval_request(self, user_id: str, segment_id: str,
                                         justification: str, duration_hours: int,
                                         requested_by: str) -> AccessRequest:
        """
        Create a dual approval request for high-security segments (levels 4-5)
        
        Args:
            user_id (str): User ID requesting access
            segment_id (str): Resource segment ID
            justification (str): Access justification
            duration_hours (int): Requested duration in hours
            requested_by (str): ID of user making the request
            
        Returns:
            AccessRequest: Created access request
            
        Raises:
            Exception: If creation fails or validation errors
        """
        try:
            # Validate the request
            is_valid, reason, details = await self.validate_access_request(user_id, segment_id)
            if not is_valid:
                raise Exception(f"Access request validation failed: {reason}")
            
            # Check if dual approval is required
            segment = get_resource_segment_by_id(self.db, segment_id)
            if not segment.requires_dual_approval:
                raise Exception("Dual approval not required for this segment")
            
            # Generate request ID
            import uuid
            request_id = str(uuid.uuid4())
            
            # Create access request
            access_request = AccessRequest(
                request_id, user_id, segment_id, justification, 
                duration_hours, requested_by
            )
            
            # Store in Firestore
            request_ref = self.db.collection('accessRequests').document(request_id)
            request_ref.set(access_request.to_dict())
            
            # Log the request creation
            await create_audit_log(
                self.db,
                event_type='access_request',
                sub_type='dual_approval_request_created',
                user_id=requested_by,
                target_user_id=user_id,
                resource_segment_id=segment_id,
                action=f'Created dual approval request for {segment.name}',
                result='success',
                details={
                    'request_id': request_id,
                    'justification': justification,
                    'duration_hours': duration_hours,
                    'segment_name': segment.name,
                    'security_level': segment.security_level
                }
            )
            
            # Notify administrators
            await self._notify_administrators_for_approval(access_request, segment)
            
            logger.info(f"Dual approval request created: {request_id} for segment {segment.name}")
            return access_request
            
        except Exception as e:
            logger.error(f"Failed to create dual approval request: {str(e)}")
            raise e
    
    async def process_approval_decision(self, request_id: str, approver_id: str,
                                      decision: str, comments: str = "") -> Dict[str, Any]:
        """
        Process an approval decision for a dual approval request
        
        Args:
            request_id (str): Access request ID
            approver_id (str): ID of approving administrator
            decision (str): 'approve' or 'deny'
            comments (str): Optional comments
            
        Returns:
            Dict: Processing result with status and next steps
            
        Raises:
            Exception: If processing fails
        """
        try:
            # Get the access request
            request_ref = self.db.collection('accessRequests').document(request_id)
            request_doc = request_ref.get()
            
            if not request_doc.exists:
                raise Exception("Access request not found")
            
            access_request = AccessRequest.from_dict(request_doc.to_dict())
            
            if access_request.status != AccessRequestStatus.PENDING:
                raise Exception(f"Request is not pending (status: {access_request.status.value})")
            
            # Verify approver is an admin
            approver = get_user_by_id(self.db, approver_id)
            if not approver or approver.role != 'admin':
                raise Exception("Only administrators can approve access requests")
            
            # Check if approver has already made a decision
            existing_approval = next((a for a in access_request.approvals if a['approver_id'] == approver_id), None)
            existing_denial = next((d for d in access_request.denials if d['approver_id'] == approver_id), None)
            
            if existing_approval or existing_denial:
                raise Exception("Approver has already made a decision on this request")
            
            approval_entry = {
                'approver_id': approver_id,
                'approver_name': approver.name,
                'decision': decision,
                'timestamp': datetime.utcnow(),
                'comments': comments
            }
            
            result = {'request_id': request_id, 'decision': decision}
            
            if decision == 'approve':
                access_request.approvals.append(approval_entry)
                
                # Check if we have enough approvals (need 2 different admins)
                if len(access_request.approvals) >= 2:
                    # Grant access
                    access_request.status = AccessRequestStatus.APPROVED
                    access_request.approved_at = datetime.utcnow()
                    access_request.expires_at = datetime.utcnow() + timedelta(hours=access_request.duration_hours)
                    
                    # Create access grant
                    access_grant = await self._create_access_grant(access_request)
                    access_request.granted_access = access_grant
                    
                    result['status'] = 'approved'
                    result['access_granted'] = True
                    result['expires_at'] = access_request.expires_at.isoformat()
                    
                    logger.info(f"Access request {request_id} approved with dual approval")
                else:
                    result['status'] = 'pending_second_approval'
                    result['approvals_needed'] = 2 - len(access_request.approvals)
                    
            elif decision == 'deny':
                access_request.denials.append(approval_entry)
                access_request.status = AccessRequestStatus.DENIED
                
                result['status'] = 'denied'
                result['access_granted'] = False
                
                logger.info(f"Access request {request_id} denied by {approver.name}")
            
            # Update the request in Firestore
            request_ref.update(access_request.to_dict())
            
            # Log the decision
            await create_audit_log(
                self.db,
                event_type='access_request',
                sub_type=f'dual_approval_{decision}',
                user_id=approver_id,
                target_user_id=access_request.user_id,
                resource_segment_id=access_request.segment_id,
                action=f'Access request {decision}ed',
                result='success',
                details={
                    'request_id': request_id,
                    'decision': decision,
                    'comments': comments,
                    'total_approvals': len(access_request.approvals),
                    'total_denials': len(access_request.denials)
                }
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to process approval decision: {str(e)}")
            raise e
    
    async def get_pending_approval_requests(self, admin_id: str) -> List[Dict[str, Any]]:
        """
        Get pending approval requests for an administrator
        
        Args:
            admin_id (str): Administrator ID
            
        Returns:
            List[Dict]: List of pending requests
        """
        try:
            # Verify user is admin
            admin = get_user_by_id(self.db, admin_id)
            if not admin or admin.role != 'admin':
                raise Exception("Only administrators can view approval requests")
            
            # Get pending requests
            requests_ref = self.db.collection('accessRequests')
            query = requests_ref.where('status', '==', 'pending')
            
            pending_requests = []
            for doc in query.stream():
                request_data = doc.to_dict()
                
                # Check if this admin has already made a decision
                has_decided = any(
                    a['approver_id'] == admin_id for a in request_data.get('approvals', [])
                ) or any(
                    d['approver_id'] == admin_id for d in request_data.get('denials', [])
                )
                
                if not has_decided:
                    # Enrich with user and segment information
                    user = get_user_by_id(self.db, request_data['userId'])
                    segment = get_resource_segment_by_id(self.db, request_data['segmentId'])
                    
                    request_data['user_name'] = user.name if user else 'Unknown'
                    request_data['user_role'] = user.role if user else 'Unknown'
                    request_data['segment_name'] = segment.name if segment else 'Unknown'
                    request_data['security_level'] = segment.security_level if segment else 0
                    
                    pending_requests.append(request_data)
            
            return pending_requests
            
        except Exception as e:
            logger.error(f"Failed to get pending approval requests: {str(e)}")
            return []
    
    async def revoke_access(self, user_id: str, segment_id: str, revoked_by: str,
                          reason: str = "Manual revocation") -> bool:
        """
        Revoke user access to a resource segment
        
        Args:
            user_id (str): User ID
            segment_id (str): Resource segment ID
            revoked_by (str): ID of user revoking access
            reason (str): Reason for revocation
            
        Returns:
            bool: True if successful
        """
        try:
            # Find active access grants for this user/segment
            grants_ref = self.db.collection('accessGrants')
            query = grants_ref.where('userId', '==', user_id)\
                             .where('segmentId', '==', segment_id)\
                             .where('status', '==', 'active')
            
            revoked_count = 0
            for doc in query.stream():
                grant_data = doc.to_dict()
                
                # Update grant status
                doc.reference.update({
                    'status': 'revoked',
                    'revokedAt': datetime.utcnow(),
                    'revokedBy': revoked_by,
                    'revocationReason': reason
                })
                
                revoked_count += 1
            
            # Log the revocation
            segment = get_resource_segment_by_id(self.db, segment_id)
            await create_audit_log(
                self.db,
                event_type='access_request',
                sub_type='access_revoked',
                user_id=revoked_by,
                target_user_id=user_id,
                resource_segment_id=segment_id,
                action=f'Revoked access to {segment.name if segment else segment_id}',
                result='success',
                details={
                    'reason': reason,
                    'grants_revoked': revoked_count
                }
            )
            
            logger.info(f"Access revoked for user {user_id} to segment {segment_id} by {revoked_by}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to revoke access: {str(e)}")
            return False
    
    def _get_user_security_clearance(self, user) -> int:
        """
        Get user's security clearance level based on role
        
        Args:
            user: User object
            
        Returns:
            int: Security clearance level (1-5)
        """
        role_clearance = {
            'student': 1,
            'visitor': 1,
            'faculty': 3,
            'admin': 5
        }
        
        return role_clearance.get(user.role, 1)
    
    def _check_time_restrictions(self, time_windows: List[Dict[str, Any]]) -> bool:
        """
        Check if current time falls within allowed time windows
        
        Args:
            time_windows (List[Dict]): List of time window restrictions
            
        Returns:
            bool: True if access is allowed at current time
        """
        if not time_windows:
            return True  # No restrictions means always allowed
        
        now = datetime.utcnow()
        current_hour = now.hour
        current_day = now.strftime('%A').lower()
        
        for window in time_windows:
            start_hour = window.get('startHour', 0)
            end_hour = window.get('endHour', 23)
            allowed_days = [day.lower() for day in window.get('allowedDays', [])]
            
            # Check if current day is allowed
            if current_day in allowed_days:
                # Check if current hour is within the window
                if start_hour <= current_hour <= end_hour:
                    return True
        
        return False
    
    async def _create_access_grant(self, access_request: AccessRequest) -> Dict[str, Any]:
        """
        Create an access grant from an approved request
        
        Args:
            access_request: Approved access request
            
        Returns:
            Dict: Access grant information
        """
        import uuid
        grant_id = str(uuid.uuid4())
        
        grant_data = {
            'grantId': grant_id,
            'requestId': access_request.request_id,
            'userId': access_request.user_id,
            'segmentId': access_request.segment_id,
            'grantedAt': datetime.utcnow(),
            'expiresAt': access_request.expires_at,
            'status': 'active',
            'grantedBy': 'dual_approval_system',
            'approvals': access_request.approvals
        }
        
        # Store the grant
        grant_ref = self.db.collection('accessGrants').document(grant_id)
        grant_ref.set(grant_data)
        
        return grant_data
    
    async def _notify_administrators_for_approval(self, access_request: AccessRequest, 
                                                segment) -> None:
        """
        Notify administrators about a new approval request
        
        Args:
            access_request: Access request needing approval
            segment: Resource segment being requested
        """
        try:
            # Get all admin users
            users_ref = self.db.collection('users')
            admin_query = users_ref.where('role', '==', 'admin').where('isActive', '==', True)
            
            from ..models.notification import create_notification
            
            for admin_doc in admin_query.stream():
                admin_data = admin_doc.to_dict()
                
                # Create notification for each admin
                await create_notification(
                    self.db,
                    user_id=admin_data['userId'],
                    title='Dual Approval Required',
                    message=f'Access request for {segment.name} (Level {segment.security_level}) requires your approval',
                    notification_type='approval_request',
                    priority='high',
                    data={
                        'request_id': access_request.request_id,
                        'segment_id': access_request.segment_id,
                        'segment_name': segment.name,
                        'security_level': segment.security_level,
                        'requested_by': access_request.requested_by
                    }
                )
            
        except Exception as e:
            logger.error(f"Failed to notify administrators: {str(e)}")


# Global service instance
access_control_service = None


def get_access_control_service(db):
    """
    Get or create the global access control service instance
    
    Args:
        db: Firestore client
        
    Returns:
        AccessControlService: Service instance
    """
    global access_control_service
    if access_control_service is None:
        access_control_service = AccessControlService(db)
    return access_control_service