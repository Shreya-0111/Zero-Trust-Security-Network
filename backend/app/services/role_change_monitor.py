"""
Role Change Monitor Service
Monitors user role modifications and automatically revokes Resource_Segment access when appropriate
"""

import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from ..models.user import get_user_by_id
from ..models.resource_segment import get_resource_segment_by_id
from ..models.audit_log import create_audit_log
from ..models.notification import create_notification
from ..services.access_control_service import get_access_control_service

logger = logging.getLogger(__name__)


class RoleChangeMonitor:
    """Service for monitoring role changes and automatic access revocation"""
    
    def __init__(self, db):
        """
        Initialize Role Change Monitor
        
        Args:
            db: Firestore client
        """
        self.db = db
    
    async def monitor_user_role_change(self, user_id: str, old_role: str, new_role: str, 
                                     changed_by: str, reason: str = "") -> Dict[str, Any]:
        """
        Monitor user role modifications and revoke access when appropriate
        
        Args:
            user_id (str): User ID whose role changed
            old_role (str): Previous role
            new_role (str): New role
            changed_by (str): ID of user who made the change
            reason (str): Reason for role change
            
        Returns:
            Dict: Summary of revocation actions taken
        """
        try:
            user = get_user_by_id(self.db, user_id)
            if not user:
                raise Exception("User not found")
            
            logger.info(f"Monitoring role change for user {user_id}: {old_role} -> {new_role}")
            
            # Get user's current active access grants
            active_grants = await self._get_user_active_grants(user_id)
            
            # Determine which grants need to be revoked
            grants_to_revoke = []
            for grant in active_grants:
                should_revoke, revocation_reason = await self._should_revoke_access(
                    grant, old_role, new_role
                )
                
                if should_revoke:
                    grant['revocation_reason'] = revocation_reason
                    grants_to_revoke.append(grant)
            
            # Revoke inappropriate access grants
            revocation_results = []
            for grant in grants_to_revoke:
                try:
                    success = await self._revoke_access_grant(
                        grant, user_id, changed_by, grant['revocation_reason']
                    )
                    
                    revocation_results.append({
                        'grant_id': grant['grantId'],
                        'segment_id': grant['segmentId'],
                        'segment_name': grant.get('segment_name', 'Unknown'),
                        'success': success,
                        'reason': grant['revocation_reason']
                    })
                    
                except Exception as e:
                    logger.error(f"Failed to revoke grant {grant['grantId']}: {str(e)}")
                    revocation_results.append({
                        'grant_id': grant['grantId'],
                        'segment_id': grant['segmentId'],
                        'segment_name': grant.get('segment_name', 'Unknown'),
                        'success': False,
                        'error': str(e)
                    })
            
            # Log the role change monitoring
            await create_audit_log(
                self.db,
                event_type='role_change',
                sub_type='access_revocation_check',
                user_id=changed_by,
                target_user_id=user_id,
                action=f'Role change monitoring: {old_role} -> {new_role}',
                result='success',
                details={
                    'old_role': old_role,
                    'new_role': new_role,
                    'reason': reason,
                    'total_grants_checked': len(active_grants),
                    'grants_revoked': len([r for r in revocation_results if r['success']]),
                    'revocation_results': revocation_results
                }
            )
            
            # Send notifications if access was revoked
            if revocation_results:
                await self._send_revocation_notifications(
                    user_id, user.name, revocation_results, old_role, new_role
                )
            
            summary = {
                'user_id': user_id,
                'user_name': user.name,
                'role_change': f'{old_role} -> {new_role}',
                'grants_checked': len(active_grants),
                'grants_revoked': len([r for r in revocation_results if r['success']]),
                'revocation_results': revocation_results,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            logger.info(f"Role change monitoring completed for {user_id}: {len(revocation_results)} grants processed")
            return summary
            
        except Exception as e:
            logger.error(f"Failed to monitor role change for user {user_id}: {str(e)}")
            
            # Log the failure
            await create_audit_log(
                self.db,
                event_type='role_change',
                sub_type='monitoring_failed',
                user_id=changed_by,
                target_user_id=user_id,
                action=f'Failed to monitor role change: {old_role} -> {new_role}',
                result='failure',
                details={'error': str(e)}
            )
            
            raise e
    
    async def monitor_account_status_change(self, user_id: str, old_status: bool, 
                                          new_status: bool, changed_by: str, 
                                          reason: str = "") -> Dict[str, Any]:
        """
        Monitor user account status changes and revoke access when deactivated
        
        Args:
            user_id (str): User ID whose status changed
            old_status (bool): Previous active status
            new_status (bool): New active status
            changed_by (str): ID of user who made the change
            reason (str): Reason for status change
            
        Returns:
            Dict: Summary of revocation actions taken
        """
        try:
            user = get_user_by_id(self.db, user_id)
            if not user:
                raise Exception("User not found")
            
            logger.info(f"Monitoring status change for user {user_id}: {old_status} -> {new_status}")
            
            # Only process if account is being deactivated
            if old_status and not new_status:
                # Get all active access grants
                active_grants = await self._get_user_active_grants(user_id)
                
                # Revoke all access grants for deactivated account
                revocation_results = []
                for grant in active_grants:
                    try:
                        success = await self._revoke_access_grant(
                            grant, user_id, changed_by, "Account deactivated"
                        )
                        
                        revocation_results.append({
                            'grant_id': grant['grantId'],
                            'segment_id': grant['segmentId'],
                            'segment_name': grant.get('segment_name', 'Unknown'),
                            'success': success,
                            'reason': 'Account deactivated'
                        })
                        
                    except Exception as e:
                        logger.error(f"Failed to revoke grant {grant['grantId']}: {str(e)}")
                        revocation_results.append({
                            'grant_id': grant['grantId'],
                            'segment_id': grant['segmentId'],
                            'segment_name': grant.get('segment_name', 'Unknown'),
                            'success': False,
                            'error': str(e)
                        })
                
                # Log the status change monitoring
                await create_audit_log(
                    self.db,
                    event_type='account_status_change',
                    sub_type='access_revocation_on_deactivation',
                    user_id=changed_by,
                    target_user_id=user_id,
                    action=f'Account deactivated - revoking all access',
                    result='success',
                    details={
                        'old_status': old_status,
                        'new_status': new_status,
                        'reason': reason,
                        'grants_revoked': len([r for r in revocation_results if r['success']]),
                        'revocation_results': revocation_results
                    }
                )
                
                # Send notifications
                if revocation_results:
                    await self._send_deactivation_notifications(
                        user_id, user.name, revocation_results
                    )
                
                summary = {
                    'user_id': user_id,
                    'user_name': user.name,
                    'status_change': f'{old_status} -> {new_status}',
                    'grants_revoked': len([r for r in revocation_results if r['success']]),
                    'revocation_results': revocation_results,
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                logger.info(f"Account deactivation processing completed for {user_id}: {len(revocation_results)} grants revoked")
                return summary
            
            else:
                # No action needed for activation or no change
                return {
                    'user_id': user_id,
                    'user_name': user.name,
                    'status_change': f'{old_status} -> {new_status}',
                    'action_taken': 'none',
                    'reason': 'No revocation needed for account activation',
                    'timestamp': datetime.utcnow().isoformat()
                }
            
        except Exception as e:
            logger.error(f"Failed to monitor status change for user {user_id}: {str(e)}")
            raise e
    
    async def _get_user_active_grants(self, user_id: str) -> List[Dict[str, Any]]:
        """
        Get all active access grants for a user
        
        Args:
            user_id (str): User ID
            
        Returns:
            List[Dict]: List of active access grants
        """
        grants_ref = self.db.collection('accessGrants')
        query = grants_ref.where('userId', '==', user_id).where('status', '==', 'active')
        
        grants = []
        for doc in query.stream():
            grant_data = doc.to_dict()
            
            # Enrich with segment information
            segment = get_resource_segment_by_id(self.db, grant_data['segmentId'])
            if segment:
                grant_data['segment_name'] = segment.name
                grant_data['security_level'] = segment.security_level
                grant_data['allowed_roles'] = segment.allowed_roles
            
            grants.append(grant_data)
        
        return grants
    
    async def _should_revoke_access(self, grant: Dict[str, Any], old_role: str, 
                                  new_role: str) -> tuple[bool, str]:
        """
        Determine if an access grant should be revoked based on role change
        
        Args:
            grant (Dict): Access grant information
            old_role (str): Previous role
            new_role (str): New role
            
        Returns:
            tuple: (should_revoke, reason)
        """
        try:
            segment_id = grant['segmentId']
            segment = get_resource_segment_by_id(self.db, segment_id)
            
            if not segment:
                return True, "Resource segment no longer exists"
            
            # Check if new role is allowed for this segment
            if new_role not in segment.allowed_roles:
                return True, f"New role '{new_role}' not allowed for segment '{segment.name}'"
            
            # Check security clearance requirements
            role_clearance = {
                'student': 1,
                'visitor': 1,
                'faculty': 3,
                'admin': 5
            }
            
            new_clearance = role_clearance.get(new_role, 1)
            required_clearance = segment.security_level
            
            if new_clearance < required_clearance:
                return True, f"New role clearance level {new_clearance} insufficient for segment security level {required_clearance}"
            
            # Access should be maintained
            return False, "Access still appropriate for new role"
            
        except Exception as e:
            logger.error(f"Error checking if access should be revoked: {str(e)}")
            return True, f"Error evaluating access: {str(e)}"
    
    async def _revoke_access_grant(self, grant: Dict[str, Any], user_id: str, 
                                 revoked_by: str, reason: str) -> bool:
        """
        Revoke a specific access grant
        
        Args:
            grant (Dict): Access grant to revoke
            user_id (str): User ID
            revoked_by (str): ID of user performing revocation
            reason (str): Reason for revocation
            
        Returns:
            bool: True if successful
        """
        try:
            grant_id = grant['grantId']
            
            # Update grant status
            grant_ref = self.db.collection('accessGrants').document(grant_id)
            grant_ref.update({
                'status': 'revoked',
                'revokedAt': datetime.utcnow(),
                'revokedBy': revoked_by,
                'revocationReason': reason
            })
            
            # Log the revocation
            await create_audit_log(
                self.db,
                event_type='access_revocation',
                sub_type='automatic_role_change',
                user_id=revoked_by,
                target_user_id=user_id,
                resource_segment_id=grant['segmentId'],
                action=f'Automatically revoked access to {grant.get("segment_name", grant["segmentId"])}',
                result='success',
                details={
                    'grant_id': grant_id,
                    'reason': reason,
                    'segment_name': grant.get('segment_name'),
                    'security_level': grant.get('security_level')
                }
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to revoke access grant {grant.get('grantId')}: {str(e)}")
            return False
    
    async def _send_revocation_notifications(self, user_id: str, user_name: str, 
                                           revocation_results: List[Dict[str, Any]], 
                                           old_role: str, new_role: str) -> None:
        """
        Send notifications about access revocations due to role change
        
        Args:
            user_id (str): User ID
            user_name (str): User name
            revocation_results (List[Dict]): List of revocation results
            old_role (str): Previous role
            new_role (str): New role
        """
        try:
            successful_revocations = [r for r in revocation_results if r['success']]
            
            if not successful_revocations:
                return
            
            # Notify the user
            segment_names = [r['segment_name'] for r in successful_revocations]
            await create_notification(
                self.db,
                user_id=user_id,
                title='Access Revoked Due to Role Change',
                message=f'Your access to {len(segment_names)} resource segment(s) has been revoked due to your role change from {old_role} to {new_role}.',
                notification_type='access_revoked',
                priority='high',
                data={
                    'old_role': old_role,
                    'new_role': new_role,
                    'revoked_segments': segment_names,
                    'revocation_count': len(successful_revocations)
                }
            )
            
            # Notify administrators
            users_ref = self.db.collection('users')
            admin_query = users_ref.where('role', '==', 'admin').where('isActive', '==', True)
            
            for admin_doc in admin_query.stream():
                admin_data = admin_doc.to_dict()
                
                await create_notification(
                    self.db,
                    user_id=admin_data['userId'],
                    title='Automatic Access Revocation',
                    message=f'Access automatically revoked for {user_name} due to role change: {old_role} -> {new_role}',
                    notification_type='admin_alert',
                    priority='medium',
                    data={
                        'affected_user': user_name,
                        'affected_user_id': user_id,
                        'old_role': old_role,
                        'new_role': new_role,
                        'revoked_segments': segment_names,
                        'revocation_count': len(successful_revocations)
                    }
                )
            
        except Exception as e:
            logger.error(f"Failed to send revocation notifications: {str(e)}")
    
    async def _send_deactivation_notifications(self, user_id: str, user_name: str, 
                                             revocation_results: List[Dict[str, Any]]) -> None:
        """
        Send notifications about access revocations due to account deactivation
        
        Args:
            user_id (str): User ID
            user_name (str): User name
            revocation_results (List[Dict]): List of revocation results
        """
        try:
            successful_revocations = [r for r in revocation_results if r['success']]
            
            if not successful_revocations:
                return
            
            # Notify administrators only (user account is deactivated)
            users_ref = self.db.collection('users')
            admin_query = users_ref.where('role', '==', 'admin').where('isActive', '==', True)
            
            segment_names = [r['segment_name'] for r in successful_revocations]
            
            for admin_doc in admin_query.stream():
                admin_data = admin_doc.to_dict()
                
                await create_notification(
                    self.db,
                    user_id=admin_data['userId'],
                    title='Access Revoked - Account Deactivated',
                    message=f'All access revoked for {user_name} due to account deactivation',
                    notification_type='admin_alert',
                    priority='medium',
                    data={
                        'affected_user': user_name,
                        'affected_user_id': user_id,
                        'action': 'account_deactivated',
                        'revoked_segments': segment_names,
                        'revocation_count': len(successful_revocations)
                    }
                )
            
        except Exception as e:
            logger.error(f"Failed to send deactivation notifications: {str(e)}")


# Global service instance
role_change_monitor = None


def get_role_change_monitor(db):
    """
    Get or create the global role change monitor instance
    
    Args:
        db: Firestore client
        
    Returns:
        RoleChangeMonitor: Service instance
    """
    global role_change_monitor
    if role_change_monitor is None:
        role_change_monitor = RoleChangeMonitor(db)
    return role_change_monitor