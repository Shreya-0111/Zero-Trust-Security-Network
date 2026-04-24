"""
Resource Segment Service
Handles resource segment management, access control, and policy enforcement
"""

import logging
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from ..models.resource_segment import (
    ResourceSegment,
    create_resource_segment,
    get_resource_segment_by_id,
    get_all_resource_segments,
    get_segments_by_security_level,
    get_segments_by_role,
    update_resource_segment,
    delete_resource_segment,
    create_default_resource_segments
)
from ..models.user import get_user_by_id
from ..models.audit_log import create_audit_log

logger = logging.getLogger(__name__)


class ResourceSegmentService:
    """Service for managing resource segments and access control"""
    
    def __init__(self, db):
        """
        Initialize Resource Segment Service
        
        Args:
            db: Firestore client
        """
        self.db = db
    
    async def create_segment(self, name: str, description: str, security_level: int,
                           category: str, created_by: str, **kwargs) -> ResourceSegment:
        """
        Create a new resource segment
        
        Args:
            name (str): Segment name
            description (str): Segment description
            security_level (int): Security level (1-5)
            category (str): Segment category
            created_by (str): Admin user ID
            **kwargs: Additional segment properties
            
        Returns:
            ResourceSegment: Created resource segment
            
        Raises:
            Exception: If creation fails or validation errors
        """
        try:
            # Verify the creator is an admin
            creator = get_user_by_id(self.db, created_by)
            if not creator or creator.role != 'admin':
                raise Exception("Only administrators can create resource segments")
            
            # Create the segment
            segment = create_resource_segment(
                self.db, name, description, security_level, category, created_by, **kwargs
            )
            
            # Log the creation
            await create_audit_log(
                self.db,
                event_type='resource_management',
                sub_type='segment_created',
                user_id=created_by,
                resource_segment_id=segment.segment_id,
                action=f'Created resource segment: {name}',
                result='success',
                details={
                    'segment_name': name,
                    'security_level': security_level,
                    'category': category
                }
            )
            
            logger.info(f"Resource segment '{name}' created by {created_by}")
            return segment
            
        except Exception as e:
            logger.error(f"Failed to create resource segment: {str(e)}")
            
            # Log the failure
            await create_audit_log(
                self.db,
                event_type='resource_management',
                sub_type='segment_creation_failed',
                user_id=created_by,
                action=f'Failed to create resource segment: {name}',
                result='failure',
                details={'error': str(e)}
            )
            
            raise e
    
    async def get_segment(self, segment_id: str, user_id: str) -> Optional[ResourceSegment]:
        """
        Get a resource segment by ID with access control
        
        Args:
            segment_id (str): Segment ID
            user_id (str): Requesting user ID
            
        Returns:
            ResourceSegment: Resource segment or None if not found/accessible
        """
        try:
            segment = get_resource_segment_by_id(self.db, segment_id)
            if not segment:
                return None
            
            # Check if user can access this segment info
            user = get_user_by_id(self.db, user_id)
            if not user:
                return None
            
            # Admins can see all segments
            if user.role == 'admin':
                return segment
            
            # Faculty can see segments they can assign to visitors or access themselves
            if user.role == 'faculty':
                can_access, _ = segment.can_user_access(user.role, self._get_user_security_clearance(user))
                if can_access or 'visitor' in segment.allowed_roles:
                    return segment
            
            # Students can only see visitor-accessible segments
            if user.role == 'student' and 'visitor' in segment.allowed_roles:
                return segment
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get resource segment {segment_id}: {str(e)}")
            return None
    
    async def get_segments_for_user(self, user_id: str, include_visitor_segments: bool = False) -> List[ResourceSegment]:
        """
        Get resource segments accessible by a user
        
        Args:
            user_id (str): User ID
            include_visitor_segments (bool): Whether to include segments accessible by visitors
            
        Returns:
            List[ResourceSegment]: List of accessible segments
        """
        try:
            user = get_user_by_id(self.db, user_id)
            if not user:
                return []
            
            # Get user's security clearance level
            security_clearance = self._get_user_security_clearance(user)
            
            # Get all active segments
            all_segments = get_all_resource_segments(self.db, include_inactive=False)
            
            accessible_segments = []
            
            for segment in all_segments:
                # Check if user can access this segment
                can_access, _ = segment.can_user_access(user.role, security_clearance)
                
                if can_access:
                    accessible_segments.append(segment)
                elif include_visitor_segments and 'visitor' in segment.allowed_roles:
                    # Include visitor-accessible segments for faculty/admin who can assign visitors
                    if user.role in ['faculty', 'admin']:
                        accessible_segments.append(segment)
            
            return accessible_segments
            
        except Exception as e:
            logger.error(f"Failed to get segments for user {user_id}: {str(e)}")
            return []
    
    async def update_segment(self, segment_id: str, update_data: Dict[str, Any], 
                           modified_by: str) -> bool:
        """
        Update a resource segment
        
        Args:
            segment_id (str): Segment ID
            update_data (dict): Fields to update
            modified_by (str): Admin user ID making the update
            
        Returns:
            bool: True if successful
            
        Raises:
            Exception: If update fails or insufficient permissions
        """
        try:
            # Verify the modifier is an admin
            modifier = get_user_by_id(self.db, modified_by)
            if not modifier or modifier.role != 'admin':
                raise Exception("Only administrators can update resource segments")
            
            # Get the current segment for logging
            current_segment = get_resource_segment_by_id(self.db, segment_id)
            if not current_segment:
                raise Exception("Resource segment not found")
            
            # Update the segment
            success = update_resource_segment(self.db, segment_id, update_data, modified_by)
            
            if success:
                # Log the update
                await create_audit_log(
                    self.db,
                    event_type='resource_management',
                    sub_type='segment_updated',
                    user_id=modified_by,
                    resource_segment_id=segment_id,
                    action=f'Updated resource segment: {current_segment.name}',
                    result='success',
                    details={
                        'updated_fields': list(update_data.keys()),
                        'segment_name': current_segment.name
                    }
                )
                
                logger.info(f"Resource segment '{current_segment.name}' updated by {modified_by}")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to update resource segment {segment_id}: {str(e)}")
            
            # Log the failure
            await create_audit_log(
                self.db,
                event_type='resource_management',
                sub_type='segment_update_failed',
                user_id=modified_by,
                resource_segment_id=segment_id,
                action=f'Failed to update resource segment',
                result='failure',
                details={'error': str(e)}
            )
            
            raise e
    
    async def delete_segment(self, segment_id: str, deleted_by: str) -> bool:
        """
        Delete (deactivate) a resource segment
        
        Args:
            segment_id (str): Segment ID
            deleted_by (str): Admin user ID performing the deletion
            
        Returns:
            bool: True if successful
            
        Raises:
            Exception: If deletion fails or insufficient permissions
        """
        try:
            # Verify the deleter is an admin
            deleter = get_user_by_id(self.db, deleted_by)
            if not deleter or deleter.role != 'admin':
                raise Exception("Only administrators can delete resource segments")
            
            # Get the current segment for logging
            current_segment = get_resource_segment_by_id(self.db, segment_id)
            if not current_segment:
                raise Exception("Resource segment not found")
            
            # Check if segment is in use (has active access grants, etc.)
            # This would need to be implemented based on your access grant model
            # For now, we'll allow deletion but log it
            
            # Soft delete the segment
            success = delete_resource_segment(self.db, segment_id, deleted_by)
            
            if success:
                # Log the deletion
                await create_audit_log(
                    self.db,
                    event_type='resource_management',
                    sub_type='segment_deleted',
                    user_id=deleted_by,
                    resource_segment_id=segment_id,
                    action=f'Deleted resource segment: {current_segment.name}',
                    result='success',
                    details={
                        'segment_name': current_segment.name,
                        'security_level': current_segment.security_level
                    }
                )
                
                logger.info(f"Resource segment '{current_segment.name}' deleted by {deleted_by}")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to delete resource segment {segment_id}: {str(e)}")
            
            # Log the failure
            await create_audit_log(
                self.db,
                event_type='resource_management',
                sub_type='segment_deletion_failed',
                user_id=deleted_by,
                resource_segment_id=segment_id,
                action=f'Failed to delete resource segment',
                result='failure',
                details={'error': str(e)}
            )
            
            raise e
    
    async def check_access_permission(self, user_id: str, segment_id: str, 
                                    action: str = 'access') -> Tuple[bool, str, Dict[str, Any]]:
        """
        Check if a user can access a specific resource segment
        
        Args:
            user_id (str): User ID
            segment_id (str): Resource segment ID
            action (str): Action being performed
            
        Returns:
            Tuple[bool, str, Dict]: (can_access, reason, additional_info)
        """
        try:
            # Get user and segment
            user = get_user_by_id(self.db, user_id)
            segment = get_resource_segment_by_id(self.db, segment_id)
            
            if not user:
                return False, "User not found", {}
            
            if not segment:
                return False, "Resource segment not found", {}
            
            # Get user's security clearance
            security_clearance = self._get_user_security_clearance(user)
            
            # Check basic access permission
            can_access, reason = segment.can_user_access(user.role, security_clearance)
            
            additional_info = {
                'user_role': user.role,
                'security_clearance': security_clearance,
                'segment_security_level': segment.security_level,
                'requires_jit': segment.requires_jit,
                'requires_dual_approval': segment.requires_dual_approval,
                'max_access_duration': segment.max_access_duration
            }
            
            # If basic access is granted, check additional requirements
            if can_access:
                # Check if JIT access is required
                if segment.requires_jit and action != 'jit_request':
                    return False, "Just-in-time access required for this segment", additional_info
                
                # Check time restrictions
                time_allowed = self._check_time_restrictions(segment.access_restrictions.get('timeWindows', []))
                if not time_allowed:
                    return False, "Access not allowed during current time window", additional_info
            
            return can_access, reason, additional_info
            
        except Exception as e:
            logger.error(f"Failed to check access permission: {str(e)}")
            return False, f"Error checking access: {str(e)}", {}
    
    async def initialize_default_segments(self, admin_user_id: str) -> List[ResourceSegment]:
        """
        Initialize default resource segments for the system
        
        Args:
            admin_user_id (str): Admin user ID creating the defaults
            
        Returns:
            List[ResourceSegment]: List of created segments
        """
        try:
            # Verify the user is an admin
            admin_user = get_user_by_id(self.db, admin_user_id)
            if not admin_user or admin_user.role != 'admin':
                raise Exception("Only administrators can initialize default segments")
            
            # Create default segments
            segments = create_default_resource_segments(self.db, admin_user_id)
            
            # Log the initialization
            await create_audit_log(
                self.db,
                event_type='resource_management',
                sub_type='default_segments_initialized',
                user_id=admin_user_id,
                action='Initialized default resource segments',
                result='success',
                details={
                    'segments_created': len(segments),
                    'segment_names': [s.name for s in segments]
                }
            )
            
            logger.info(f"Default resource segments initialized by {admin_user_id}")
            return segments
            
        except Exception as e:
            logger.error(f"Failed to initialize default segments: {str(e)}")
            raise e
    
    def _get_user_security_clearance(self, user) -> int:
        """
        Get user's security clearance level based on role
        
        Args:
            user: User object
            
        Returns:
            int: Security clearance level (1-5)
        """
        # Map roles to security clearance levels
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


# Global service instance
resource_segment_service = None


def get_resource_segment_service(db):
    """
    Get or create the global resource segment service instance
    
    Args:
        db: Firestore client
        
    Returns:
        ResourceSegmentService: Service instance
    """
    global resource_segment_service
    if resource_segment_service is None:
        resource_segment_service = ResourceSegmentService(db)
    return resource_segment_service