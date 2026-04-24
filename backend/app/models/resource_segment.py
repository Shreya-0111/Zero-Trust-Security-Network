"""
Resource Segment Model
Defines the Resource Segment data structure and validation for Firestore
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
import uuid


class ResourceSegment:
    """Resource Segment model with schema validation"""
    
    # Valid security levels (1-5)
    VALID_SECURITY_LEVELS = [1, 2, 3, 4, 5]
    
    # Valid categories
    VALID_CATEGORIES = ['academic', 'administrative', 'research', 'infrastructure', 'emergency']
    
    # Valid roles
    VALID_ROLES = ['student', 'faculty', 'admin', 'visitor']
    
    # Valid resource types
    VALID_RESOURCE_TYPES = ['database', 'server', 'application', 'file_system', 'facility']
    
    # Valid log levels
    VALID_LOG_LEVELS = ['basic', 'detailed', 'comprehensive']
    
    def __init__(self, name: str, description: str, security_level: int, category: str, 
                 created_by: str, segment_id: Optional[str] = None):
        """
        Initialize Resource Segment model
        
        Args:
            name (str): Segment name
            description (str): Segment description
            security_level (int): Security level (1-5)
            category (str): Segment category
            created_by (str): Admin user ID who created the segment
            segment_id (str, optional): Segment ID (auto-generated if not provided)
        """
        self.segment_id = segment_id or str(uuid.uuid4())
        self.name = name
        self.description = description
        self.security_level = security_level
        self.category = category
        self.allowed_roles = ['faculty', 'admin']  # Default allowed roles
        self.requires_jit = security_level >= 3  # JIT required for levels 3+
        self.requires_dual_approval = security_level >= 4  # Dual approval for levels 4-5
        self.max_access_duration = 24  # Default 24 hours
        self.access_restrictions = {
            'timeWindows': [
                {
                    'startHour': 8,
                    'endHour': 18,
                    'allowedDays': ['monday', 'tuesday', 'wednesday', 'thursday', 'friday']
                }
            ],
            'locationRestrictions': [],
            'deviceRequirements': {
                'requiresRegisteredDevice': security_level >= 2,
                'minimumTrustScore': max(50, security_level * 15)
            }
        }
        self.resources = []
        self.policies = []
        self.audit_requirements = {
            'logLevel': 'comprehensive' if security_level >= 4 else 'detailed' if security_level >= 2 else 'basic',
            'retentionPeriod': max(365, security_level * 365),  # Minimum 1 year, more for higher levels
            'realTimeMonitoring': security_level >= 3
        }
        self.created_by = created_by
        self.created_at = datetime.utcnow()
        self.last_modified = datetime.utcnow()
        self.modified_by = created_by
        self.is_active = True
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert Resource Segment object to dictionary for Firestore storage
        
        Returns:
            dict: Resource segment data as dictionary
        """
        return {
            'segmentId': self.segment_id,
            'name': self.name,
            'description': self.description,
            'securityLevel': self.security_level,
            'category': self.category,
            'allowedRoles': self.allowed_roles,
            'requiresJIT': self.requires_jit,
            'requiresDualApproval': self.requires_dual_approval,
            'maxAccessDuration': self.max_access_duration,
            'accessRestrictions': self.access_restrictions,
            'resources': self.resources,
            'policies': self.policies,
            'auditRequirements': self.audit_requirements,
            'createdBy': self.created_by,
            'createdAt': self.created_at,
            'lastModified': self.last_modified,
            'modifiedBy': self.modified_by,
            'isActive': self.is_active
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ResourceSegment':
        """
        Create Resource Segment object from dictionary
        
        Args:
            data (dict): Resource segment data dictionary
            
        Returns:
            ResourceSegment: Resource segment object
        """
        segment = cls(
            name=data.get('name'),
            description=data.get('description'),
            security_level=data.get('securityLevel'),
            category=data.get('category'),
            created_by=data.get('createdBy'),
            segment_id=data.get('segmentId')
        )
        
        segment.allowed_roles = data.get('allowedRoles', ['faculty', 'admin'])
        segment.requires_jit = data.get('requiresJIT', segment.security_level >= 3)
        segment.requires_dual_approval = data.get('requiresDualApproval', segment.security_level >= 4)
        segment.max_access_duration = data.get('maxAccessDuration', 24)
        segment.access_restrictions = data.get('accessRestrictions', segment.access_restrictions)
        segment.resources = data.get('resources', [])
        segment.policies = data.get('policies', [])
        segment.audit_requirements = data.get('auditRequirements', segment.audit_requirements)
        segment.created_at = data.get('createdAt', datetime.utcnow())
        segment.last_modified = data.get('lastModified', datetime.utcnow())
        segment.modified_by = data.get('modifiedBy', segment.created_by)
        segment.is_active = data.get('isActive', True)
        
        return segment
    
    def validate(self) -> tuple[bool, Optional[str]]:
        """
        Validate resource segment data
        
        Returns:
            tuple: (is_valid, error_message)
        """
        # Validate required fields
        if not self.segment_id:
            return False, "Segment ID is required"
        
        if not self.name or not self.name.strip():
            return False, "Name is required"
        
        if not self.description or not self.description.strip():
            return False, "Description is required"
        
        if not self.created_by:
            return False, "Created by is required"
        
        # Validate security level
        if self.security_level not in self.VALID_SECURITY_LEVELS:
            return False, f"Security level must be one of: {self.VALID_SECURITY_LEVELS}"
        
        # Validate category
        if self.category not in self.VALID_CATEGORIES:
            return False, f"Category must be one of: {', '.join(self.VALID_CATEGORIES)}"
        
        # Validate allowed roles
        if not self.allowed_roles:
            return False, "At least one allowed role is required"
        
        for role in self.allowed_roles:
            if role not in self.VALID_ROLES:
                return False, f"Invalid role: {role}. Must be one of: {', '.join(self.VALID_ROLES)}"
        
        # Validate max access duration
        if self.max_access_duration <= 0 or self.max_access_duration > 168:  # Max 1 week
            return False, "Max access duration must be between 1 and 168 hours"
        
        # Validate resources
        for resource in self.resources:
            if not isinstance(resource, dict):
                return False, "Each resource must be a dictionary"
            
            required_fields = ['resourceId', 'resourceName', 'resourceType']
            for field in required_fields:
                if field not in resource:
                    return False, f"Resource missing required field: {field}"
            
            if resource['resourceType'] not in self.VALID_RESOURCE_TYPES:
                return False, f"Invalid resource type: {resource['resourceType']}"
            
            if 'sensitivity' in resource:
                if not isinstance(resource['sensitivity'], int) or resource['sensitivity'] not in [1, 2, 3, 4, 5]:
                    return False, "Resource sensitivity must be an integer between 1 and 5"
        
        # Validate audit requirements
        if 'logLevel' in self.audit_requirements:
            if self.audit_requirements['logLevel'] not in self.VALID_LOG_LEVELS:
                return False, f"Invalid log level: {self.audit_requirements['logLevel']}"
        
        return True, None
    
    def add_resource(self, resource_id: str, resource_name: str, resource_type: str, 
                    sensitivity: int = 1) -> None:
        """
        Add a resource to the segment
        
        Args:
            resource_id (str): Resource identifier
            resource_name (str): Resource display name
            resource_type (str): Resource type
            sensitivity (int): Resource sensitivity level (1-5)
        """
        if resource_type not in self.VALID_RESOURCE_TYPES:
            raise ValueError(f"Invalid resource type: {resource_type}")
        
        if sensitivity not in [1, 2, 3, 4, 5]:
            raise ValueError("Sensitivity must be between 1 and 5")
        
        resource = {
            'resourceId': resource_id,
            'resourceName': resource_name,
            'resourceType': resource_type,
            'sensitivity': sensitivity
        }
        
        # Check if resource already exists
        for existing_resource in self.resources:
            if existing_resource['resourceId'] == resource_id:
                raise ValueError(f"Resource with ID {resource_id} already exists")
        
        self.resources.append(resource)
        self.last_modified = datetime.utcnow()
    
    def remove_resource(self, resource_id: str) -> bool:
        """
        Remove a resource from the segment
        
        Args:
            resource_id (str): Resource identifier
            
        Returns:
            bool: True if resource was removed, False if not found
        """
        for i, resource in enumerate(self.resources):
            if resource['resourceId'] == resource_id:
                del self.resources[i]
                self.last_modified = datetime.utcnow()
                return True
        return False
    
    def update_access_restrictions(self, restrictions: Dict[str, Any]) -> None:
        """
        Update access restrictions for the segment
        
        Args:
            restrictions (dict): New access restrictions
        """
        # Validate time windows
        if 'timeWindows' in restrictions:
            for window in restrictions['timeWindows']:
                if not isinstance(window, dict):
                    raise ValueError("Time window must be a dictionary")
                
                required_fields = ['startHour', 'endHour', 'allowedDays']
                for field in required_fields:
                    if field not in window:
                        raise ValueError(f"Time window missing required field: {field}")
                
                if not (0 <= window['startHour'] <= 23) or not (0 <= window['endHour'] <= 23):
                    raise ValueError("Hours must be between 0 and 23")
                
                valid_days = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
                for day in window['allowedDays']:
                    if day not in valid_days:
                        raise ValueError(f"Invalid day: {day}")
        
        self.access_restrictions.update(restrictions)
        self.last_modified = datetime.utcnow()
    
    def can_user_access(self, user_role: str, security_clearance: int = 1) -> tuple[bool, str]:
        """
        Check if a user with given role and clearance can access this segment
        
        Args:
            user_role (str): User role
            security_clearance (int): User security clearance level
            
        Returns:
            tuple: (can_access, reason)
        """
        # Check role permission
        if user_role not in self.allowed_roles:
            return False, f"Role '{user_role}' not allowed for this segment"
        
        # Check security clearance
        if security_clearance < self.security_level:
            return False, f"Security clearance level {security_clearance} insufficient for level {self.security_level} segment"
        
        # Check if segment is active
        if not self.is_active:
            return False, "Segment is not active"
        
        return True, "Access granted"
    
    def to_public_dict(self) -> Dict[str, Any]:
        """
        Convert Resource Segment object to dictionary with public fields only
        
        Returns:
            dict: Public resource segment data
        """
        return {
            'segmentId': self.segment_id,
            'name': self.name,
            'description': self.description,
            'securityLevel': self.security_level,
            'category': self.category,
            'allowedRoles': self.allowed_roles,
            'requiresJIT': self.requires_jit,
            'requiresDualApproval': self.requires_dual_approval,
            'maxAccessDuration': self.max_access_duration,
            'accessRestrictions': self.access_restrictions,
            'resources': self.resources,
            'isActive': self.is_active,
            'createdAt': self.created_at.isoformat() if isinstance(self.created_at, datetime) else self.created_at,
            'lastModified': self.last_modified.isoformat() if isinstance(self.last_modified, datetime) else self.last_modified
        }


def create_resource_segment(db, name: str, description: str, security_level: int, 
                          category: str, created_by: str, **kwargs) -> ResourceSegment:
    """
    Create a new resource segment document in Firestore
    
    Args:
        db: Firestore client
        name (str): Segment name
        description (str): Segment description
        security_level (int): Security level (1-5)
        category (str): Segment category
        created_by (str): Admin user ID
        **kwargs: Additional segment properties
        
    Returns:
        ResourceSegment: Created resource segment object
        
    Raises:
        Exception: If validation fails or creation fails
    """
    # Create resource segment object
    segment = ResourceSegment(name, description, security_level, category, created_by)
    
    # Apply additional properties
    for key, value in kwargs.items():
        if hasattr(segment, key):
            setattr(segment, key, value)
    
    # Validate segment data
    is_valid, error_message = segment.validate()
    if not is_valid:
        raise Exception(f"Resource segment validation failed: {error_message}")
    
    # Check if segment with same name already exists
    segments_ref = db.collection('resourceSegments')
    existing_query = segments_ref.where('name', '==', name).where('isActive', '==', True).limit(1)
    existing_docs = list(existing_query.stream())
    
    if existing_docs:
        raise Exception(f"Resource segment with name '{name}' already exists")
    
    # Create segment document in Firestore
    segment_ref = db.collection('resourceSegments').document(segment.segment_id)
    segment_ref.set(segment.to_dict())
    
    return segment


def get_resource_segment_by_id(db, segment_id: str) -> Optional[ResourceSegment]:
    """
    Get resource segment by ID from Firestore
    
    Args:
        db: Firestore client
        segment_id (str): Segment ID
        
    Returns:
        ResourceSegment: Resource segment object or None if not found
    """
    segment_doc = db.collection('resourceSegments').document(segment_id).get()
    if not segment_doc.exists:
        return None
    
    return ResourceSegment.from_dict(segment_doc.to_dict())


def get_all_resource_segments(db, include_inactive: bool = False) -> List[ResourceSegment]:
    """
    Get all resource segments from Firestore
    
    Args:
        db: Firestore client
        include_inactive (bool): Whether to include inactive segments
        
    Returns:
        List[ResourceSegment]: List of resource segment objects
    """
    segments_ref = db.collection('resourceSegments')
    
    if not include_inactive:
        query = segments_ref.where('isActive', '==', True)
    else:
        query = segments_ref
    
    segments = []
    for doc in query.stream():
        segments.append(ResourceSegment.from_dict(doc.to_dict()))
    
    return segments


def get_segments_by_security_level(db, max_security_level: int) -> List[ResourceSegment]:
    """
    Get resource segments with security level up to the specified maximum
    
    Args:
        db: Firestore client
        max_security_level (int): Maximum security level to include
        
    Returns:
        List[ResourceSegment]: List of resource segment objects
    """
    segments_ref = db.collection('resourceSegments')
    query = segments_ref.where('isActive', '==', True).where('securityLevel', '<=', max_security_level)
    
    segments = []
    for doc in query.stream():
        segments.append(ResourceSegment.from_dict(doc.to_dict()))
    
    return segments


def get_segments_by_role(db, user_role: str) -> List[ResourceSegment]:
    """
    Get resource segments accessible by a specific role
    
    Args:
        db: Firestore client
        user_role (str): User role
        
    Returns:
        List[ResourceSegment]: List of accessible resource segment objects
    """
    segments_ref = db.collection('resourceSegments')
    from google.cloud.firestore_v1 import FieldFilter
    query = segments_ref.where(
        filter=FieldFilter('isActive', '==', True)
    ).where(
        filter=FieldFilter('allowedRoles', 'array_contains', user_role)
    )
    
    segments = []
    for doc in query.stream():
        segments.append(ResourceSegment.from_dict(doc.to_dict()))
    
    return segments


def update_resource_segment(db, segment_id: str, update_data: Dict[str, Any], 
                          modified_by: str) -> bool:
    """
    Update resource segment document in Firestore
    
    Args:
        db: Firestore client
        segment_id (str): Segment ID
        update_data (dict): Fields to update
        modified_by (str): Admin user ID making the update
        
    Returns:
        bool: True if successful
        
    Raises:
        Exception: If segment not found or validation fails
    """
    segment_ref = db.collection('resourceSegments').document(segment_id)
    segment_doc = segment_ref.get()
    
    if not segment_doc.exists:
        raise Exception("Resource segment not found")
    
    # Add modification metadata
    update_data['lastModified'] = datetime.utcnow()
    update_data['modifiedBy'] = modified_by
    
    # Update the document
    segment_ref.update(update_data)
    return True


def delete_resource_segment(db, segment_id: str, deleted_by: str) -> bool:
    """
    Soft delete resource segment (mark as inactive)
    
    Args:
        db: Firestore client
        segment_id (str): Segment ID
        deleted_by (str): Admin user ID performing the deletion
        
    Returns:
        bool: True if successful
        
    Raises:
        Exception: If segment not found
    """
    segment_ref = db.collection('resourceSegments').document(segment_id)
    segment_doc = segment_ref.get()
    
    if not segment_doc.exists:
        raise Exception("Resource segment not found")
    
    # Soft delete by marking as inactive
    update_data = {
        'isActive': False,
        'lastModified': datetime.utcnow(),
        'modifiedBy': deleted_by
    }
    
    segment_ref.update(update_data)
    return True


def create_default_resource_segments(db, created_by: str) -> List[ResourceSegment]:
    """
    Create default resource segments for the system
    
    Args:
        db: Firestore client
        created_by (str): Admin user ID creating the defaults
        
    Returns:
        List[ResourceSegment]: List of created resource segments
    """
    default_segments = [
        {
            'name': 'Academic Resources',
            'description': 'General academic facilities and resources',
            'security_level': 1,
            'category': 'academic',
            'allowed_roles': ['student', 'faculty', 'admin', 'visitor'],
            'resources': [
                {'resourceId': 'classrooms', 'resourceName': 'Classrooms', 'resourceType': 'facility', 'sensitivity': 1},
                {'resourceId': 'lecture-halls', 'resourceName': 'Lecture Halls', 'resourceType': 'facility', 'sensitivity': 1},
                {'resourceId': 'study-areas', 'resourceName': 'Study Areas', 'resourceType': 'facility', 'sensitivity': 1}
            ]
        },
        {
            'name': 'Library Services',
            'description': 'Library facilities and study areas',
            'security_level': 1,
            'category': 'academic',
            'allowed_roles': ['student', 'faculty', 'admin', 'visitor'],
            'resources': [
                {'resourceId': 'main-library', 'resourceName': 'Main Library', 'resourceType': 'facility', 'sensitivity': 1},
                {'resourceId': 'study-rooms', 'resourceName': 'Study Rooms', 'resourceType': 'facility', 'sensitivity': 1},
                {'resourceId': 'computer-lab', 'resourceName': 'Computer Lab', 'resourceType': 'facility', 'sensitivity': 2}
            ]
        },
        {
            'name': 'Administrative Systems',
            'description': 'Administrative office areas and systems',
            'security_level': 3,
            'category': 'administrative',
            'allowed_roles': ['faculty', 'admin'],
            'resources': [
                {'resourceId': 'admin-offices', 'resourceName': 'Administrative Offices', 'resourceType': 'facility', 'sensitivity': 3},
                {'resourceId': 'student-records', 'resourceName': 'Student Records System', 'resourceType': 'database', 'sensitivity': 4},
                {'resourceId': 'hr-system', 'resourceName': 'HR Management System', 'resourceType': 'application', 'sensitivity': 4}
            ]
        },
        {
            'name': 'Research Labs',
            'description': 'Research laboratory facilities and equipment',
            'security_level': 4,
            'category': 'research',
            'allowed_roles': ['faculty', 'admin'],
            'resources': [
                {'resourceId': 'research-lab-1', 'resourceName': 'Research Lab 1', 'resourceType': 'facility', 'sensitivity': 4},
                {'resourceId': 'research-data', 'resourceName': 'Research Data Storage', 'resourceType': 'database', 'sensitivity': 5},
                {'resourceId': 'lab-equipment', 'resourceName': 'Laboratory Equipment', 'resourceType': 'facility', 'sensitivity': 4}
            ]
        },
        {
            'name': 'IT Infrastructure',
            'description': 'Server rooms and IT facilities',
            'security_level': 5,
            'category': 'infrastructure',
            'allowed_roles': ['admin'],
            'resources': [
                {'resourceId': 'server-room', 'resourceName': 'Server Room', 'resourceType': 'facility', 'sensitivity': 5},
                {'resourceId': 'network-core', 'resourceName': 'Network Core Systems', 'resourceType': 'server', 'sensitivity': 5},
                {'resourceId': 'backup-systems', 'resourceName': 'Backup Systems', 'resourceType': 'server', 'sensitivity': 5}
            ]
        }
    ]
    
    created_segments = []
    
    for segment_data in default_segments:
        try:
            # Extract resources before creating segment
            resources = segment_data.pop('resources', [])
            allowed_roles = segment_data.pop('allowed_roles', ['faculty', 'admin'])
            
            # Create the segment
            segment = create_resource_segment(db, created_by=created_by, **segment_data)
            
            # Add allowed roles
            segment.allowed_roles = allowed_roles
            
            # Add resources
            for resource in resources:
                segment.add_resource(
                    resource['resourceId'],
                    resource['resourceName'],
                    resource['resourceType'],
                    resource.get('sensitivity', 1)
                )
            
            # Update the segment in Firestore
            update_resource_segment(db, segment.segment_id, {
                'allowedRoles': segment.allowed_roles,
                'resources': segment.resources
            }, created_by)
            
            created_segments.append(segment)
            
        except Exception as e:
            # Skip if segment already exists
            if "already exists" not in str(e):
                raise e
    
    return created_segments