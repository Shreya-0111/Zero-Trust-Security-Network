"""
Policy Model
Defines the Policy data structure and validation for Firestore
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
import uuid


class Policy:
    """Policy model with schema validation"""
    
    def __init__(
        self,
        name: str,
        description: str,
        rules: List[Dict[str, Any]],
        priority: int = 0,
        created_by: str = None,
        policy_id: str = None
    ):
        """
        Initialize Policy model
        
        Args:
            name (str): Policy name (unique)
            description (str): Policy description
            rules (list): List of policy rules
            priority (int): Policy priority (higher = evaluated first)
            created_by (str): Admin user ID who created the policy
            policy_id (str, optional): Policy ID (auto-generated if not provided)
        """
        self.policy_id = policy_id or str(uuid.uuid4())
        self.name = name
        self.description = description
        self.rules = rules
        self.priority = priority
        self.is_active = True
        self.created_by = created_by
        self.created_at = datetime.utcnow()
        self.last_modified = datetime.utcnow()
        self.modified_by = created_by
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert Policy object to dictionary for Firestore storage
        
        Returns:
            dict: Policy data as dictionary
        """
        return {
            'policyId': self.policy_id,
            'name': self.name,
            'description': self.description,
            'rules': self.rules,
            'priority': self.priority,
            'isActive': self.is_active,
            'createdBy': self.created_by,
            'createdAt': self.created_at,
            'lastModified': self.last_modified,
            'modifiedBy': self.modified_by
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Policy':
        """
        Create Policy object from dictionary
        
        Args:
            data (dict): Policy data dictionary
            
        Returns:
            Policy: Policy object
        """
        policy = cls(
            name=data.get('name'),
            description=data.get('description', ''),
            rules=data.get('rules', []),
            priority=data.get('priority', 0),
            created_by=data.get('createdBy'),
            policy_id=data.get('policyId')
        )
        
        policy.is_active = data.get('isActive', True)
        policy.created_at = data.get('createdAt', datetime.utcnow())
        policy.last_modified = data.get('lastModified', datetime.utcnow())
        policy.modified_by = data.get('modifiedBy')
        
        return policy
    
    def validate(self) -> tuple[bool, Optional[str]]:
        """
        Validate policy data
        
        Returns:
            tuple: (is_valid, error_message)
        """
        # Validate required fields
        if not self.name:
            return False, "Policy name is required"
        
        if not self.rules or len(self.rules) == 0:
            return False, "At least one rule is required"
        
        # Validate each rule
        for i, rule in enumerate(self.rules):
            is_valid, error = self._validate_rule(rule, i)
            if not is_valid:
                return False, error
        
        # Validate priority
        if not isinstance(self.priority, int):
            return False, "Priority must be an integer"
        
        return True, None
    
    def _validate_rule(self, rule: Dict[str, Any], index: int) -> tuple[bool, Optional[str]]:
        """
        Validate individual policy rule
        
        Args:
            rule (dict): Rule to validate
            index (int): Rule index for error messages
        
        Returns:
            tuple: (is_valid, error_message)
        """
        # Required fields
        if 'resourceType' not in rule:
            return False, f"Rule {index}: resourceType is required"
        
        if 'allowedRoles' not in rule or not isinstance(rule['allowedRoles'], list):
            return False, f"Rule {index}: allowedRoles must be a list"
        
        if len(rule['allowedRoles']) == 0:
            return False, f"Rule {index}: at least one allowed role is required"
        
        # Validate minConfidence if present
        if 'minConfidence' in rule:
            min_conf = rule['minConfidence']
            if not isinstance(min_conf, (int, float)) or min_conf < 0 or min_conf > 100:
                return False, f"Rule {index}: minConfidence must be between 0 and 100"
        
        # Validate mfaRequired if present
        if 'mfaRequired' in rule and not isinstance(rule['mfaRequired'], bool):
            return False, f"Rule {index}: mfaRequired must be a boolean"
        
        # Validate timeRestrictions if present
        if 'timeRestrictions' in rule:
            time_restrictions = rule['timeRestrictions']
            
            if 'startHour' in time_restrictions:
                start_hour = time_restrictions['startHour']
                if not isinstance(start_hour, int) or start_hour < 0 or start_hour > 23:
                    return False, f"Rule {index}: startHour must be between 0 and 23"
            
            if 'endHour' in time_restrictions:
                end_hour = time_restrictions['endHour']
                if not isinstance(end_hour, int) or end_hour < 0 or end_hour > 23:
                    return False, f"Rule {index}: endHour must be between 0 and 23"
            
            if 'allowedDays' in time_restrictions:
                allowed_days = time_restrictions['allowedDays']
                if not isinstance(allowed_days, list):
                    return False, f"Rule {index}: allowedDays must be a list"
                
                valid_days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
                for day in allowed_days:
                    if day not in valid_days:
                        return False, f"Rule {index}: invalid day '{day}' in allowedDays"
        
        return True, None
    
    def add_rule(self, rule: Dict[str, Any]) -> bool:
        """
        Add a new rule to the policy
        
        Args:
            rule (dict): Rule to add
        
        Returns:
            bool: True if successful
        
        Raises:
            Exception: If rule validation fails
        """
        is_valid, error = self._validate_rule(rule, len(self.rules))
        if not is_valid:
            raise Exception(f"Invalid rule: {error}")
        
        self.rules.append(rule)
        self.last_modified = datetime.utcnow()
        return True
    
    def update_rule(self, index: int, rule: Dict[str, Any]) -> bool:
        """
        Update an existing rule
        
        Args:
            index (int): Rule index to update
            rule (dict): New rule data
        
        Returns:
            bool: True if successful
        
        Raises:
            Exception: If index is invalid or rule validation fails
        """
        if index < 0 or index >= len(self.rules):
            raise Exception(f"Invalid rule index: {index}")
        
        is_valid, error = self._validate_rule(rule, index)
        if not is_valid:
            raise Exception(f"Invalid rule: {error}")
        
        self.rules[index] = rule
        self.last_modified = datetime.utcnow()
        return True
    
    def remove_rule(self, index: int) -> bool:
        """
        Remove a rule from the policy
        
        Args:
            index (int): Rule index to remove
        
        Returns:
            bool: True if successful
        
        Raises:
            Exception: If index is invalid or would leave policy with no rules
        """
        if index < 0 or index >= len(self.rules):
            raise Exception(f"Invalid rule index: {index}")
        
        if len(self.rules) <= 1:
            raise Exception("Cannot remove last rule from policy")
        
        self.rules.pop(index)
        self.last_modified = datetime.utcnow()
        return True


def create_policy(
    db,
    name: str,
    description: str,
    rules: List[Dict[str, Any]],
    priority: int = 0,
    created_by: str = None
) -> Policy:
    """
    Create a new policy in Firestore
    
    Args:
        db: Firestore client
        name (str): Policy name
        description (str): Policy description
        rules (list): Policy rules
        priority (int): Policy priority
        created_by (str): Admin user ID
    
    Returns:
        Policy: Created policy object
    
    Raises:
        Exception: If validation fails or creation fails
    """
    # Create policy object
    policy = Policy(name, description, rules, priority, created_by)
    
    # Validate policy
    is_valid, error_message = policy.validate()
    if not is_valid:
        raise Exception(f"Policy validation failed: {error_message}")
    
    # Check if policy with same name already exists
    policies_ref = db.collection('policies')
    existing = policies_ref.where('name', '==', name).limit(1).stream()
    
    if any(existing):
        raise Exception(f"Policy with name '{name}' already exists")
    
    # Create policy document in Firestore
    policy_ref = policies_ref.document(policy.policy_id)
    policy_ref.set(policy.to_dict())
    
    return policy


def get_policy_by_id(db, policy_id: str) -> Optional[Policy]:
    """
    Get policy by ID from Firestore
    
    Args:
        db: Firestore client
        policy_id (str): Policy ID
    
    Returns:
        Policy: Policy object or None if not found
    """
    policy_doc = db.collection('policies').document(policy_id).get()
    if not policy_doc.exists:
        return None
    
    return Policy.from_dict(policy_doc.to_dict())


def get_all_policies(db, active_only: bool = True) -> List[Policy]:
    """
    Get all policies from Firestore
    
    Args:
        db: Firestore client
        active_only (bool): If True, only return active policies
    
    Returns:
        list: List of Policy objects
    """
    policies_ref = db.collection('policies')
    
    if active_only:
        query = policies_ref.where('isActive', '==', True)
    else:
        query = policies_ref
    
    policies = []
    for doc in query.stream():
        policy = Policy.from_dict(doc.to_dict())
        policies.append(policy)
    
    # Sort by priority (highest first)
    policies.sort(key=lambda p: p.priority, reverse=True)
    
    return policies


def update_policy(
    db,
    policy_id: str,
    update_data: Dict[str, Any],
    modified_by: str = None
) -> bool:
    """
    Update policy in Firestore
    
    Args:
        db: Firestore client
        policy_id (str): Policy ID
        update_data (dict): Fields to update
        modified_by (str): Admin user ID making the update
    
    Returns:
        bool: True if successful
    
    Raises:
        Exception: If policy not found or validation fails
    """
    policy_ref = db.collection('policies').document(policy_id)
    policy_doc = policy_ref.get()
    
    if not policy_doc.exists:
        raise Exception("Policy not found")
    
    # Add modification metadata
    update_data['lastModified'] = datetime.utcnow()
    if modified_by:
        update_data['modifiedBy'] = modified_by
    
    # If updating rules, validate them
    if 'rules' in update_data:
        policy = Policy.from_dict(policy_doc.to_dict())
        policy.rules = update_data['rules']
        is_valid, error = policy.validate()
        if not is_valid:
            raise Exception(f"Policy validation failed: {error}")
    
    policy_ref.update(update_data)
    return True


def delete_policy(db, policy_id: str) -> bool:
    """
    Delete (deactivate) policy in Firestore
    
    Args:
        db: Firestore client
        policy_id (str): Policy ID
    
    Returns:
        bool: True if successful
    
    Raises:
        Exception: If policy not found
    """
    policy_ref = db.collection('policies').document(policy_id)
    
    if not policy_ref.get().exists:
        raise Exception("Policy not found")
    
    # Soft delete by setting isActive to False
    policy_ref.update({
        'isActive': False,
        'lastModified': datetime.utcnow()
    })
    
    return True


def create_default_policies(db, admin_id: str = 'system') -> List[Policy]:
    """
    Create default policies for common resources
    
    Args:
        db: Firestore client
        admin_id (str): Admin user ID creating the policies
    
    Returns:
        list: List of created Policy objects
    """
    default_policies = [
        {
            'name': 'Lab Server Access',
            'description': 'Access policy for laboratory servers',
            'rules': [
                {
                    'resourceType': 'lab_server',
                    'allowedRoles': ['faculty', 'admin'],
                    'minConfidence': 70,
                    'mfaRequired': True,
                    'timeRestrictions': {
                        'startHour': 6,
                        'endHour': 22
                    }
                }
            ],
            'priority': 10
        },
        {
            'name': 'Library Database Access',
            'description': 'Access policy for library databases',
            'rules': [
                {
                    'resourceType': 'library_database',
                    'allowedRoles': ['student', 'faculty', 'admin'],
                    'minConfidence': 60,
                    'mfaRequired': False
                }
            ],
            'priority': 5
        },
        {
            'name': 'Admin Panel Access',
            'description': 'Access policy for administrative panel',
            'rules': [
                {
                    'resourceType': 'admin_panel',
                    'allowedRoles': ['admin'],
                    'minConfidence': 90,
                    'mfaRequired': True
                }
            ],
            'priority': 20
        }
    ]
    
    created_policies = []
    
    for policy_data in default_policies:
        try:
            # Check if policy already exists
            existing = db.collection('policies').where('name', '==', policy_data['name']).limit(1).stream()
            if any(existing):
                print(f"Policy '{policy_data['name']}' already exists, skipping")
                continue
            
            policy = create_policy(
                db,
                name=policy_data['name'],
                description=policy_data['description'],
                rules=policy_data['rules'],
                priority=policy_data['priority'],
                created_by=admin_id
            )
            created_policies.append(policy)
            print(f"Created policy: {policy.name}")
        
        except Exception as e:
            print(f"Error creating policy '{policy_data['name']}': {str(e)}")
    
    return created_policies
