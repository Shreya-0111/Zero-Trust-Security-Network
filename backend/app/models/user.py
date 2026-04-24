"""
User Model
Defines the User data structure and validation for Firestore
"""

from datetime import datetime
import re


class User:
    """User model with schema validation"""
    
    # Valid roles
    VALID_ROLES = ['student', 'faculty', 'admin']
    
    # Email validation regex
    EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    
    def __init__(self, user_id, email, role, name, department=None, student_id=None):
        """
        Initialize User model
        
        Args:
            user_id (str): Firebase UID
            email (str): User email address
            role (str): User role (student, faculty, admin)
            name (str): User full name
            department (str, optional): User department
            student_id (str, optional): Student ID (for students)
        """
        self.user_id = user_id
        self.email = email
        self.role = role
        self.name = name
        self.department = department
        self.student_id = student_id
        self.mfa_enabled = False
        self.mfa_secret = None
        self.created_at = datetime.utcnow()
        self.last_login = None
        self.is_active = True
        self.failed_login_attempts = 0
        self.lockout_until = None
        self.mfa_failed_attempts = 0
        self.metadata = {
            'lastIpAddress': None,
            'lastDeviceInfo': None,
            'lastFailedLoginIp': None,
            'lastFailedLoginAt': None
        }
    
    def to_dict(self):
        """
        Convert User object to dictionary for Firestore storage
        
        Returns:
            dict: User data as dictionary
        """
        return {
            'userId': self.user_id,
            'email': self.email,
            'role': self.role,
            'name': self.name,
            'department': self.department,
            'studentId': self.student_id,
            'mfaEnabled': self.mfa_enabled,
            'mfaSecret': self.mfa_secret,
            'createdAt': self.created_at,
            'lastLogin': self.last_login,
            'isActive': self.is_active,
            'failedLoginAttempts': self.failed_login_attempts,
            'lockoutUntil': self.lockout_until,
            'mfaFailedAttempts': self.mfa_failed_attempts,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data):
        """
        Create User object from dictionary
        
        Args:
            data (dict): User data dictionary
            
        Returns:
            User: User object
        """
        user = cls(
            user_id=data.get('userId'),
            email=data.get('email'),
            role=data.get('role'),
            name=data.get('name'),
            department=data.get('department'),
            student_id=data.get('studentId')
        )
        
        user.mfa_enabled = data.get('mfaEnabled', False)
        user.mfa_secret = data.get('mfaSecret')
        user.created_at = data.get('createdAt', datetime.utcnow())
        user.last_login = data.get('lastLogin')
        user.is_active = data.get('isActive', True)
        user.failed_login_attempts = data.get('failedLoginAttempts', 0)
        user.lockout_until = data.get('lockoutUntil')
        user.mfa_failed_attempts = data.get('mfaFailedAttempts', 0)
        user.metadata = data.get('metadata', {})
        
        return user
    
    def validate(self):
        """
        Validate user data
        
        Returns:
            tuple: (is_valid, error_message)
        """
        # Validate required fields
        if not self.user_id:
            return False, "User ID is required"
        
        if not self.email:
            return False, "Email is required"
        
        if not self.name:
            return False, "Name is required"
        
        if not self.role:
            return False, "Role is required"
        
        # Validate email format
        if not self.EMAIL_REGEX.match(self.email):
            return False, "Invalid email format"
        
        # Validate role
        if self.role not in self.VALID_ROLES:
            return False, f"Role must be one of: {', '.join(self.VALID_ROLES)}"
        
        # Validate student-specific fields
        if self.role == 'student' and not self.student_id:
            return False, "Student ID is required for student role"
        
        return True, None
    
    def to_public_dict(self):
        """
        Convert User object to dictionary with public fields only (no sensitive data)
        
        Returns:
            dict: Public user data
        """
        return {
            'userId': self.user_id,
            'email': self.email,
            'role': self.role,
            'name': self.name,
            'department': self.department,
            'studentId': self.student_id,
            'mfaEnabled': self.mfa_enabled,
            'createdAt': self.created_at.isoformat() if isinstance(self.created_at, datetime) else self.created_at,
            'lastLogin': self.last_login.isoformat() if isinstance(self.last_login, datetime) else self.last_login,
            'isActive': self.is_active
        }


def create_user_document(db, user_id, email, role, name, department=None, student_id=None):
    """
    Create a new user document in Firestore
    
    Args:
        db: Firestore client
        user_id (str): Firebase UID
        email (str): User email
        role (str): User role
        name (str): User name
        department (str, optional): User department
        student_id (str, optional): Student ID
        
    Returns:
        User: Created user object
        
    Raises:
        Exception: If validation fails or creation fails
    """
    # Create user object
    user = User(user_id, email, role, name, department, student_id)
    
    # Validate user data
    is_valid, error_message = user.validate()
    if not is_valid:
        raise Exception(f"User validation failed: {error_message}")
    
    # Check if user already exists
    user_ref = db.collection('users').document(user_id)
    if user_ref.get().exists:
        raise Exception("User already exists")
    
    # Create user document in Firestore
    user_ref.set(user.to_dict())
    
    return user


def get_user_by_id(db, user_id):
    """
    Get user by ID from Firestore
    
    Args:
        db: Firestore client
        user_id (str): User ID
        
    Returns:
        User: User object or None if not found
    """
    user_doc = db.collection('users').document(user_id).get()
    if not user_doc.exists:
        return None
    
    return User.from_dict(user_doc.to_dict())


def get_user_by_email(db, email):
    """
    Get user by email from Firestore
    
    Args:
        db: Firestore client
        email (str): User email
        
    Returns:
        User: User object or None if not found
    """
    users_ref = db.collection('users')
    query = users_ref.where('email', '==', email).limit(1)
    results = query.stream()
    
    for doc in results:
        return User.from_dict(doc.to_dict())
    
    return None


def update_user(db, user_id, update_data):
    """
    Update user document in Firestore
    
    Args:
        db: Firestore client
        user_id (str): User ID
        update_data (dict): Fields to update
        
    Returns:
        bool: True if successful
    """
    user_ref = db.collection('users').document(user_id)
    if not user_ref.get().exists:
        raise Exception("User not found")
    
    user_ref.update(update_data)
    return True
