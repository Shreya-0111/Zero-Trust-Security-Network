"""
Access Request Model
Defines the AccessRequest data structure and validation for Firestore
"""

from datetime import datetime
import uuid


class AccessRequest:
    """Access Request model with schema validation"""
    
    # Valid decision types
    VALID_DECISIONS = ['granted', 'denied', 'pending', 'granted_with_mfa']
    
    # Valid urgency levels
    VALID_URGENCY = ['low', 'medium', 'high']
    
    def __init__(
        self, 
        user_id, 
        user_role, 
        requested_resource, 
        intent, 
        duration, 
        urgency='medium',
        request_id=None
    ):
        """
        Initialize AccessRequest model
        
        Args:
            user_id (str): User ID making the request
            user_role (str): Role of the user
            requested_resource (str): Resource being requested
            intent (str): Intent description (min 20 characters)
            duration (str): Requested duration (e.g., '7 days', '1 month')
            urgency (str): Urgency level (low, medium, high)
            request_id (str, optional): Request ID (auto-generated if not provided)
        """
        self.request_id = request_id or str(uuid.uuid4())
        self.user_id = user_id
        self.user_role = user_role
        self.requested_resource = requested_resource
        self.intent = intent
        self.duration = duration
        self.urgency = urgency
        self.decision = 'pending'
        self.confidence_score = 0
        self.confidence_breakdown = {
            'roleMatch': 0,
            'intentClarity': 0,
            'historicalPattern': 0,
            'contextValidity': 0,
            'anomalyScore': 0
        }
        self.policies_applied = []
        self.timestamp = datetime.utcnow()
        self.ip_address = None
        self.device_info = {}
        self.session_id = None
        self.reviewed_by = None
        self.expires_at = None
        self.denial_reason = None
    
    def to_dict(self):
        """
        Convert AccessRequest object to dictionary for Firestore storage
        
        Returns:
            dict: Access request data as dictionary
        """
        return {
            'requestId': self.request_id,
            'userId': self.user_id,
            'userRole': self.user_role,
            'requestedResource': self.requested_resource,
            'intent': self.intent,
            'duration': self.duration,
            'urgency': self.urgency,
            'decision': self.decision,
            'confidenceScore': self.confidence_score,
            'confidenceBreakdown': self.confidence_breakdown,
            'policiesApplied': self.policies_applied,
            'timestamp': self.timestamp,
            'ipAddress': self.ip_address,
            'deviceInfo': self.device_info,
            'sessionId': self.session_id,
            'reviewedBy': self.reviewed_by,
            'expiresAt': self.expires_at,
            'denialReason': self.denial_reason
        }
    
    @classmethod
    def from_dict(cls, data):
        """
        Create AccessRequest object from dictionary
        
        Args:
            data (dict): Access request data dictionary
            
        Returns:
            AccessRequest: AccessRequest object
        """
        request = cls(
            user_id=data.get('userId'),
            user_role=data.get('userRole'),
            requested_resource=data.get('requestedResource'),
            intent=data.get('intent'),
            duration=data.get('duration'),
            urgency=data.get('urgency', 'medium'),
            request_id=data.get('requestId')
        )
        
        request.decision = data.get('decision', 'pending')
        request.confidence_score = data.get('confidenceScore', 0)
        request.confidence_breakdown = data.get('confidenceBreakdown', {})
        request.policies_applied = data.get('policiesApplied', [])
        request.timestamp = data.get('timestamp', datetime.utcnow())
        request.ip_address = data.get('ipAddress')
        request.device_info = data.get('deviceInfo', {})
        request.session_id = data.get('sessionId')
        request.reviewed_by = data.get('reviewedBy')
        request.expires_at = data.get('expiresAt')
        request.denial_reason = data.get('denialReason')
        
        return request
    
    def validate(self):
        """
        Validate access request data
        
        Returns:
            tuple: (is_valid, error_message)
        """
        # Validate required fields
        if not self.user_id:
            return False, "User ID is required"
        
        if not self.user_role:
            return False, "User role is required"
        
        if not self.requested_resource:
            return False, "Requested resource is required"
        
        if not self.intent:
            return False, "Intent is required"
        
        if not self.duration:
            return False, "Duration is required"
        
        # Validate intent length (minimum 20 characters)
        if len(self.intent.strip()) < 20:
            return False, "Intent must be at least 20 characters"
        
        # Validate intent word count (minimum 5 words)
        word_count = len(self.intent.strip().split())
        if word_count < 5:
            return False, "Intent must contain at least 5 words"
        
        # Validate urgency
        if self.urgency not in self.VALID_URGENCY:
            return False, f"Urgency must be one of: {', '.join(self.VALID_URGENCY)}"
        
        # Validate decision
        if self.decision not in self.VALID_DECISIONS:
            return False, f"Decision must be one of: {', '.join(self.VALID_DECISIONS)}"
        
        return True, None
    
    def set_evaluation_result(self, evaluation_result):
        """
        Set evaluation result from policy engine
        
        Args:
            evaluation_result (dict): Result from policy engine evaluation
        """
        self.decision = evaluation_result.get('decision', 'denied')
        self.confidence_score = evaluation_result.get('confidenceScore', 0)
        self.confidence_breakdown = evaluation_result.get('confidenceBreakdown', {})
        self.policies_applied = evaluation_result.get('policiesApplied', [])
        self.denial_reason = evaluation_result.get('message')


def create_access_request(
    db, 
    user_id, 
    user_role, 
    requested_resource, 
    intent, 
    duration, 
    urgency,
    ip_address,
    device_info,
    session_id=None
):
    """
    Create a new access request document in Firestore
    
    Args:
        db: Firestore client
        user_id (str): User ID
        user_role (str): User role
        requested_resource (str): Resource type
        intent (str): Intent description
        duration (str): Requested duration
        urgency (str): Urgency level
        ip_address (str): Client IP address
        device_info (dict): Device information
        session_id (str, optional): Session ID
        
    Returns:
        AccessRequest: Created access request object
        
    Raises:
        Exception: If validation fails or creation fails
    """
    # Create access request object
    access_request = AccessRequest(
        user_id=user_id,
        user_role=user_role,
        requested_resource=requested_resource,
        intent=intent,
        duration=duration,
        urgency=urgency
    )
    
    # Set metadata
    access_request.ip_address = ip_address
    access_request.device_info = device_info
    access_request.session_id = session_id
    
    # Validate access request data
    is_valid, error_message = access_request.validate()
    if not is_valid:
        raise Exception(f"Access request validation failed: {error_message}")
    
    # Create access request document in Firestore
    request_ref = db.collection('accessRequests').document(access_request.request_id)
    request_ref.set(access_request.to_dict())
    
    return access_request


def get_access_request_by_id(db, request_id):
    """
    Get access request by ID from Firestore
    
    Args:
        db: Firestore client
        request_id (str): Request ID
        
    Returns:
        AccessRequest: AccessRequest object or None if not found
    """
    request_doc = db.collection('accessRequests').document(request_id).get()
    if not request_doc.exists:
        return None
    
    return AccessRequest.from_dict(request_doc.to_dict())


def update_access_request(db, request_id, update_data):
    """
    Update access request document in Firestore
    
    Args:
        db: Firestore client
        request_id (str): Request ID
        update_data (dict): Fields to update
        
    Returns:
        bool: True if successful
    """
    request_ref = db.collection('accessRequests').document(request_id)
    if not request_ref.get().exists:
        raise Exception("Access request not found")
    
    request_ref.update(update_data)
    return True


def get_user_access_requests(db, user_id, limit=50):
    """
    Get user's access requests from Firestore
    
    Args:
        db: Firestore client
        user_id (str): User ID
        limit (int): Maximum number of requests to return
        
    Returns:
        list: List of AccessRequest objects
    """
    requests_ref = db.collection('accessRequests')
    query = requests_ref.where('userId', '==', user_id).order_by('timestamp', direction='DESCENDING').limit(limit)
    
    requests = []
    for doc in query.stream():
        requests.append(AccessRequest.from_dict(doc.to_dict()))
    
    return requests
