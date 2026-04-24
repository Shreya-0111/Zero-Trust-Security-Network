"""
Visitor Model

Defines the data structure for visitor management including registration,
session tracking, route compliance, and credential management.
"""

from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field, validator
import uuid


class VisitorCredentials(BaseModel):
    """Visitor access credentials"""
    temporary_password: str = Field(..., description="Encrypted temporary password")
    qr_code: str = Field(..., description="Base64 encoded QR code")
    access_token: str = Field(..., description="JWT access token")


class AssignedRoute(BaseModel):
    """Visitor route assignment"""
    allowed_segments: List[str] = Field(default_factory=list, description="Allowed resource segment IDs")
    restricted_areas: List[str] = Field(default_factory=list, description="Restricted segment IDs")
    route_description: str = Field(default="", description="Route instructions")


class AccessLogEntry(BaseModel):
    """Individual access log entry"""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    resource_segment: str = Field(..., description="Resource segment accessed")
    action: str = Field(..., description="Action performed")
    approved: bool = Field(..., description="Whether access was approved")
    risk_score: Optional[float] = Field(None, description="Risk score at time of access")


class RouteCompliance(BaseModel):
    """Route compliance tracking"""
    compliance_score: float = Field(default=100.0, description="Compliance score (0-100)")
    deviations: List[Dict[str, Any]] = Field(default_factory=list, description="Route deviation events")
    last_compliance_check: datetime = Field(default_factory=datetime.utcnow)


class SessionExtension(BaseModel):
    """Session extension record"""
    requested_by: str = Field(..., description="Host ID who requested extension")
    approved_by: str = Field(..., description="Admin ID who approved extension")
    additional_hours: int = Field(..., description="Additional hours granted")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    reason: str = Field(..., description="Reason for extension")


class Visitor(BaseModel):
    """
    Visitor Model
    
    Represents a temporary visitor with limited access requiring host sponsorship.
    Includes comprehensive tracking of access patterns, route compliance, and session management.
    """
    
    # Core identification
    visitor_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique visitor identifier")
    name: str = Field(..., min_length=1, max_length=100, description="Visitor's full name")
    email: Optional[str] = Field(None, description="Visitor's email address")
    phone: str = Field(..., description="Visitor's phone number")
    photo: str = Field(..., description="Cloud Storage URL for visitor photo")
    
    # Host relationship
    host_id: str = Field(..., description="Faculty/admin user ID who sponsors the visitor")
    host_name: str = Field(..., description="Host's full name")
    host_department: str = Field(..., description="Host's department")
    
    # Visit details
    visit_purpose: str = Field(..., min_length=10, description="Detailed purpose of visit")
    entry_time: datetime = Field(default_factory=datetime.utcnow, description="Actual entry time")
    expected_exit_time: datetime = Field(..., description="Expected exit time")
    actual_exit_time: Optional[datetime] = Field(None, description="Actual exit time")
    max_duration: int = Field(default=8, ge=1, le=8, description="Maximum duration in hours")
    
    # Route and access control
    assigned_route: AssignedRoute = Field(default_factory=AssignedRoute, description="Assigned access route")
    access_log: List[AccessLogEntry] = Field(default_factory=list, description="Access activity log")
    route_compliance: RouteCompliance = Field(default_factory=RouteCompliance, description="Route compliance tracking")
    
    # Status and management
    status: str = Field(default="active", description="Visitor status")
    alerts: List[str] = Field(default_factory=list, description="Alert IDs associated with visitor")
    session_extensions: List[SessionExtension] = Field(default_factory=list, description="Session extension history")
    
    # Security credentials
    credentials: VisitorCredentials = Field(..., description="Visitor access credentials")
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    @validator('status')
    def validate_status(cls, v):
        """Validate visitor status"""
        allowed_statuses = ['active', 'completed', 'expired', 'terminated']
        if v not in allowed_statuses:
            raise ValueError(f'Status must be one of: {allowed_statuses}')
        return v
    
    @validator('expected_exit_time')
    def validate_exit_time(cls, v, values):
        """Validate that exit time is after entry time and within max duration"""
        if 'entry_time' in values and 'max_duration' in values:
            entry_time = values['entry_time']
            max_duration = values['max_duration']
            
            if v <= entry_time:
                raise ValueError('Expected exit time must be after entry time')
            
            max_exit_time = entry_time + timedelta(hours=max_duration)
            if v > max_exit_time:
                raise ValueError(f'Expected exit time cannot exceed {max_duration} hours from entry')
        
        return v
    
    @validator('phone')
    def validate_phone(cls, v):
        """Basic phone number validation"""
        import re
        # Allow various phone number formats
        phone_pattern = r'^\+?[\d\s\-\(\)]+$'
        if not re.match(phone_pattern, v):
            raise ValueError('Invalid phone number format')
        return v
    
    def is_session_active(self) -> bool:
        """Check if visitor session is currently active"""
        now = datetime.utcnow()
        
        # Ensure all datetimes are timezone-naive for comparison
        entry_time = self.entry_time
        if hasattr(entry_time, 'replace') and entry_time.tzinfo is not None:
            entry_time = entry_time.replace(tzinfo=None)
        
        expected_exit_time = self.expected_exit_time
        if hasattr(expected_exit_time, 'replace') and expected_exit_time.tzinfo is not None:
            expected_exit_time = expected_exit_time.replace(tzinfo=None)
        
        return (
            self.status == 'active' and
            now >= entry_time and
            now <= expected_exit_time
        )
    
    def is_session_expired(self) -> bool:
        """Check if visitor session has expired"""
        now = datetime.utcnow()
        
        # Ensure expected_exit_time is timezone-naive for comparison
        expected_exit_time = self.expected_exit_time
        if hasattr(expected_exit_time, 'replace') and expected_exit_time.tzinfo is not None:
            expected_exit_time = expected_exit_time.replace(tzinfo=None)
        
        return now > expected_exit_time
    
    def get_remaining_time(self) -> timedelta:
        """Get remaining time in the session"""
        if self.is_session_expired():
            return timedelta(0)
        
        now = datetime.utcnow()
        expected_exit_time = self.expected_exit_time
        if hasattr(expected_exit_time, 'replace') and expected_exit_time.tzinfo is not None:
            expected_exit_time = expected_exit_time.replace(tzinfo=None)
        
        return expected_exit_time - now
    
    def calculate_compliance_score(self) -> float:
        """Calculate route compliance score based on access log"""
        if not self.access_log:
            return 100.0
        
        total_accesses = len(self.access_log)
        compliant_accesses = sum(
            1 for entry in self.access_log
            if entry.resource_segment in self.assigned_route.allowed_segments
        )
        
        return (compliant_accesses / total_accesses) * 100.0
    
    def add_access_log_entry(self, resource_segment: str, action: str, approved: bool, risk_score: Optional[float] = None):
        """Add new access log entry"""
        entry = AccessLogEntry(
            resource_segment=resource_segment,
            action=action,
            approved=approved,
            risk_score=risk_score
        )
        self.access_log.append(entry)
        
        # Update compliance score
        self.route_compliance.compliance_score = self.calculate_compliance_score()
        self.route_compliance.last_compliance_check = datetime.utcnow()
        
        # Check for route deviation
        if resource_segment not in self.assigned_route.allowed_segments:
            deviation = {
                "timestamp": datetime.utcnow().isoformat(),
                "resource_segment": resource_segment,
                "action": action,
                "severity": "high" if resource_segment in self.assigned_route.restricted_areas else "medium"
            }
            self.route_compliance.deviations.append(deviation)
        
        self.updated_at = datetime.utcnow()
    
    def extend_session(self, additional_hours: int, requested_by: str, approved_by: str, reason: str):
        """Extend visitor session with approval"""
        if additional_hours <= 0 or additional_hours > 4:
            raise ValueError("Session extension must be between 1 and 4 hours")
        
        # Check if total duration would exceed 8 hours
        current_duration = (self.expected_exit_time - self.entry_time).total_seconds() / 3600
        if current_duration + additional_hours > 8:
            raise ValueError("Total session duration cannot exceed 8 hours")
        
        # Record extension
        extension = SessionExtension(
            requested_by=requested_by,
            approved_by=approved_by,
            additional_hours=additional_hours,
            reason=reason
        )
        self.session_extensions.append(extension)
        
        # Update expected exit time
        self.expected_exit_time += timedelta(hours=additional_hours)
        self.updated_at = datetime.utcnow()
    
    def terminate_session(self, reason: str = "Manual termination"):
        """Terminate visitor session"""
        self.status = "terminated"
        self.actual_exit_time = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        
        # Add termination to access log
        self.add_access_log_entry(
            resource_segment="system",
            action=f"session_terminated: {reason}",
            approved=True
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert visitor to dictionary for API responses"""
        return {
            "visitorId": self.visitor_id,
            "name": self.name,
            "email": self.email,
            "phone": self.phone,
            "photo": self.photo,
            "hostId": self.host_id,
            "hostName": self.host_name,
            "hostDepartment": self.host_department,
            "visitPurpose": self.visit_purpose,
            "entryTime": self.entry_time.isoformat(),
            "expectedExitTime": self.expected_exit_time.isoformat(),
            "actualExitTime": self.actual_exit_time.isoformat() if self.actual_exit_time else None,
            "maxDuration": self.max_duration,
            "assignedRoute": self.assigned_route.dict(),
            "accessLog": [entry.dict() for entry in self.access_log],
            "routeCompliance": self.route_compliance.dict(),
            "status": self.status,
            "alerts": self.alerts,
            "sessionExtensions": [ext.dict() for ext in self.session_extensions],
            "credentials": self.credentials.dict(),
            "createdAt": self.created_at.isoformat(),
            "updatedAt": self.updated_at.isoformat(),
            "isActive": self.is_session_active(),
            "isExpired": self.is_session_expired(),
            "remainingTime": str(self.get_remaining_time()) if not self.is_session_expired() else "0:00:00"
        }


class VisitorRegistrationRequest(BaseModel):
    """Request model for visitor registration"""
    name: str = Field(..., min_length=1, max_length=100)
    email: Optional[str] = Field(None)
    phone: str = Field(...)
    visit_purpose: str = Field(..., min_length=10)
    expected_duration: int = Field(..., ge=1, le=8, description="Duration in hours")
    assigned_route: AssignedRoute = Field(...)
    host_id: str = Field(...)
    host_name: str = Field(...)
    host_department: str = Field(...)
    
    @validator('phone')
    def validate_phone(cls, v):
        """Basic phone number validation"""
        import re
        phone_pattern = r'^\+?[\d\s\-\(\)]+$'
        if not re.match(phone_pattern, v):
            raise ValueError('Invalid phone number format')
        return v


class VisitorUpdateRequest(BaseModel):
    """Request model for visitor updates"""
    visit_purpose: Optional[str] = Field(None, min_length=10)
    assigned_route: Optional[AssignedRoute] = Field(None)
    status: Optional[str] = Field(None)
    
    @validator('status')
    def validate_status(cls, v):
        """Validate visitor status"""
        if v is not None:
            allowed_statuses = ['active', 'completed', 'expired', 'terminated']
            if v not in allowed_statuses:
                raise ValueError(f'Status must be one of: {allowed_statuses}')
        return v