"""
Enhanced User Model
Defines the comprehensive user data structure with risk profiles,
behavioral baselines, and security attributes for Zero Trust framework
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, validator
from enum import Enum

class UserRole(str, Enum):
    """User role enumeration"""
    STUDENT = "student"
    FACULTY = "faculty"
    SECURITY_OFFICER = "security_officer"
    ADMIN = "admin"

class SecurityClearanceLevel(int, Enum):
    """Security clearance level enumeration"""
    PUBLIC = 1
    INTERNAL = 2
    CONFIDENTIAL = 3
    SECRET = 4
    TOP_SECRET = 5

class RiskLevel(str, Enum):
    """Risk level enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class BehavioralBaseline(BaseModel):
    """User behavioral baseline data"""
    keystroke_dynamics: Dict[str, Any] = Field(default_factory=dict, description="Keystroke timing patterns")
    mouse_movements: Dict[str, Any] = Field(default_factory=dict, description="Mouse movement patterns")
    access_patterns: Dict[str, Any] = Field(default_factory=dict, description="Resource access patterns")
    location_history: List[Dict[str, Any]] = Field(default_factory=list, description="Historical location data")
    session_duration_patterns: Dict[str, Any] = Field(default_factory=dict, description="Session duration patterns")
    device_usage_patterns: Dict[str, Any] = Field(default_factory=dict, description="Device usage patterns")
    
    class Config:
        json_schema_extra = {
            "example": {
                "keystroke_dynamics": {
                    "avg_dwell_time": 120.5,
                    "avg_flight_time": 85.2,
                    "typing_rhythm_variance": 0.15
                },
                "mouse_movements": {
                    "avg_velocity": 250.3,
                    "click_patterns": {"single": 0.8, "double": 0.2},
                    "movement_smoothness": 0.85
                },
                "access_patterns": {
                    "peak_hours": [9, 10, 11, 14, 15, 16],
                    "common_resources": ["library", "lab_a", "classroom_101"],
                    "access_frequency": {"daily": 0.7, "weekly": 0.3}
                }
            }
        }

class RiskProfile(BaseModel):
    """User risk assessment profile"""
    current_score: int = Field(default=0, ge=0, le=100, description="Current risk score (0-100)")
    baseline_established: bool = Field(default=False, description="Whether behavioral baseline is established")
    last_assessment: datetime = Field(default_factory=datetime.utcnow, description="Last risk assessment timestamp")
    risk_factors: List[str] = Field(default_factory=list, description="Current risk factors")
    behavioral_baseline: BehavioralBaseline = Field(default_factory=BehavioralBaseline, description="Behavioral baseline data")
    risk_history: List[Dict[str, Any]] = Field(default_factory=list, description="Historical risk scores")
    anomaly_count: int = Field(default=0, description="Number of detected anomalies")
    trust_score: int = Field(default=100, ge=0, le=100, description="Trust score (inverse of risk)")
    
    @validator('current_score')
    def validate_risk_score(cls, v):
        if not 0 <= v <= 100:
            raise ValueError('Risk score must be between 0 and 100')
        return v
    
    @validator('trust_score')
    def validate_trust_score(cls, v):
        if not 0 <= v <= 100:
            raise ValueError('Trust score must be between 0 and 100')
        return v
    
    def get_risk_level(self) -> RiskLevel:
        """Get risk level based on current score"""
        if self.current_score >= 80:
            return RiskLevel.CRITICAL
        elif self.current_score >= 60:
            return RiskLevel.HIGH
        elif self.current_score >= 30:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    class Config:
        json_schema_extra = {
            "example": {
                "current_score": 25,
                "baseline_established": True,
                "risk_factors": ["unusual_location", "off_hours_access"],
                "anomaly_count": 2,
                "trust_score": 75
            }
        }

class UserPreferences(BaseModel):
    """User preferences and settings"""
    notifications: bool = Field(default=True, description="Enable notifications")
    security_alerts: bool = Field(default=True, description="Enable security alerts")
    data_retention: str = Field(default="standard", description="Data retention preference")
    language: str = Field(default="en", description="Preferred language")
    timezone: str = Field(default="UTC", description="User timezone")
    theme: str = Field(default="light", description="UI theme preference")
    
    class Config:
        json_schema_extra = {
            "example": {
                "notifications": True,
                "security_alerts": True,
                "data_retention": "standard",
                "language": "en",
                "timezone": "America/New_York",
                "theme": "dark"
            }
        }

class DeviceInfo(BaseModel):
    """User device information summary"""
    device_count: int = Field(default=0, description="Number of registered devices")
    trusted_devices: int = Field(default=0, description="Number of trusted devices")
    last_device_registration: Optional[datetime] = Field(default=None, description="Last device registration timestamp")
    device_limit_reached: bool = Field(default=False, description="Whether device limit is reached")

class SecurityMetrics(BaseModel):
    """User security metrics"""
    mfa_enabled: bool = Field(default=False, description="Multi-factor authentication enabled")
    last_password_change: datetime = Field(default_factory=datetime.utcnow, description="Last password change")
    failed_login_attempts: int = Field(default=0, description="Failed login attempts count")
    account_locked: bool = Field(default=False, description="Account lock status")
    last_security_training: Optional[datetime] = Field(default=None, description="Last security training completion")
    security_score: int = Field(default=50, ge=0, le=100, description="Overall security score")
    
    class Config:
        json_schema_extra = {
            "example": {
                "mfa_enabled": True,
                "failed_login_attempts": 0,
                "account_locked": False,
                "security_score": 85
            }
        }

class EnhancedUser(BaseModel):
    """Enhanced user model with comprehensive security and risk management"""
    uid: str = Field(..., description="Unique user identifier")
    email: str = Field(..., description="User email address")
    display_name: str = Field(default="", description="User display name")
    role: UserRole = Field(default=UserRole.STUDENT, description="User role")
    department: str = Field(default="", description="User department")
    security_clearance: SecurityClearanceLevel = Field(default=SecurityClearanceLevel.PUBLIC, description="Security clearance level")
    
    # Status and activity
    is_active: bool = Field(default=True, description="User active status")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Account creation timestamp")
    last_activity: datetime = Field(default_factory=datetime.utcnow, description="Last activity timestamp")
    last_login: Optional[datetime] = Field(default=None, description="Last login timestamp")
    
    # Risk and security profiles
    risk_profile: RiskProfile = Field(default_factory=RiskProfile, description="User risk assessment profile")
    security_metrics: SecurityMetrics = Field(default_factory=SecurityMetrics, description="Security metrics")
    device_info: DeviceInfo = Field(default_factory=DeviceInfo, description="Device information")
    preferences: UserPreferences = Field(default_factory=UserPreferences, description="User preferences")
    
    # Additional metadata
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional user metadata")
    tags: List[str] = Field(default_factory=list, description="User tags for categorization")
    
    @validator('email')
    def validate_email(cls, v):
        if '@' not in v:
            raise ValueError('Invalid email format')
        return v.lower()
    
    @validator('role')
    def validate_role(cls, v):
        if isinstance(v, str):
            try:
                return UserRole(v)
            except ValueError:
                raise ValueError(f'Invalid role: {v}')
        elif isinstance(v, UserRole):
            return v
        else:
            raise ValueError(f'Invalid role type: {type(v)}')
    
    @validator('security_clearance')
    def validate_security_clearance(cls, v):
        if isinstance(v, int):
            try:
                return SecurityClearanceLevel(v)
            except ValueError:
                raise ValueError(f'Invalid security clearance: {v}')
        elif isinstance(v, SecurityClearanceLevel):
            return v
        else:
            raise ValueError(f'Invalid security clearance type: {type(v)}')
    
    def get_role_level(self) -> int:
        """Get numeric role level for hierarchy comparison"""
        role_levels = {
            UserRole.STUDENT: 1,
            UserRole.FACULTY: 2,
            UserRole.SECURITY_OFFICER: 3,
            UserRole.ADMIN: 4
        }
        return role_levels.get(self.role, 1)
    
    def has_role_or_higher(self, required_role: UserRole) -> bool:
        """Check if user has required role or higher"""
        role_levels = {
            UserRole.STUDENT: 1,
            UserRole.FACULTY: 2,
            UserRole.SECURITY_OFFICER: 3,
            UserRole.ADMIN: 4
        }
        return role_levels.get(self.role, 1) >= role_levels.get(required_role, 1)
    
    def has_security_clearance(self, required_level: SecurityClearanceLevel) -> bool:
        """Check if user has required security clearance or higher"""
        return self.security_clearance.value >= required_level.value
    
    def is_high_risk(self, threshold: int = 70) -> bool:
        """Check if user is considered high risk"""
        return self.risk_profile.current_score >= threshold
    
    def is_trusted(self, threshold: int = 80) -> bool:
        """Check if user is considered trusted"""
        return self.risk_profile.trust_score >= threshold
    
    def needs_security_review(self) -> bool:
        """Check if user needs security review"""
        return (
            self.risk_profile.current_score >= 60 or
            self.security_metrics.failed_login_attempts >= 3 or
            self.risk_profile.anomaly_count >= 5 or
            not self.security_metrics.mfa_enabled
        )
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = datetime.utcnow()
    
    def update_risk_score(self, new_score: int, factors: List[str] = None):
        """Update risk score and related metrics"""
        if not 0 <= new_score <= 100:
            raise ValueError("Risk score must be between 0 and 100")
        
        # Store previous score in history
        if self.risk_profile.current_score != new_score:
            self.risk_profile.risk_history.append({
                "timestamp": datetime.utcnow(),
                "previous_score": self.risk_profile.current_score,
                "new_score": new_score,
                "factors": factors or []
            })
        
        self.risk_profile.current_score = new_score
        self.risk_profile.trust_score = max(0, min(100, 100 - new_score))
        self.risk_profile.last_assessment = datetime.utcnow()
        
        if factors:
            self.risk_profile.risk_factors = factors
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Firestore storage"""
        return {
            "uid": self.uid,
            "email": self.email,
            "displayName": self.display_name,
            "role": self.role.value,
            "department": self.department,
            "securityClearance": self.security_clearance.value,
            "isActive": self.is_active,
            "createdAt": self.created_at,
            "lastActivity": self.last_activity,
            "lastLogin": self.last_login,
            "riskProfile": {
                "currentScore": self.risk_profile.current_score,
                "baselineEstablished": self.risk_profile.baseline_established,
                "lastAssessment": self.risk_profile.last_assessment,
                "riskFactors": self.risk_profile.risk_factors,
                "behavioralBaseline": self.risk_profile.behavioral_baseline.dict(),
                "riskHistory": self.risk_profile.risk_history,
                "anomalyCount": self.risk_profile.anomaly_count,
                "trustScore": self.risk_profile.trust_score
            },
            "securityMetrics": self.security_metrics.dict(),
            "deviceInfo": self.device_info.dict(),
            "preferences": self.preferences.dict(),
            "metadata": self.metadata,
            "tags": self.tags
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EnhancedUser':
        """Create EnhancedUser from dictionary"""
        # Handle nested objects
        if 'riskProfile' in data:
            risk_data = data['riskProfile']
            if 'behavioralBaseline' in risk_data:
                risk_data['behavioralBaseline'] = BehavioralBaseline(**risk_data['behavioralBaseline'])
            data['riskProfile'] = RiskProfile(**risk_data)
        
        if 'securityMetrics' in data:
            data['securityMetrics'] = SecurityMetrics(**data['securityMetrics'])
        
        if 'deviceInfo' in data:
            data['deviceInfo'] = DeviceInfo(**data['deviceInfo'])
        
        if 'preferences' in data:
            data['preferences'] = UserPreferences(**data['preferences'])
        
        # Convert string enums back to enum types
        if 'role' in data and isinstance(data['role'], str):
            data['role'] = UserRole(data['role'])
        
        if 'securityClearance' in data and isinstance(data['securityClearance'], int):
            data['securityClearance'] = SecurityClearanceLevel(data['securityClearance'])
        
        return cls(**data)
    
    class Config:
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
        json_schema_extra = {
            "example": {
                "uid": "user123",
                "email": "john.doe@university.edu",
                "display_name": "John Doe",
                "role": "faculty",
                "department": "Computer Science",
                "security_clearance": 3,
                "is_active": True,
                "risk_profile": {
                    "current_score": 25,
                    "baseline_established": True,
                    "risk_factors": ["unusual_location"],
                    "trust_score": 75
                },
                "security_metrics": {
                    "mfa_enabled": True,
                    "failed_login_attempts": 0,
                    "security_score": 85
                }
            }
        }