"""
Device Fingerprint Data Model
Defines the structure for device fingerprint storage and validation
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, validator
from enum import Enum

class FingerprintStability(str, Enum):
    """Stability levels for fingerprint components"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class CanvasFingerprint(BaseModel):
    """Canvas fingerprint component"""
    hash: str = Field(..., description="SHA-256 hash of canvas rendering")
    confidence: float = Field(..., ge=0, le=100, description="Confidence level of canvas fingerprint")
    dataLength: Optional[int] = Field(None, description="Length of canvas data")

class WebGLFingerprint(BaseModel):
    """WebGL fingerprint component"""
    renderer: str = Field(..., description="WebGL renderer information")
    vendor: str = Field(..., description="WebGL vendor information")
    version: str = Field(..., description="WebGL version")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Additional WebGL parameters")

class AudioFingerprint(BaseModel):
    """Audio fingerprint component"""
    hash: str = Field(..., description="SHA-256 hash of audio processing")
    sampleRate: int = Field(..., description="Audio sample rate")
    bufferSize: int = Field(..., description="Audio buffer size")
    sum: Optional[float] = Field(None, description="Audio processing sum for validation")

class ScreenFingerprint(BaseModel):
    """Screen characteristics"""
    width: int = Field(..., description="Screen width in pixels")
    height: int = Field(..., description="Screen height in pixels")
    colorDepth: int = Field(..., description="Screen color depth")
    pixelRatio: float = Field(..., description="Device pixel ratio")
    availWidth: Optional[int] = Field(None, description="Available screen width")
    availHeight: Optional[int] = Field(None, description="Available screen height")

class SystemFingerprint(BaseModel):
    """System characteristics"""
    platform: str = Field(..., description="Operating system platform")
    userAgent: str = Field(..., description="Browser user agent string")
    language: str = Field(..., description="Browser language")
    languages: Optional[List[str]] = Field(None, description="Supported languages")
    timezone: str = Field(..., description="System timezone")
    hardwareConcurrency: int = Field(..., description="Number of CPU cores")
    deviceMemory: Optional[int] = Field(None, description="Device memory in GB")
    cookieEnabled: Optional[bool] = Field(None, description="Cookie support enabled")
    doNotTrack: Optional[str] = Field(None, description="Do not track setting")
    maxTouchPoints: Optional[int] = Field(None, description="Maximum touch points")

class PluginInfo(BaseModel):
    """Browser plugin information"""
    name: str = Field(..., description="Plugin name")
    filename: str = Field(..., description="Plugin filename")
    description: str = Field(..., description="Plugin description")

class DeviceCharacteristics(BaseModel):
    """Complete device fingerprint characteristics"""
    canvas: CanvasFingerprint
    webgl: WebGLFingerprint
    audio: AudioFingerprint
    screen: ScreenFingerprint
    system: SystemFingerprint
    fonts: List[str] = Field(default_factory=list, description="Available fonts")
    plugins: List[PluginInfo] = Field(default_factory=list, description="Browser plugins")
    overallHash: Optional[str] = Field(None, description="Overall fingerprint hash")
    timestamp: Optional[str] = Field(None, description="Collection timestamp")
    collectionTime: Optional[int] = Field(None, description="Collection time in milliseconds")
    deviceName: Optional[str] = Field(None, description="User-assigned device name")

    @validator('fonts')
    def validate_fonts(cls, v):
        """Validate fonts list"""
        if len(v) > 100:  # Reasonable limit
            return v[:100]
        return v

    @validator('plugins')
    def validate_plugins(cls, v):
        """Validate plugins list"""
        if len(v) > 50:  # Reasonable limit
            return v[:50]
        return v

class VerificationResult(BaseModel):
    """Device fingerprint verification result"""
    timestamp: datetime
    similarity: float = Field(..., ge=0, le=100)
    result: str = Field(..., pattern="^(success|partial|failed)$")
    deviceInfo: Optional[Dict[str, Any]] = Field(None)

class DeviceFingerprint(BaseModel):
    """Device fingerprint storage model"""
    deviceId: str = Field(..., description="Unique device identifier")
    userId: str = Field(..., description="Associated user ID")
    fingerprintHash: str = Field(..., description="SHA-256 hash of fingerprint")
    characteristics: str = Field(..., description="Encrypted characteristics data")
    trustScore: float = Field(default=100, ge=0, le=100, description="Device trust score")
    registeredAt: datetime = Field(default_factory=datetime.utcnow)
    lastVerified: datetime = Field(default_factory=datetime.utcnow)
    verificationHistory: List[VerificationResult] = Field(default_factory=list)
    isApproved: bool = Field(default=True)
    approvedBy: Optional[str] = Field(None, description="Admin who approved device")
    deviceName: str = Field(default="Unknown Device")
    isActive: bool = Field(default=True)
    deactivatedAt: Optional[datetime] = Field(None)
    deactivatedBy: Optional[str] = Field(None)

    class Config:
        """Pydantic configuration"""
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class DeviceRegistrationRequest(BaseModel):
    """Device registration request model"""
    userId: str = Field(..., description="User ID for device registration")
    fingerprintData: DeviceCharacteristics = Field(..., description="Device fingerprint data")
    deviceName: Optional[str] = Field("Unknown Device", description="User-assigned device name")

class DeviceValidationRequest(BaseModel):
    """Device validation request model"""
    userId: str = Field(..., description="User ID for validation")
    currentFingerprint: DeviceCharacteristics = Field(..., description="Current device fingerprint")

class DeviceRegistrationResponse(BaseModel):
    """Device registration response model"""
    success: bool
    deviceId: Optional[str] = None
    trustScore: Optional[float] = None
    message: str
    error: Optional[str] = None
    requires_mfa: Optional[bool] = None

class DeviceValidationResponse(BaseModel):
    """Device validation response model"""
    success: bool
    approved: Optional[bool] = None
    similarity: float = Field(default=0, ge=0, le=100)
    deviceId: Optional[str] = None
    trustScore: Optional[float] = None
    message: str
    error: Optional[str] = None
    requires_additional_verification: Optional[bool] = None
    requires_reregistration: Optional[bool] = None

class DeviceListResponse(BaseModel):
    """Device list response model"""
    success: bool
    devices: List[Dict[str, Any]] = Field(default_factory=list)
    totalCount: int = Field(default=0)
    error: Optional[str] = None

class DeviceStatistics(BaseModel):
    """Device fingerprint statistics model"""
    totalDevices: int = Field(default=0)
    activeDevices: int = Field(default=0)
    inactiveDevices: int = Field(default=0)
    trustScoreDistribution: Dict[str, int] = Field(default_factory=dict)
    recentRegistrations: int = Field(default=0)

class DeviceAnomalyReport(BaseModel):
    """Device fingerprint anomaly report"""
    deviceId: str
    userId: str
    anomalies: List[str] = Field(default_factory=list)
    severity: str = Field(default="low", pattern="^(low|medium|high|critical)$")
    detectedAt: datetime = Field(default_factory=datetime.utcnow)
    resolved: bool = Field(default=False)
    resolvedAt: Optional[datetime] = None
    resolvedBy: Optional[str] = None

# Component weight configuration for similarity calculation
FINGERPRINT_COMPONENT_WEIGHTS = {
    "canvas": {"weight": 0.25, "stability": FingerprintStability.HIGH},
    "webgl": {"weight": 0.25, "stability": FingerprintStability.HIGH},
    "audio": {"weight": 0.20, "stability": FingerprintStability.MEDIUM},
    "screen": {"weight": 0.15, "stability": FingerprintStability.LOW},
    "system": {"weight": 0.15, "stability": FingerprintStability.MEDIUM}
}

# Validation thresholds
FINGERPRINT_VALIDATION_THRESHOLDS = {
    "auto_approve": 95.0,
    "additional_verification": 85.0,
    "deny": 85.0
}

# Trust score adjustment values
TRUST_SCORE_ADJUSTMENTS = {
    "successful_validation": 5,
    "failed_validation": -10,
    "anomaly_detected": -15,
    "security_incident": -25,
    "max_trust": 100,
    "min_trust": 0
}