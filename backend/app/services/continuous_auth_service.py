"""
Continuous Authentication Service
Implements real-time session validation with device fingerprint consistency,
location stability, access pattern analysis, and behavioral baseline establishment.
"""

import hashlib
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from firebase_admin import firestore
from app.firebase_config import db
from app.services.device_fingerprint_service import DeviceFingerprintService
from app.services.audit_logger import log_audit_event
from app.models.notification import create_notification
from app.utils.error_handler import handle_service_error

logger = logging.getLogger(__name__)

@dataclass
class RiskFactors:
    """Data class for risk calculation factors"""
    device_consistency: float = 0.0
    location_stability: float = 0.0
    access_patterns: float = 0.0
    time_appropriateness: float = 0.0
    request_frequency: float = 0.0

@dataclass
class SessionData:
    """Data class for session information"""
    session_id: str
    user_id: str
    device_id: str
    start_time: datetime
    last_activity: datetime
    ip_address: str
    user_agent: str
    device_fingerprint: Dict
    access_log: List[Dict]
    location_history: List[Dict]
    behavioral_data: Dict

class ContinuousAuthService:
    """Service for continuous session monitoring and risk assessment"""
    
    def __init__(self):
        self.db = db
        self.device_service = DeviceFingerprintService()
        
        # Risk calculation weights (must sum to 1.0)
        self.risk_weights = {
            "device_consistency": 0.25,
            "location_stability": 0.20,
            "access_patterns": 0.20,
            "time_appropriateness": 0.15,
            "request_frequency": 0.20
        }
        
        # Risk thresholds
        self.risk_thresholds = {
            "mfa_required": 70,
            "session_termination": 85
        }
        
        # Behavioral baseline parameters
        self.baseline_window_days = 30
        self.min_sessions_for_baseline = 5
    
    @handle_service_error
    def monitor_user_session(self, session_id: str) -> Dict:
        """
        Continuously evaluate session authenticity and calculate risk score
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session monitoring result with risk assessment
        """
        try:
            # Get session data
            session_data = self._get_session_data(session_id)
            if not session_data:
                return {
                    "success": False,
                    "error": "SESSION_NOT_FOUND",
                    "message": "Session not found"
                }
            
            # Calculate dynamic risk score
            risk_assessment = self.calculate_dynamic_risk_score(session_data)
            
            # Update session with current risk score
            self._update_session_risk(session_id, risk_assessment)
            
            # Determine required action based on risk score
            action = self._determine_action(risk_assessment["risk_score"])
            
            # Log monitoring event
            log_audit_event(
                user_id=session_data.user_id,
                action="continuous_auth_monitoring",
                resource_type="session",
                resource_id=session_id,
                details={
                    "risk_score": risk_assessment["risk_score"],
                    "risk_factors": risk_assessment["risk_factors"].__dict__,
                    "action_required": action,
                    "baseline_available": risk_assessment["baseline_available"]
                }
            )
            
            return {
                "success": True,
                "session_id": session_id,
                "risk_score": risk_assessment["risk_score"],
                "risk_factors": risk_assessment["risk_factors"].__dict__,
                "action_required": action,
                "baseline_available": risk_assessment["baseline_available"],
                "message": f"Session monitoring completed - {action}"
            }
            
        except Exception as e:
            logger.error(f"Error monitoring session {session_id}: {str(e)}")
            raise
    
    @handle_service_error
    def calculate_dynamic_risk_score(self, session_data: SessionData) -> Dict:
        """
        Calculate real-time risk assessment using weighted factors
        
        Args:
            session_data: Current session information
            
        Returns:
            Risk assessment with detailed factor breakdown
        """
        try:
            # Calculate individual risk factors
            risk_factors = RiskFactors()
            
            # 1. Device consistency (25%)
            risk_factors.device_consistency = self._calculate_device_consistency_risk(
                session_data.user_id, 
                session_data.device_fingerprint
            )
            
            # 2. Location stability (20%)
            risk_factors.location_stability = self._calculate_location_stability_risk(
                session_data.user_id,
                session_data.ip_address,
                session_data.location_history
            )
            
            # 3. Access patterns (20%)
            risk_factors.access_patterns = self._calculate_access_pattern_risk(
                session_data.user_id,
                session_data.access_log
            )
            
            # 4. Time appropriateness (15%)
            risk_factors.time_appropriateness = self._calculate_time_appropriateness_risk(
                session_data.user_id,
                datetime.utcnow()
            )
            
            # 5. Request frequency (20%)
            risk_factors.request_frequency = self._calculate_request_frequency_risk(
                session_data.access_log
            )
            
            # Calculate weighted risk score
            risk_score = (
                risk_factors.device_consistency * self.risk_weights["device_consistency"] +
                risk_factors.location_stability * self.risk_weights["location_stability"] +
                risk_factors.access_patterns * self.risk_weights["access_patterns"] +
                risk_factors.time_appropriateness * self.risk_weights["time_appropriateness"] +
                risk_factors.request_frequency * self.risk_weights["request_frequency"]
            )
            
            # Ensure risk score is within bounds
            risk_score = max(0, min(100, risk_score))
            
            # Check if behavioral baseline is available
            baseline_available = self._has_behavioral_baseline(session_data.user_id)
            
            logger.info(f"Risk score calculated for session {session_data.session_id}: {risk_score}")
            
            return {
                "risk_score": risk_score,
                "risk_factors": risk_factors,
                "baseline_available": baseline_available,
                "calculation_timestamp": datetime.utcnow()
            }
            
        except Exception as e:
            logger.error(f"Error calculating risk score: {str(e)}")
            raise
    
    @handle_service_error
    def validate_behavioral_patterns(self, user_id: str, current_behavior: Dict) -> Dict:
        """
        Compare current behavior against user baseline
        
        Args:
            user_id: User identifier
            current_behavior: Current behavioral data
            
        Returns:
            Behavioral validation result
        """
        try:
            # Get user's behavioral baseline
            baseline = self._get_behavioral_baseline(user_id)
            
            if not baseline:
                return {
                    "success": False,
                    "error": "NO_BASELINE",
                    "message": "Behavioral baseline not established",
                    "deviation_score": 0
                }
            
            # Calculate deviation from baseline
            deviation_score = self._calculate_behavioral_deviation(current_behavior, baseline)
            
            # Determine if behavior is anomalous
            is_anomalous = deviation_score > 70  # 70% deviation threshold
            
            return {
                "success": True,
                "deviation_score": deviation_score,
                "is_anomalous": is_anomalous,
                "baseline_available": True,
                "message": "Behavioral validation completed"
            }
            
        except Exception as e:
            logger.error(f"Error validating behavioral patterns: {str(e)}")
            raise
    
    @handle_service_error
    def detect_session_anomalies(self, session_data: SessionData) -> List[Dict]:
        """
        Identify suspicious session characteristics
        
        Args:
            session_data: Session information
            
        Returns:
            List of detected anomalies
        """
        anomalies = []
        
        try:
            # Check for rapid location changes
            if len(session_data.location_history) >= 2:
                recent_locations = session_data.location_history[-2:]
                if self._detect_impossible_travel(recent_locations):
                    anomalies.append({
                        "type": "impossible_travel",
                        "severity": "high",
                        "description": "Impossible travel detected between locations",
                        "timestamp": datetime.utcnow()
                    })
            
            # Check for unusual access patterns
            if session_data.access_log:
                access_velocity = len(session_data.access_log) / max(1, 
                    (datetime.utcnow() - session_data.start_time).total_seconds() / 60)
                
                if access_velocity > 10:  # More than 10 requests per minute
                    anomalies.append({
                        "type": "high_request_velocity",
                        "severity": "medium",
                        "description": f"Unusually high request rate: {access_velocity:.1f}/min",
                        "timestamp": datetime.utcnow()
                    })
            
            # Check for device fingerprint inconsistencies
            device_validation = self.device_service.validate_fingerprint(
                session_data.user_id, 
                session_data.device_fingerprint
            )
            
            if not device_validation.get("success") or device_validation.get("similarity", 0) < 85:
                anomalies.append({
                    "type": "device_fingerprint_mismatch",
                    "severity": "high",
                    "description": f"Device fingerprint similarity: {device_validation.get('similarity', 0)}%",
                    "timestamp": datetime.utcnow()
                })
            
            # Check for off-hours access
            current_hour = datetime.utcnow().hour
            if current_hour < 6 or current_hour > 22:  # Outside 6 AM - 10 PM
                user_history = self._get_user_access_history(session_data.user_id)
                typical_hours = self._get_typical_access_hours(user_history)
                
                if current_hour not in typical_hours:
                    anomalies.append({
                        "type": "unusual_access_time",
                        "severity": "low",
                        "description": f"Access at unusual hour: {current_hour}:00",
                        "timestamp": datetime.utcnow()
                    })
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting session anomalies: {str(e)}")
            return [{
                "type": "detection_error",
                "severity": "low",
                "description": f"Error during anomaly detection: {str(e)}",
                "timestamp": datetime.utcnow()
            }]
    
    @handle_service_error
    def trigger_reauthentication(self, session_id: str, risk_level: str) -> Dict:
        """
        Initiate additional verification for high-risk sessions
        
        Args:
            session_id: Session identifier
            risk_level: Risk level (medium, high, critical)
            
        Returns:
            Re-authentication trigger result
        """
        try:
            session_data = self._get_session_data(session_id)
            if not session_data:
                return {
                    "success": False,
                    "error": "SESSION_NOT_FOUND",
                    "message": "Session not found"
                }
            
            # Create re-authentication challenge
            challenge_id = f"reauth_{session_id}_{int(datetime.utcnow().timestamp())}"
            challenge_data = {
                "challenge_id": challenge_id,
                "session_id": session_id,
                "user_id": session_data.user_id,
                "risk_level": risk_level,
                "challenge_type": "mfa",  # Could be mfa, biometric, security_questions
                "created_at": datetime.utcnow(),
                "expires_at": datetime.utcnow() + timedelta(minutes=5),
                "status": "pending",
                "reason": f"High risk detected (level: {risk_level})"
            }
            
            # Store challenge
            self.db.collection('reauthentication_challenges').document(challenge_id).set(challenge_data)
            
            # Send notification to user
            create_notification(
                user_id=session_data.user_id,
                title="Re-authentication Required",
                message=f"Additional verification required due to {risk_level} risk level",
                notification_type="security_alert",
                priority="high" if risk_level == "critical" else "medium"
            )
            
            # Send WebSocket notification
            from websocket_config import emit_reauthentication_required
            emit_reauthentication_required(session_data.user_id, challenge_data)
            
            # Log re-authentication trigger
            log_audit_event(
                user_id=session_data.user_id,
                action="reauthentication_triggered",
                resource_type="session",
                resource_id=session_id,
                details={
                    "challenge_id": challenge_id,
                    "risk_level": risk_level,
                    "challenge_type": "mfa"
                },
                severity="medium"
            )
            
            return {
                "success": True,
                "challenge_id": challenge_id,
                "challenge_type": "mfa",
                "expires_at": challenge_data["expires_at"],
                "message": "Re-authentication challenge created"
            }
            
        except Exception as e:
            logger.error(f"Error triggering re-authentication: {str(e)}")
            raise
    
    @handle_service_error
    def terminate_suspicious_session(self, session_id: str, reason: str) -> Dict:
        """
        Immediately end high-risk sessions
        
        Args:
            session_id: Session identifier
            reason: Termination reason
            
        Returns:
            Session termination result
        """
        try:
            session_data = self._get_session_data(session_id)
            if not session_data:
                return {
                    "success": False,
                    "error": "SESSION_NOT_FOUND",
                    "message": "Session not found"
                }
            
            # Update session status
            session_ref = self.db.collection('continuousAuthSessions').document(session_id)
            session_ref.update({
                "status": "terminated",
                "termination_reason": reason,
                "terminated_by": "system",
                "terminated_at": datetime.utcnow()
            })
            
            # Send immediate notification to user
            create_notification(
                user_id=session_data.user_id,
                title="Session Terminated",
                message=f"Your session was terminated due to security concerns: {reason}",
                notification_type="security_alert",
                priority="high"
            )
            
            # Send alert to administrators
            self._send_admin_alert(session_data.user_id, session_id, reason)
            
            # Log termination
            log_audit_event(
                user_id=session_data.user_id,
                action="session_terminated_risk",
                resource_type="session",
                resource_id=session_id,
                details={
                    "termination_reason": reason,
                    "terminated_by": "system"
                },
                severity="high"
            )
            
            logger.warning(f"Session {session_id} terminated for user {session_data.user_id}: {reason}")
            
            return {
                "success": True,
                "session_id": session_id,
                "termination_reason": reason,
                "message": "Session terminated successfully"
            }
            
        except Exception as e:
            logger.error(f"Error terminating session: {str(e)}")
            raise
    
    def _get_session_data(self, session_id: str) -> Optional[SessionData]:
        """Get session data from Firestore"""
        try:
            session_ref = self.db.collection('continuousAuthSessions').document(session_id)
            session_doc = session_ref.get()
            
            if not session_doc.exists:
                return None
            
            data = session_doc.to_dict()
            return SessionData(
                session_id=session_id,
                user_id=data.get("userId", ""),
                device_id=data.get("deviceId", ""),
                start_time=data.get("startTime", datetime.utcnow()),
                last_activity=data.get("lastActivity", datetime.utcnow()),
                ip_address=data.get("ipAddress", ""),
                user_agent=data.get("userAgent", ""),
                device_fingerprint=data.get("deviceFingerprint", {}),
                access_log=data.get("accessLog", []),
                location_history=data.get("locationHistory", []),
                behavioral_data=data.get("behavioralData", {})
            )
            
        except Exception as e:
            logger.error(f"Error getting session data: {str(e)}")
            return None
    
    def _calculate_device_consistency_risk(self, user_id: str, current_fingerprint: Dict) -> float:
        """Calculate risk based on device fingerprint consistency"""
        try:
            validation_result = self.device_service.validate_fingerprint(user_id, current_fingerprint)
            
            if not validation_result.get("success"):
                return 100.0  # Maximum risk for unrecognized device
            
            similarity = validation_result.get("similarity", 0)
            
            # Convert similarity to risk (inverse relationship)
            if similarity >= 95:
                return 0.0  # No risk for perfect match
            elif similarity >= 85:
                return 25.0  # Low risk for good match
            elif similarity >= 70:
                return 50.0  # Medium risk for partial match
            else:
                return 100.0  # High risk for poor match
                
        except Exception as e:
            logger.error(f"Error calculating device consistency risk: {str(e)}")
            return 50.0  # Default medium risk on error
    
    def _calculate_location_stability_risk(self, user_id: str, current_ip: str, location_history: List[Dict]) -> float:
        """Calculate risk based on location stability"""
        try:
            # Get user's typical locations
            user_locations = self._get_user_typical_locations(user_id)
            
            # Check if current IP is in typical locations
            if current_ip in [loc.get("ip_address") for loc in user_locations]:
                return 0.0  # No risk for known location
            
            # Check for rapid location changes
            if len(location_history) >= 2:
                if self._detect_impossible_travel(location_history[-2:]):
                    return 100.0  # Maximum risk for impossible travel
            
            # Check geographic distance from typical locations
            if user_locations:
                min_distance = self._calculate_min_geographic_distance(current_ip, user_locations)
                
                if min_distance < 50:  # Within 50km
                    return 10.0
                elif min_distance < 200:  # Within 200km
                    return 30.0
                elif min_distance < 1000:  # Within 1000km
                    return 60.0
                else:
                    return 90.0  # Very far from typical locations
            
            return 40.0  # Default medium risk for new users
            
        except Exception as e:
            logger.error(f"Error calculating location stability risk: {str(e)}")
            return 50.0
    
    def _calculate_access_pattern_risk(self, user_id: str, access_log: List[Dict]) -> float:
        """Calculate risk based on access pattern analysis"""
        try:
            # Get user's typical access patterns
            typical_patterns = self._get_user_access_patterns(user_id)
            
            if not typical_patterns or not access_log:
                return 30.0  # Default risk for insufficient data
            
            # Analyze current session patterns
            current_patterns = self._analyze_current_access_patterns(access_log)
            
            # Compare against typical patterns
            pattern_deviation = self._calculate_pattern_deviation(current_patterns, typical_patterns)
            
            # Convert deviation to risk score
            if pattern_deviation < 20:
                return 0.0
            elif pattern_deviation < 40:
                return 25.0
            elif pattern_deviation < 60:
                return 50.0
            elif pattern_deviation < 80:
                return 75.0
            else:
                return 100.0
                
        except Exception as e:
            logger.error(f"Error calculating access pattern risk: {str(e)}")
            return 50.0
    
    def _calculate_time_appropriateness_risk(self, user_id: str, current_time: datetime) -> float:
        """Calculate risk based on time-of-day appropriateness"""
        try:
            # Get user's typical access hours
            typical_hours = self._get_user_typical_hours(user_id)
            
            current_hour = current_time.hour
            current_day = current_time.weekday()  # 0=Monday, 6=Sunday
            
            # Check if current time is typical for this user
            if not typical_hours:
                # No history - use general business hours
                if 6 <= current_hour <= 22 and current_day < 5:  # Weekday business hours
                    return 10.0
                else:
                    return 60.0
            
            # Check against user's typical patterns
            hour_frequency = typical_hours.get(str(current_hour), 0)
            
            if hour_frequency > 0.1:  # User typically accesses at this hour
                return 0.0
            elif hour_frequency > 0.05:
                return 20.0
            elif 6 <= current_hour <= 22:  # General business hours
                return 40.0
            else:
                return 80.0  # Outside typical hours and business hours
                
        except Exception as e:
            logger.error(f"Error calculating time appropriateness risk: {str(e)}")
            return 50.0
    
    def _calculate_request_frequency_risk(self, access_log: List[Dict]) -> float:
        """Calculate risk based on request frequency"""
        try:
            if not access_log:
                return 0.0
            
            # Calculate requests per minute
            session_duration = (datetime.utcnow() - 
                              datetime.fromisoformat(access_log[0].get("timestamp", datetime.utcnow().isoformat()))
                              ).total_seconds() / 60
            
            if session_duration <= 0:
                return 0.0
            
            request_rate = len(access_log) / session_duration
            
            # Evaluate request rate
            if request_rate < 1:  # Less than 1 request per minute
                return 0.0
            elif request_rate < 3:  # 1-3 requests per minute
                return 10.0
            elif request_rate < 5:  # 3-5 requests per minute
                return 30.0
            elif request_rate < 10:  # 5-10 requests per minute
                return 60.0
            else:  # More than 10 requests per minute
                return 100.0
                
        except Exception as e:
            logger.error(f"Error calculating request frequency risk: {str(e)}")
            return 50.0
    
    def _determine_action(self, risk_score: float) -> str:
        """Determine required action based on risk score"""
        if risk_score >= self.risk_thresholds["session_termination"]:
            return "terminate_session"
        elif risk_score >= self.risk_thresholds["mfa_required"]:
            return "require_mfa"
        elif risk_score >= 50:
            return "monitor_closely"
        else:
            return "continue_normal"
    
    def _update_session_risk(self, session_id: str, risk_assessment: Dict) -> None:
        """Update session with current risk assessment"""
        try:
            session_ref = self.db.collection('continuousAuthSessions').document(session_id)
            
            risk_entry = {
                "timestamp": datetime.utcnow(),
                "risk_score": risk_assessment["risk_score"],
                "factors": risk_assessment["risk_factors"].__dict__,
                "action": self._determine_action(risk_assessment["risk_score"])
            }
            
            session_ref.update({
                "riskProfile.currentRiskScore": risk_assessment["risk_score"],
                "riskProfile.riskHistory": firestore.ArrayUnion([risk_entry]),
                "lastActivity": datetime.utcnow()
            })
            
        except Exception as e:
            logger.error(f"Error updating session risk: {str(e)}")
    
    def _has_behavioral_baseline(self, user_id: str) -> bool:
        """Check if user has established behavioral baseline"""
        try:
            baseline_ref = self.db.collection('behavioralBaselines').document(user_id)
            baseline_doc = baseline_ref.get()
            
            if not baseline_doc.exists:
                return False
            
            baseline_data = baseline_doc.to_dict()
            session_count = baseline_data.get("sessionCount", 0)
            
            return session_count >= self.min_sessions_for_baseline
            
        except Exception as e:
            logger.error(f"Error checking behavioral baseline: {str(e)}")
            return False
    
    def _get_behavioral_baseline(self, user_id: str) -> Optional[Dict]:
        """Get user's behavioral baseline"""
        try:
            baseline_ref = self.db.collection('behavioralBaselines').document(user_id)
            baseline_doc = baseline_ref.get()
            
            if baseline_doc.exists:
                return baseline_doc.to_dict()
            return None
            
        except Exception as e:
            logger.error(f"Error getting behavioral baseline: {str(e)}")
            return None
    
    def _calculate_behavioral_deviation(self, current_behavior: Dict, baseline: Dict) -> float:
        """Calculate deviation from behavioral baseline"""
        # This is a simplified implementation
        # In a real system, this would use more sophisticated behavioral analysis
        try:
            deviation_score = 0.0
            factors_checked = 0
            
            # Compare typing patterns if available
            if "typing_patterns" in current_behavior and "typing_patterns" in baseline:
                current_typing = current_behavior["typing_patterns"]
                baseline_typing = baseline["typing_patterns"]
                
                # Compare average typing speed
                if "avg_speed" in current_typing and "avg_speed" in baseline_typing:
                    speed_diff = abs(current_typing["avg_speed"] - baseline_typing["avg_speed"])
                    speed_deviation = min(speed_diff / baseline_typing["avg_speed"] * 100, 100)
                    deviation_score += speed_deviation
                    factors_checked += 1
            
            # Compare mouse movement patterns if available
            if "mouse_patterns" in current_behavior and "mouse_patterns" in baseline:
                # Simplified mouse pattern comparison
                deviation_score += 20  # Placeholder
                factors_checked += 1
            
            # Compare navigation patterns
            if "navigation_patterns" in current_behavior and "navigation_patterns" in baseline:
                # Simplified navigation pattern comparison
                deviation_score += 15  # Placeholder
                factors_checked += 1
            
            return deviation_score / max(factors_checked, 1)
            
        except Exception as e:
            logger.error(f"Error calculating behavioral deviation: {str(e)}")
            return 50.0
    
    def _detect_impossible_travel(self, locations: List[Dict]) -> bool:
        """Detect impossible travel between locations"""
        if len(locations) < 2:
            return False
        
        try:
            loc1 = locations[-2]
            loc2 = locations[-1]
            
            # Calculate time difference
            time1 = datetime.fromisoformat(loc1.get("timestamp", datetime.utcnow().isoformat()))
            time2 = datetime.fromisoformat(loc2.get("timestamp", datetime.utcnow().isoformat()))
            time_diff_hours = (time2 - time1).total_seconds() / 3600
            
            if time_diff_hours <= 0:
                return False
            
            # Calculate distance (simplified - would use actual geolocation)
            # For now, assume different IP addresses indicate different locations
            if loc1.get("ip_address") != loc2.get("ip_address"):
                # Assume minimum 100km distance for different IPs
                distance_km = 100
                max_speed_kmh = 1000  # Maximum reasonable travel speed (including flights)
                
                required_time = distance_km / max_speed_kmh
                return time_diff_hours < required_time
            
            return False
            
        except Exception as e:
            logger.error(f"Error detecting impossible travel: {str(e)}")
            return False
    
    def _get_user_typical_locations(self, user_id: str) -> List[Dict]:
        """Get user's typical access locations"""
        try:
            # Query recent sessions for location patterns
            sessions_query = self.db.collection('continuousAuthSessions')\
                .where('userId', '==', user_id)\
                .where('startTime', '>=', datetime.utcnow() - timedelta(days=self.baseline_window_days))\
                .limit(50)
            
            sessions = sessions_query.get()
            locations = []
            
            for session_doc in sessions:
                session_data = session_doc.to_dict()
                location_history = session_data.get("locationTracking", {}).get("ipHistory", [])
                locations.extend(location_history)
            
            # Group by IP address and count frequency
            location_counts = {}
            for loc in locations:
                ip = loc.get("ipAddress", "")
                if ip:
                    location_counts[ip] = location_counts.get(ip, 0) + 1
            
            # Return locations that appear frequently (>= 3 times)
            frequent_locations = []
            for ip, count in location_counts.items():
                if count >= 3:
                    frequent_locations.append({"ip_address": ip, "frequency": count})
            
            return frequent_locations
            
        except Exception as e:
            logger.error(f"Error getting user typical locations: {str(e)}")
            return []
    
    def _calculate_min_geographic_distance(self, current_ip: str, typical_locations: List[Dict]) -> float:
        """Calculate minimum geographic distance from typical locations"""
        # This is a simplified implementation
        # In a real system, this would use actual geolocation services
        try:
            for location in typical_locations:
                if location.get("ip_address") == current_ip:
                    return 0.0  # Same IP = same location
            
            # For different IPs, assume some distance
            # This would be replaced with actual geolocation calculation
            return 100.0  # Default 100km for different IPs
            
        except Exception as e:
            logger.error(f"Error calculating geographic distance: {str(e)}")
            return 500.0  # Default high distance on error
    
    def _get_user_access_patterns(self, user_id: str) -> Dict:
        """Get user's typical access patterns"""
        try:
            # This would analyze historical access patterns
            # For now, return a placeholder
            return {
                "avg_session_duration": 120,  # minutes
                "typical_resources": ["dashboard", "profile", "reports"],
                "request_frequency": 2.5  # requests per minute
            }
            
        except Exception as e:
            logger.error(f"Error getting user access patterns: {str(e)}")
            return {}
    
    def _analyze_current_access_patterns(self, access_log: List[Dict]) -> Dict:
        """Analyze current session access patterns"""
        try:
            if not access_log:
                return {}
            
            # Calculate session metrics
            unique_resources = set(log.get("resource", "") for log in access_log)
            
            return {
                "unique_resources": len(unique_resources),
                "total_requests": len(access_log),
                "resources_accessed": list(unique_resources)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing current access patterns: {str(e)}")
            return {}
    
    def _calculate_pattern_deviation(self, current_patterns: Dict, typical_patterns: Dict) -> float:
        """Calculate deviation from typical access patterns"""
        try:
            # Simplified pattern comparison
            deviation = 0.0
            
            # Compare resource diversity
            current_resources = set(current_patterns.get("resources_accessed", []))
            typical_resources = set(typical_patterns.get("typical_resources", []))
            
            if typical_resources:
                overlap = len(current_resources.intersection(typical_resources))
                total = len(current_resources.union(typical_resources))
                similarity = overlap / total if total > 0 else 0
                deviation += (1 - similarity) * 100
            
            return min(deviation, 100)
            
        except Exception as e:
            logger.error(f"Error calculating pattern deviation: {str(e)}")
            return 50.0
    
    def _get_user_typical_hours(self, user_id: str) -> Dict:
        """Get user's typical access hours"""
        try:
            # This would analyze historical access times
            # For now, return business hours as default
            return {
                "9": 0.3, "10": 0.4, "11": 0.4, "12": 0.2,
                "13": 0.3, "14": 0.4, "15": 0.4, "16": 0.3, "17": 0.2
            }
            
        except Exception as e:
            logger.error(f"Error getting user typical hours: {str(e)}")
            return {}
    
    def _get_user_access_history(self, user_id: str) -> List[Dict]:
        """Get user's access history for analysis"""
        try:
            # Query recent access history
            history_query = self.db.collection('auditLogs')\
                .where('userId', '==', user_id)\
                .where('timestamp', '>=', datetime.utcnow() - timedelta(days=self.baseline_window_days))\
                .limit(100)
            
            history_docs = history_query.get()
            return [doc.to_dict() for doc in history_docs]
            
        except Exception as e:
            logger.error(f"Error getting user access history: {str(e)}")
            return []
    
    def _get_typical_access_hours(self, access_history: List[Dict]) -> List[int]:
        """Extract typical access hours from history"""
        try:
            hour_counts = {}
            
            for access in access_history:
                timestamp = access.get("timestamp")
                if timestamp:
                    if isinstance(timestamp, str):
                        timestamp = datetime.fromisoformat(timestamp)
                    hour = timestamp.hour
                    hour_counts[hour] = hour_counts.get(hour, 0) + 1
            
            # Return hours with significant activity (>= 10% of total)
            total_accesses = sum(hour_counts.values())
            if total_accesses == 0:
                return []
            
            typical_hours = []
            for hour, count in hour_counts.items():
                if count / total_accesses >= 0.1:
                    typical_hours.append(hour)
            
            return typical_hours
            
        except Exception as e:
            logger.error(f"Error getting typical access hours: {str(e)}")
            return []
    
    def _send_admin_alert(self, user_id: str, session_id: str, reason: str) -> None:
        """Send alert to administrators about session termination"""
        try:
            # Get admin users
            admin_query = self.db.collection('users').where('role', '==', 'admin')
            admin_docs = admin_query.get()
            
            for admin_doc in admin_docs:
                admin_data = admin_doc.to_dict()
                create_notification(
                    user_id=admin_data.get("userId"),
                    title="High-Risk Session Terminated",
                    message=f"Session {session_id} for user {user_id} was terminated: {reason}",
                    notification_type="security_alert",
                    priority="high"
                )
            
            # Send WebSocket notification to admin room
            from websocket_config import emit_admin_notification
            emit_admin_notification({
                "type": "session_terminated",
                "user_id": user_id,
                "session_id": session_id,
                "reason": reason,
                "timestamp": datetime.utcnow().isoformat()
            })
            
        except Exception as e:
            logger.error(f"Error sending admin alert: {str(e)}")


# Global service instance
continuous_auth_service = ContinuousAuthService()