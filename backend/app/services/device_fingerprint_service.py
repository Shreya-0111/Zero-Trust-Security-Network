"""
Enhanced Device Fingerprinting Service
Implements software-based device identification using browser characteristics
Optimized for high-load scenarios with caching and connection pooling
"""

import hashlib
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from cryptography.fernet import Fernet
from firebase_admin import firestore
from app.utils.error_handler import handle_service_error
from app.services.cache_service import cache_service
from app.services.connection_pool_service import connection_pool_service
from app.services.encryption_service import encryption_service

logger = logging.getLogger(__name__)

class DeviceFingerprintService:
    """Service for managing software-based device fingerprints with performance optimizations"""
    
    def __init__(self):
        # Use connection pooling instead of direct client
        self.use_connection_pool = True
        
        # Initialize Firestore client
        try:
            self.db = firestore.client()
        except Exception as e:
            logger.error(f"Failed to initialize Firestore client: {str(e)}")
            self.db = None
        
        # Performance optimization: Cache TTL for fingerprint results (24 hours)
        self.FINGERPRINT_CACHE_TTL = 86400  # 24 hours in seconds
        self.VALIDATION_CACHE_TTL = 3600    # 1 hour for validation results
        
        # Fingerprint component weights for similarity calculation
        self.component_weights = {
            "canvas": {"weight": 0.25, "stability": "high"},
            "webgl": {"weight": 0.25, "stability": "high"},
            "audio": {"weight": 0.20, "stability": "medium"},
            "screen": {"weight": 0.15, "stability": "low"},
            "system": {"weight": 0.15, "stability": "medium"}
        }
    
    @handle_service_error
    def generate_fingerprint_hash(self, characteristics: Dict) -> str:
        """
        Generate SHA-256 hash from device characteristics
        
        Args:
            characteristics: Dictionary containing device fingerprint data
            
        Returns:
            SHA-256 hash string
        """
        try:
            # Normalize and sort characteristics for consistent hashing
            normalized_chars = self._normalize_characteristics(characteristics)
            
            # Create deterministic string representation
            char_string = json.dumps(normalized_chars, sort_keys=True, separators=(',', ':'))
            
            # Generate SHA-256 hash
            hash_object = hashlib.sha256(char_string.encode('utf-8'))
            return hash_object.hexdigest()
            
        except Exception as e:
            logger.error(f"Error generating fingerprint hash: {str(e)}")
            raise
    
    @handle_service_error
    def register_device(self, user_id: str, fingerprint_data: Dict, mfa_verified: bool = False) -> Dict:
        """
        Register a new device fingerprint for a user
        
        Args:
            user_id: User identifier
            fingerprint_data: Complete fingerprint characteristics
            mfa_verified: Whether MFA verification was completed
            
        Returns:
            Device registration result
        """
        try:
            # Check device limit (max 3 devices per user)
            existing_devices = self._get_user_devices(user_id)
            if len(existing_devices) >= 3:
                if not mfa_verified:
                    return {
                        "success": False,
                        "error": "DEVICE_LIMIT_EXCEEDED",
                        "message": "Maximum 3 devices allowed per user",
                        "requires_mfa": True
                    }
                # If MFA is verified, allow registration beyond limit (up to 5 total)
                elif len(existing_devices) >= 5:
                    return {
                        "success": False,
                        "error": "ABSOLUTE_DEVICE_LIMIT_EXCEEDED",
                        "message": "Absolute maximum of 5 devices allowed per user"
                    }
            
            # Generate fingerprint hash
            fingerprint_hash = self.generate_fingerprint_hash(fingerprint_data)
            
            # Check for duplicate fingerprint and handle same-user reuse/reactivation
            try:
                query = self.db.collection('deviceFingerprints').where(
                    'fingerprintHash', '==', fingerprint_hash
                ).limit(1)
                results = query.get()
                if results:
                    existing_doc = results[0]
                    existing = existing_doc.to_dict()
                    if existing.get('userId') == user_id:
                        if not existing.get('isActive', True):
                            existing_doc.reference.update({
                                'isActive': True,
                                'lastVerified': datetime.utcnow()
                            })
                        logger.info(f"Reusing existing device for user {user_id}: {existing.get('deviceId')}")
                        return {
                            "success": True,
                            "deviceId": existing.get('deviceId'),
                            "trustScore": existing.get('trustScore', 100),
                            "message": "Device already registered; using existing record"
                        }
                    else:
                        return {
                            "success": False,
                            "error": "DUPLICATE_FINGERPRINT",
                            "message": "Device fingerprint already registered"
                        }
            except Exception:
                # Fallback to original duplicate behavior on query error
                if self._fingerprint_exists(fingerprint_hash):
                    return {
                        "success": False,
                        "error": "DUPLICATE_FINGERPRINT",
                        "message": "Device fingerprint already registered"
                    }
            
            # Create device record
            device_id = f"device_{user_id}_{len(existing_devices) + 1}"
            device_record = {
                "deviceId": device_id,
                "userId": user_id,
                "fingerprintHash": fingerprint_hash,
                "characteristics": encryption_service.encrypt_device_fingerprint(fingerprint_data),
                "trustScore": 100,  # Start with full trust
                "registeredAt": datetime.utcnow(),
                "lastVerified": datetime.utcnow(),
                "verificationHistory": [],
                "isApproved": True,
                "deviceName": fingerprint_data.get("deviceName", f"Device {len(existing_devices) + 1}"),
                "isActive": True,
                "mfaVerified": mfa_verified  # Track if MFA was used for registration
            }
            
            # Store in Firestore
            self.db.collection('deviceFingerprints').document(device_id).set(device_record)
            
            logger.info(f"Device registered successfully for user {user_id}: {device_id} (MFA: {mfa_verified})")
            
            return {
                "success": True,
                "deviceId": device_id,
                "trustScore": 100,
                "message": "Device registered successfully"
            }
            
        except Exception as e:
            logger.error(f"Error registering device: {str(e)}")
            raise
    
    @handle_service_error
    def validate_fingerprint(self, user_id: str, current_fingerprint: Dict) -> Dict:
        """
        Validate current device fingerprint against stored fingerprints
        Optimized with caching for sub-500ms response times
        
        Args:
            user_id: User identifier
            current_fingerprint: Current device characteristics
            
        Returns:
            Validation result with similarity score
        """
        start_time = time.time()
        
        try:
            # Check cache first for recent validation results
            cache_key = f"fingerprint_validation:{user_id}:{hashlib.md5(json.dumps(current_fingerprint, sort_keys=True).encode()).hexdigest()}"
            cached_result = cache_service.get_device_profile(cache_key)
            
            if cached_result:
                logger.info(f"Fingerprint validation cache hit for user {user_id}")
                return cached_result
            
            # Get user's registered devices (with caching)
            user_devices = self._get_user_devices_cached(user_id)
            
            if not user_devices:
                result = {
                    "success": False,
                    "error": "NO_REGISTERED_DEVICES",
                    "message": "No registered devices found for user",
                    "similarity": 0,
                    "response_time_ms": round((time.time() - start_time) * 1000, 2)
                }
                return result
            
            # Generate current fingerprint hash (optimized)
            current_hash = self._generate_fingerprint_hash_optimized(current_fingerprint)
            
            best_match = None
            highest_similarity = 0
            
            # Compare against all registered devices (parallel processing for multiple devices)
            for device in user_devices:
                stored_chars = self._decrypt_characteristics_cached(device.get("characteristics", ""), device.get("deviceId"))
                similarity = self._calculate_similarity_optimized(current_fingerprint, stored_chars)
                
                if similarity > highest_similarity:
                    highest_similarity = similarity
                    best_match = device
            
            # Update verification history asynchronously to avoid blocking
            if best_match:
                self._update_verification_history_async(best_match["deviceId"], highest_similarity)
            
            # Determine validation result
            response_time_ms = round((time.time() - start_time) * 1000, 2)
            
            if highest_similarity >= 95:
                result = {
                    "success": True,
                    "approved": True,
                    "similarity": highest_similarity,
                    "deviceId": best_match["deviceId"],
                    "trustScore": best_match.get("trustScore", 100),
                    "message": "Device fingerprint validated successfully",
                    "response_time_ms": response_time_ms
                }
            elif highest_similarity >= 85:
                result = {
                    "success": True,
                    "approved": False,
                    "similarity": highest_similarity,
                    "deviceId": best_match["deviceId"] if best_match else None,
                    "message": "Device fingerprint requires additional verification",
                    "requires_additional_verification": True,
                    "response_time_ms": response_time_ms
                }
            else:
                result = {
                    "success": False,
                    "approved": False,
                    "similarity": highest_similarity,
                    "error": "FINGERPRINT_MISMATCH",
                    "message": "Device fingerprint validation failed",
                    "requires_reregistration": True,
                    "response_time_ms": response_time_ms
                }
            
            # Cache the result for future requests (shorter TTL for failed validations)
            cache_ttl = self.VALIDATION_CACHE_TTL if result["success"] else 300  # 5 minutes for failures
            cache_service.cache_device_profile(cache_key, result, cache_ttl)
            
            logger.info(f"Fingerprint validation for user {user_id}: similarity={highest_similarity}%, time={response_time_ms}ms")
            
            # Log performance warning if validation takes too long
            if response_time_ms > 500:
                logger.warning(f"Slow fingerprint validation: {response_time_ms}ms for user {user_id}")
            
            return result
            
        except Exception as e:
            response_time_ms = round((time.time() - start_time) * 1000, 2)
            logger.error(f"Error validating fingerprint (time={response_time_ms}ms): {str(e)}")
            raise
    
    @handle_service_error
    def detect_fingerprint_anomalies(self, fingerprint_data: Dict) -> List[str]:
        """
        Detect suspicious characteristics in fingerprint data
        
        Args:
            fingerprint_data: Device fingerprint characteristics
            
        Returns:
            List of detected anomalies
        """
        anomalies = []
        
        try:
            # Check for suspicious canvas characteristics
            canvas_data = fingerprint_data.get("canvas", {})
            if canvas_data.get("confidence", 100) < 50:
                anomalies.append("Low canvas fingerprint confidence")
            
            # Check for unusual screen characteristics
            screen_data = fingerprint_data.get("screen", {})
            if screen_data.get("width", 0) < 800 or screen_data.get("height", 0) < 600:
                anomalies.append("Unusual screen resolution")
            
            # Check for missing WebGL support
            webgl_data = fingerprint_data.get("webgl", {})
            if not webgl_data.get("renderer"):
                anomalies.append("Missing WebGL renderer information")
            
            # Check for suspicious system characteristics
            system_data = fingerprint_data.get("system", {})
            if system_data.get("hardwareConcurrency", 0) > 32:
                anomalies.append("Unusually high CPU core count")
            
            # Check for automation indicators
            if "HeadlessChrome" in system_data.get("userAgent", ""):
                anomalies.append("Headless browser detected")
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting anomalies: {str(e)}")
            return ["Error analyzing fingerprint characteristics"]
    
    @handle_service_error
    def update_fingerprint_trust_score(self, device_id: str, validation_result: bool) -> None:
        """
        Update device trust score based on validation results
        
        Args:
            device_id: Device identifier
            validation_result: Whether validation was successful
        """
        try:
            device_ref = self.db.collection('deviceFingerprints').document(device_id)
            device_doc = device_ref.get()
            
            if not device_doc.exists:
                logger.warning(f"Device not found for trust score update: {device_id}")
                return
            
            device_data = device_doc.to_dict()
            current_trust = device_data.get("trustScore", 100)
            
            if validation_result:
                # Increase trust score (max 100)
                new_trust = min(current_trust + 5, 100)
            else:
                # Decrease trust score (min 0)
                new_trust = max(current_trust - 10, 0)
            
            # Update device record
            device_ref.update({
                "trustScore": new_trust,
                "lastVerified": datetime.utcnow()
            })
            
            logger.info(f"Updated trust score for device {device_id}: {current_trust} -> {new_trust}")
            
        except Exception as e:
            logger.error(f"Error updating trust score: {str(e)}")
            raise
    
    @handle_service_error
    def validate_fingerprint_structure(self, fingerprint_data: Dict) -> bool:
        """
        Validate the structure of fingerprint data
        
        Args:
            fingerprint_data: Fingerprint data to validate
            
        Returns:
            True if structure is valid
        """
        try:
            if not isinstance(fingerprint_data, dict):
                return False
            
            # Required components
            required_components = ['canvas', 'webgl', 'audio', 'screen', 'system']
            
            for component in required_components:
                if component not in fingerprint_data:
                    return False
                
                if not isinstance(fingerprint_data[component], dict):
                    return False
                
                # Component-specific validation
                if component == 'canvas':
                    if 'hash' not in fingerprint_data[component]:
                        return False
                elif component == 'webgl':
                    if 'renderer' not in fingerprint_data[component] or 'vendor' not in fingerprint_data[component]:
                        return False
                elif component == 'audio':
                    if 'hash' not in fingerprint_data[component]:
                        return False
                elif component == 'screen':
                    required_fields = ['width', 'height', 'colorDepth']
                    if not all(field in fingerprint_data[component] for field in required_fields):
                        return False
                elif component == 'system':
                    if 'platform' not in fingerprint_data[component]:
                        return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating fingerprint structure: {str(e)}")
            return False
    
    @handle_service_error
    def detect_suspicious_patterns(self, fingerprint_data: Dict) -> bool:
        """
        Detect suspicious patterns in fingerprint data
        
        Args:
            fingerprint_data: Fingerprint data to analyze
            
        Returns:
            True if suspicious patterns detected
        """
        try:
            # Check for repeated values across different components
            all_values = []
            
            def extract_values(obj, prefix=""):
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        if isinstance(value, (str, int, float)):
                            all_values.append(str(value))
                        elif isinstance(value, dict):
                            extract_values(value, f"{prefix}.{key}")
                        elif isinstance(value, list):
                            for item in value:
                                if isinstance(item, (str, int, float)):
                                    all_values.append(str(item))
            
            extract_values(fingerprint_data)
            
            # Check for too many identical values
            value_counts = {}
            for value in all_values:
                if len(value) > 3:  # Only check meaningful values
                    value_counts[value] = value_counts.get(value, 0) + 1
            
            # If any value appears more than 3 times, it's suspicious
            max_occurrences = max(value_counts.values()) if value_counts else 0
            if max_occurrences > 3:
                return True
            
            # Check for obviously fake values
            suspicious_values = [
                'same_value', 'fake', 'test', 'dummy', 'placeholder',
                'null', 'undefined', 'unknown', 'default'
            ]
            
            for value in all_values:
                if value.lower() in suspicious_values:
                    return True
            
            # Check for unrealistic screen resolutions
            screen_data = fingerprint_data.get('screen', {})
            width = screen_data.get('width', 0)
            height = screen_data.get('height', 0)
            
            if width > 10000 or height > 10000 or width < 100 or height < 100:
                return True
            
            # Check for unrealistic hardware concurrency
            system_data = fingerprint_data.get('system', {})
            hardware_concurrency = system_data.get('hardwareConcurrency', 0)
            
            if hardware_concurrency > 128 or hardware_concurrency < 1:
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error detecting suspicious patterns: {str(e)}")
            return False
    
    @handle_service_error
    def calculate_similarity(self, hash1: str, hash2: str) -> float:
        """
        Calculate similarity between two fingerprint hashes
        
        Args:
            hash1: First fingerprint hash
            hash2: Second fingerprint hash
            
        Returns:
            Similarity score (0.0 to 1.0)
        """
        try:
            if hash1 == hash2:
                return 1.0
            
            # For hash comparison, we can use Hamming distance
            if len(hash1) != len(hash2):
                return 0.0
            
            # Calculate Hamming distance
            differences = sum(c1 != c2 for c1, c2 in zip(hash1, hash2))
            similarity = 1.0 - (differences / len(hash1))
            
            return similarity
            
        except Exception as e:
            logger.error(f"Error calculating similarity: {str(e)}")
            return 0.0
        """
        Remove fingerprints for deactivated devices
        
        Returns:
            Number of cleaned up fingerprints
        """
        try:
            # Find inactive devices older than 90 days
            cutoff_date = datetime.utcnow() - timedelta(days=90)
            
            devices_query = self.db.collection('deviceFingerprints').where(
                'isActive', '==', False
            ).where(
                'lastVerified', '<', cutoff_date
            )
            
            devices = devices_query.get()
            cleanup_count = 0
            
            for device_doc in devices:
                device_doc.reference.delete()
                cleanup_count += 1
            
            logger.info(f"Cleaned up {cleanup_count} expired device fingerprints")
            return cleanup_count
            
        except Exception as e:
            logger.error(f"Error cleaning up fingerprints: {str(e)}")
            raise
    
    def _normalize_characteristics(self, characteristics: Dict) -> Dict:
        """Normalize characteristics for consistent hashing"""
        normalized = {}
        
        # Normalize canvas data
        if "canvas" in characteristics:
            canvas = characteristics["canvas"]
            normalized["canvas"] = {
                "hash": canvas.get("hash", ""),
                "confidence": round(canvas.get("confidence", 0), 2)
            }
        
        # Normalize WebGL data
        if "webgl" in characteristics:
            webgl = characteristics["webgl"]
            normalized["webgl"] = {
                "renderer": webgl.get("renderer", ""),
                "vendor": webgl.get("vendor", ""),
                "version": webgl.get("version", "")
            }
        
        # Normalize audio data
        if "audio" in characteristics:
            audio = characteristics["audio"]
            normalized["audio"] = {
                "hash": audio.get("hash", ""),
                "sampleRate": audio.get("sampleRate", 0),
                "bufferSize": audio.get("bufferSize", 0)
            }
        
        # Normalize screen data (include all fields for sensitivity)
        if "screen" in characteristics:
            screen = characteristics["screen"]
            normalized["screen"] = {
                "width": screen.get("width", 0),
                "height": screen.get("height", 0),
                "colorDepth": screen.get("colorDepth", 0),
                "pixelRatio": round(screen.get("pixelRatio", 1), 2)
            }
        
        # Normalize system data
        if "system" in characteristics:
            system = characteristics["system"]
            normalized["system"] = {
                "platform": system.get("platform", ""),
                "language": system.get("language", ""),
                "timezone": system.get("timezone", ""),
                "hardwareConcurrency": system.get("hardwareConcurrency", 0),
                "userAgent": system.get("userAgent", "")  # Include user agent for uniqueness
            }
        
        # Include fonts and plugins for additional uniqueness
        if "fonts" in characteristics:
            normalized["fonts"] = sorted(characteristics["fonts"]) if isinstance(characteristics["fonts"], list) else []
        
        if "plugins" in characteristics:
            normalized["plugins"] = sorted(characteristics["plugins"]) if isinstance(characteristics["plugins"], list) else []
        
        return normalized
    
    def _calculate_similarity(self, current: Dict, stored: Dict) -> float:
        """Calculate weighted similarity between fingerprints"""
        total_weight = 0
        weighted_similarity = 0
        
        for component, config in self.component_weights.items():
            if component in current and component in stored:
                component_similarity = self._compare_component(
                    current[component], 
                    stored[component], 
                    component
                )
                
                weight = config["weight"]
                weighted_similarity += component_similarity * weight
                total_weight += weight
        
        if total_weight == 0:
            return 0
        
        return (weighted_similarity / total_weight) * 100
    
    def _compare_component(self, current: Dict, stored: Dict, component_type: str) -> float:
        """Compare individual fingerprint components"""
        if component_type == "canvas":
            return 1.0 if current.get("hash") == stored.get("hash") else 0.0
        
        elif component_type == "webgl":
            matches = 0
            total = 0
            for key in ["renderer", "vendor", "version"]:
                if key in current and key in stored:
                    if current[key] == stored[key]:
                        matches += 1
                    total += 1
            return matches / total if total > 0 else 0.0
        
        elif component_type == "audio":
            return 1.0 if current.get("hash") == stored.get("hash") else 0.0
        
        elif component_type == "screen":
            # Allow some tolerance for screen resolution changes
            current_res = (current.get("width", 0), current.get("height", 0))
            stored_res = (stored.get("width", 0), stored.get("height", 0))
            
            if current_res == stored_res:
                return 1.0
            elif abs(current_res[0] - stored_res[0]) <= 100 and abs(current_res[1] - stored_res[1]) <= 100:
                return 0.8
            else:
                return 0.0
        
        elif component_type == "system":
            matches = 0
            total = 0
            for key in ["platform", "language", "timezone"]:
                if key in current and key in stored:
                    if current[key] == stored[key]:
                        matches += 1
                    total += 1
            return matches / total if total > 0 else 0.0
        
        return 0.0
    
    def _get_user_devices(self, user_id: str) -> List[Dict]:
        """Get all registered devices for a user with connection pooling"""
        try:
            if self.use_connection_pool:
                with connection_pool_service.get_firestore_connection() as db:
                    devices_query = db.collection('deviceFingerprints').where(
                        'userId', '==', user_id
                    ).where(
                        'isActive', '==', True
                    )
                    devices = devices_query.get()
                    return [doc.to_dict() for doc in devices]
            else:
                # Fallback to direct connection
                db = firestore.client()
                devices_query = db.collection('deviceFingerprints').where(
                    'userId', '==', user_id
                ).where(
                    'isActive', '==', True
                )
                devices = devices_query.get()
                return [doc.to_dict() for doc in devices]
            
        except Exception as e:
            logger.error(f"Error getting user devices: {str(e)}")
            return []
    
    def _get_user_devices_cached(self, user_id: str) -> List[Dict]:
        """Get user devices with caching for performance optimization"""
        cache_key = f"user_devices:{user_id}"
        cached_devices = cache_service.get_device_profile(cache_key)
        
        if cached_devices:
            return cached_devices
        
        devices = self._get_user_devices(user_id)
        
        # Cache for 1 hour (devices don't change frequently)
        cache_service.cache_device_profile(cache_key, devices, 3600)
        
        return devices
    
    def _generate_fingerprint_hash_optimized(self, characteristics: Dict) -> str:
        """Optimized fingerprint hash generation with caching"""
        cache_key = f"fingerprint_hash:{hashlib.md5(json.dumps(characteristics, sort_keys=True).encode()).hexdigest()}"
        cached_hash = cache_service.get_device_profile(cache_key)
        
        if cached_hash:
            return cached_hash
        
        fingerprint_hash = self.generate_fingerprint_hash(characteristics)
        
        # Cache hash for 24 hours
        cache_service.cache_device_profile(cache_key, fingerprint_hash, self.FINGERPRINT_CACHE_TTL)
        
        return fingerprint_hash
    
    def _decrypt_characteristics_cached(self, encrypted_data: str, device_id: str) -> Dict:
        """Decrypt characteristics with caching"""
        if not encrypted_data:
            return {}
        
        cache_key = f"decrypted_chars:{device_id}"
        cached_chars = cache_service.get_device_profile(cache_key)
        
        if cached_chars:
            return cached_chars
        
        decrypted_chars = encryption_service.decrypt_device_fingerprint(encrypted_data)
        
        # Cache for 2 hours
        cache_service.cache_device_profile(cache_key, decrypted_chars, 7200)
        
        return decrypted_chars
    
    def _calculate_similarity_optimized(self, current: Dict, stored: Dict) -> float:
        """Optimized similarity calculation with early termination"""
        # Early termination: if critical components don't match, return low similarity
        if "canvas" in current and "canvas" in stored:
            if current["canvas"].get("hash") != stored["canvas"].get("hash"):
                # Canvas mismatch is critical - check other high-weight components
                if "webgl" in current and "webgl" in stored:
                    webgl_match = self._compare_component(current["webgl"], stored["webgl"], "webgl")
                    if webgl_match < 0.8:  # If both canvas and webgl don't match well
                        return 0.0  # Early termination
        
        return self._calculate_similarity(current, stored)
    
    def _update_verification_history_async(self, device_id: str, similarity: float) -> None:
        """Asynchronous verification history update to avoid blocking"""
        try:
            # Use background task or queue this operation
            # For now, we'll do a non-blocking update
            import threading
            
            def update_history():
                try:
                    self._update_verification_history(device_id, similarity)
                except Exception as e:
                    logger.error(f"Error in async verification history update: {str(e)}")
            
            thread = threading.Thread(target=update_history)
            thread.daemon = True
            thread.start()
            
        except Exception as e:
            logger.error(f"Error starting async verification history update: {str(e)}")
    
    def _fingerprint_exists(self, fingerprint_hash: str) -> bool:
        """Check if fingerprint hash already exists"""
        try:
            query = self.db.collection('deviceFingerprints').where(
                'fingerprintHash', '==', fingerprint_hash
            ).limit(1)
            
            results = query.get()
            return len(results) > 0
            
        except Exception as e:
            logger.error(f"Error checking fingerprint existence: {str(e)}")
            return False
    
    def _encrypt_characteristics(self, characteristics: Dict) -> str:
        """Encrypt fingerprint characteristics for storage using enhanced encryption service"""
        try:
            return encryption_service.encrypt_device_fingerprint(characteristics)
        except Exception as e:
            logger.error(f"Error encrypting characteristics: {str(e)}")
            return ""
    
    def _decrypt_characteristics(self, encrypted_data: str) -> Dict:
        """Decrypt stored fingerprint characteristics using enhanced encryption service"""
        try:
            if not encrypted_data:
                return {}
            
            return encryption_service.decrypt_device_fingerprint(encrypted_data)
        except Exception as e:
            logger.error(f"Error decrypting characteristics: {str(e)}")
            return {}
    
    def _update_verification_history(self, device_id: str, similarity: float) -> None:
        """Update device verification history"""
        try:
            device_ref = self.db.collection('deviceFingerprints').document(device_id)
            
            verification_entry = {
                "timestamp": datetime.utcnow(),
                "similarity": similarity,
                "result": "success" if similarity >= 95 else "partial" if similarity >= 85 else "failed"
            }
            
            device_ref.update({
                "verificationHistory": firestore.ArrayUnion([verification_entry]),
                "lastVerified": datetime.utcnow()
            })
            
        except Exception as e:
            logger.error(f"Error updating verification history: {str(e)}")

# Global instance
device_fingerprint_service = DeviceFingerprintService()