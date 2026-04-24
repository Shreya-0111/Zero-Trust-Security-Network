"""
Enhanced Audit Service
Comprehensive audit logging with structured logging, tamper-evident storage,
and cryptographic integrity verification for the Zero Trust Security Framework.
"""

import os
import json
import hashlib
import hmac
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import geoip2.database
import geoip2.errors

# Optional user agent parsing
try:
    from user_agents import parse as parse_user_agent
    USER_AGENTS_AVAILABLE = True
except ImportError:
    USER_AGENTS_AVAILABLE = False
    def parse_user_agent(user_agent):
        return None

from app.firebase_config import get_firestore_client
from app.services.firebase_storage_service import FirebaseStorageService


class EnhancedAuditService:
    """
    Enhanced audit logging service with comprehensive event tracking,
    tamper-evident storage, and cryptographic integrity verification.
    """
    
    # Enhanced event types covering all system activities
    EVENT_TYPES = {
        'authentication': 'User authentication events',
        'access_request': 'Resource access requests',
        'jit_access': 'Just-in-time access events',
        'break_glass': 'Emergency break-glass access',
        'device_registration': 'Device fingerprint registration',
        'visitor_management': 'Visitor registration and tracking',
        'policy_change': 'Security policy modifications',
        'admin_action': 'Administrative actions',
        'continuous_auth': 'Continuous authentication events',
        'risk_assessment': 'Risk score calculations',
        'security_event': 'Security incidents and alerts',
        'compliance_event': 'Compliance-related activities',
        'data_access': 'Data access and modification',
        'system_event': 'System-level events'
    }
    
    # Event sub-types for granular tracking
    SUB_TYPES = {
        'authentication': ['login', 'logout', 'mfa_setup', 'mfa_verify', 'password_reset'],
        'access_request': ['submit', 'approve', 'deny', 'expire', 'revoke'],
        'jit_access': ['request', 'grant', 'monitor', 'expire', 'revoke'],
        'break_glass': ['request', 'approve', 'activate', 'monitor', 'expire'],
        'device_registration': ['register', 'validate', 'approve', 'reject', 'deactivate'],
        'visitor_management': ['register', 'activate', 'track', 'extend', 'terminate'],
        'policy_change': ['create', 'update', 'delete', 'activate', 'deactivate'],
        'admin_action': ['user_create', 'user_modify', 'user_delete', 'role_change', 'permission_grant'],
        'continuous_auth': ['risk_calculate', 'threshold_exceed', 'reauth_trigger', 'session_terminate'],
        'risk_assessment': ['score_update', 'factor_change', 'threshold_breach', 'anomaly_detect'],
        'security_event': ['alert_generate', 'incident_create', 'threat_detect', 'attack_block'],
        'compliance_event': ['report_generate', 'audit_export', 'retention_enforce', 'data_purge'],
        'data_access': ['read', 'write', 'delete', 'export', 'import'],
        'system_event': ['startup', 'shutdown', 'error', 'maintenance', 'backup']
    }
    
    # Severity levels with descriptions
    SEVERITY_LEVELS = {
        'low': 'Normal operations, informational events',
        'medium': 'Events requiring attention, potential security implications',
        'high': 'Security events requiring immediate attention',
        'critical': 'Critical security incidents requiring emergency response'
    }
    
    # Compliance flags for regulatory requirements
    COMPLIANCE_FLAGS = [
        'GDPR', 'FERPA', 'SOX', 'HIPAA', 'PCI_DSS', 'ISO27001', 'NIST', 'FISMA'
    ]
    
    # Retention categories
    RETENTION_CATEGORIES = {
        'standard': 2555,  # 7 years in days
        'extended': 3653,  # 10 years in days
        'permanent': -1    # Permanent retention
    }
    
    def __init__(self):
        """Initialize the Enhanced Audit Service"""
        self.db = get_firestore_client()
        self.storage_service = FirebaseStorageService()
        
        # Initialize encryption for sensitive data
        self._init_encryption()
        
        # Initialize GeoIP database for location tracking
        self._init_geoip()
        
        # Configuration
        self.batch_size = int(os.getenv('AUDIT_BATCH_SIZE', '100'))
        self.integrity_check_interval = int(os.getenv('INTEGRITY_CHECK_INTERVAL', '3600'))  # 1 hour
        self.archival_threshold_days = int(os.getenv('ARCHIVAL_THRESHOLD_DAYS', '90'))
        
        # Performance metrics
        self.metrics = {
            'logs_created': 0,
            'integrity_checks': 0,
            'archival_operations': 0,
            'errors': 0
        }
    
    def _init_encryption(self):
        """Initialize encryption for sensitive audit data"""
        try:
            # Get encryption key from environment or generate one
            key_material = os.getenv('AUDIT_ENCRYPTION_KEY')
            if not key_material:
                # Generate a key for development (in production, use proper key management)
                key_material = Fernet.generate_key().decode()
                print("Warning: Using generated encryption key. Set AUDIT_ENCRYPTION_KEY in production.")
            
            if isinstance(key_material, str):
                key_material = key_material.encode()
            
            # Derive encryption key
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'audit_salt_2024',  # In production, use random salt per installation
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(key_material))
            self.cipher = Fernet(key)
            
            # HMAC key for integrity verification
            self.hmac_key = os.getenv('AUDIT_HMAC_KEY', 'default_hmac_key_change_in_production').encode()
            
        except Exception as e:
            print(f"Error initializing encryption: {e}")
            # Fallback to no encryption (not recommended for production)
            self.cipher = None
            self.hmac_key = b'fallback_key'
    
    def _init_geoip(self):
        """Initialize GeoIP database for location tracking"""
        try:
            geoip_path = os.getenv('GEOIP_DATABASE_PATH', 'backend/geoip2/GeoLite2-City.mmdb')
            if os.path.exists(geoip_path):
                self.geoip_reader = geoip2.database.Reader(geoip_path)
            else:
                print(f"GeoIP database not found at {geoip_path}")
                self.geoip_reader = None
        except Exception as e:
            print(f"Error initializing GeoIP: {e}")
            self.geoip_reader = None
    
    def _get_geolocation(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get geolocation information for an IP address"""
        if not self.geoip_reader or not ip_address:
            return None
        
        try:
            # Skip private IP addresses
            if ip_address.startswith(('127.', '10.', '192.168.', '172.')):
                return {'type': 'private', 'ip': ip_address}
            
            response = self.geoip_reader.city(ip_address)
            return {
                'country': response.country.name,
                'country_code': response.country.iso_code,
                'city': response.city.name,
                'latitude': float(response.location.latitude) if response.location.latitude else None,
                'longitude': float(response.location.longitude) if response.location.longitude else None,
                'timezone': response.location.time_zone,
                'isp': response.traits.isp if hasattr(response.traits, 'isp') else None
            }
        except (geoip2.errors.AddressNotFoundError, ValueError, Exception):
            return {'type': 'unknown', 'ip': ip_address}
    
    def _parse_user_agent(self, user_agent: str) -> Dict[str, str]:
        """Parse user agent string for device information"""
        if not user_agent or not USER_AGENTS_AVAILABLE:
            return {'raw': user_agent} if user_agent else {}
        
        try:
            parsed = parse_user_agent(user_agent)
            return {
                'browser': f"{parsed.browser.family} {parsed.browser.version_string}",
                'os': f"{parsed.os.family} {parsed.os.version_string}",
                'device': parsed.device.family,
                'is_mobile': parsed.is_mobile,
                'is_tablet': parsed.is_tablet,
                'is_pc': parsed.is_pc,
                'is_bot': parsed.is_bot
            }
        except Exception:
            return {'raw': user_agent}
    
    def _generate_integrity_hash(self, log_data: Dict[str, Any]) -> str:
        """Generate HMAC-SHA256 hash for tamper detection"""
        try:
            # Create a copy and convert datetime objects to strings
            serializable_data = {}
            for key, value in log_data.items():
                if isinstance(value, datetime):
                    serializable_data[key] = value.isoformat()
                elif isinstance(value, dict):
                    # Recursively handle nested dictionaries
                    serializable_data[key] = self._make_serializable(value)
                else:
                    serializable_data[key] = value
            
            # Create canonical representation of log data
            canonical_data = json.dumps(serializable_data, sort_keys=True, separators=(',', ':'))
            
            # Generate HMAC
            signature = hmac.new(
                self.hmac_key,
                canonical_data.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            
            return signature
        except Exception as e:
            print(f"Error generating integrity hash: {e}")
            return ""
    
    def _make_serializable(self, obj):
        """Make an object JSON serializable"""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(item) for item in obj]
        else:
            return obj
    
    def _encrypt_sensitive_data(self, data: Any) -> str:
        """Encrypt sensitive data if encryption is available"""
        if not self.cipher:
            return str(data)
        
        try:
            if isinstance(data, dict):
                data = json.dumps(data)
            elif not isinstance(data, str):
                data = str(data)
            
            encrypted = self.cipher.encrypt(data.encode('utf-8'))
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            print(f"Error encrypting data: {e}")
            return str(data)
    
    def _decrypt_sensitive_data(self, encrypted_data: str) -> Any:
        """Decrypt sensitive data if encryption is available"""
        if not self.cipher:
            return encrypted_data
        
        try:
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
            decrypted = self.cipher.decrypt(encrypted_bytes)
            return decrypted.decode('utf-8')
        except Exception as e:
            print(f"Error decrypting data: {e}")
            return encrypted_data
    
    def log_comprehensive_event(
        self,
        event_type: str,
        sub_type: str,
        user_id: str,
        action: str,
        result: str,
        session_id: Optional[str] = None,
        device_id: Optional[str] = None,
        visitor_id: Optional[str] = None,
        resource_segment_id: Optional[str] = None,
        target_user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        risk_score: Optional[float] = None,
        confidence_score: Optional[float] = None,
        request_data: Optional[Dict[str, Any]] = None,
        response_data: Optional[Dict[str, Any]] = None,
        policy_evaluation: Optional[Dict[str, Any]] = None,
        ml_predictions: Optional[Dict[str, Any]] = None,
        contextual_factors: Optional[Dict[str, Any]] = None,
        data_accessed: Optional[List[Dict[str, Any]]] = None,
        compliance_flags: Optional[List[str]] = None,
        retention_category: str = 'standard',
        severity: str = 'low',
        additional_details: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """
        Log a comprehensive audit event with all required fields and metadata.
        
        Args:
            event_type: Type of event (authentication, access_request, etc.)
            sub_type: Specific action within event type
            user_id: User ID associated with the event
            action: Detailed action description
            result: Result of the action (success, failure, denied, pending)
            session_id: Session ID if applicable
            device_id: Device ID if applicable
            visitor_id: Visitor ID if applicable
            resource_segment_id: Resource segment ID if applicable
            target_user_id: Target user ID for admin actions
            ip_address: Client IP address
            user_agent: User agent string
            risk_score: Risk score (0-100) if applicable
            confidence_score: Confidence score (0-100) if applicable
            request_data: Sanitized request information
            response_data: Sanitized response information
            policy_evaluation: Policy decisions and scores
            ml_predictions: Machine learning outputs
            contextual_factors: Environmental factors
            data_accessed: List of data access information
            compliance_flags: Compliance-related tags
            retention_category: Data retention category
            severity: Severity level (low, medium, high, critical)
            additional_details: Additional context information
            
        Returns:
            str: Log ID if successful, None if failed
        """
        try:
            # Validate inputs
            if event_type not in self.EVENT_TYPES:
                raise ValueError(f"Invalid event_type: {event_type}")
            
            if sub_type and event_type in self.SUB_TYPES:
                if sub_type not in self.SUB_TYPES[event_type]:
                    raise ValueError(f"Invalid sub_type '{sub_type}' for event_type '{event_type}'")
            
            if severity not in self.SEVERITY_LEVELS:
                raise ValueError(f"Invalid severity: {severity}")
            
            if retention_category not in self.RETENTION_CATEGORIES:
                raise ValueError(f"Invalid retention_category: {retention_category}")
            
            # Generate unique log ID
            log_id = str(uuid.uuid4())
            timestamp = datetime.utcnow()
            
            # Get geolocation if IP address provided
            geolocation = self._get_geolocation(ip_address) if ip_address else None
            
            # Parse user agent if provided
            parsed_user_agent = self._parse_user_agent(user_agent) if user_agent else None
            
            # Sanitize and encrypt sensitive data
            sanitized_request_data = self._sanitize_request_data(request_data) if request_data else None
            sanitized_response_data = self._sanitize_response_data(response_data) if response_data else None
            
            # Build comprehensive audit log entry
            audit_entry = {
                'logId': log_id,
                'eventType': event_type,
                'subType': sub_type,
                'userId': user_id,
                'targetUserId': target_user_id,
                'deviceId': device_id,
                'visitorId': visitor_id,
                'resourceSegmentId': resource_segment_id,
                'action': action,
                'result': result,
                'timestamp': timestamp,
                'sessionId': session_id,
                'ipAddress': ip_address,
                'userAgent': user_agent,
                'parsedUserAgent': parsed_user_agent,
                'geolocation': geolocation,
                'riskScore': risk_score,
                'confidenceScore': confidence_score,
                'details': {
                    'requestData': sanitized_request_data,
                    'responseData': sanitized_response_data,
                    'policyEvaluation': policy_evaluation,
                    'mlPredictions': ml_predictions,
                    'contextualFactors': contextual_factors,
                    'additionalDetails': additional_details
                },
                'dataAccessed': data_accessed or [],
                'complianceFlags': compliance_flags or [],
                'retentionCategory': retention_category,
                'encryptionStatus': 'encrypted' if self.cipher else 'plaintext',
                'severity': severity,
                'version': '2.0',  # Audit log format version
                'source': 'enhanced-zero-trust-framework'
            }
            
            # Generate integrity hash
            audit_entry['integrityHash'] = self._generate_integrity_hash(audit_entry)
            
            # Store in Firestore
            log_ref = self.db.collection('auditLogs').document(log_id)
            log_ref.set(audit_entry)
            
            # Update metrics
            self.metrics['logs_created'] += 1
            
            # Trigger alerts for high-severity events
            if severity in ['high', 'critical']:
                self._trigger_security_alert(audit_entry)
            
            return log_id
            
        except Exception as e:
            print(f"Error logging comprehensive event: {e}")
            self.metrics['errors'] += 1
            return None
    
    def _sanitize_request_data(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize request data to remove sensitive information"""
        if not request_data:
            return {}
        
        sanitized = {}
        sensitive_fields = ['password', 'token', 'secret', 'key', 'credential']
        
        for key, value in request_data.items():
            if any(sensitive in key.lower() for sensitive in sensitive_fields):
                sanitized[key] = '[REDACTED]'
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_request_data(value)
            elif isinstance(value, str) and len(value) > 1000:
                sanitized[key] = value[:1000] + '...[TRUNCATED]'
            else:
                sanitized[key] = value
        
        return sanitized
    
    def _sanitize_response_data(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize response data to remove sensitive information"""
        if not response_data:
            return {}
        
        sanitized = {}
        sensitive_fields = ['password', 'token', 'secret', 'key', 'credential', 'ssn', 'credit_card']
        
        for key, value in response_data.items():
            if any(sensitive in key.lower() for sensitive in sensitive_fields):
                sanitized[key] = '[REDACTED]'
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_response_data(value)
            elif isinstance(value, str) and len(value) > 1000:
                sanitized[key] = value[:1000] + '...[TRUNCATED]'
            else:
                sanitized[key] = value
        
        return sanitized
    
    def _trigger_security_alert(self, audit_entry: Dict[str, Any]):
        """Trigger security alert for high-severity events"""
        try:
            # Create security event for real-time monitoring
            alert_data = {
                'alertId': str(uuid.uuid4()),
                'auditLogId': audit_entry['logId'],
                'eventType': audit_entry['eventType'],
                'severity': audit_entry['severity'],
                'userId': audit_entry['userId'],
                'action': audit_entry['action'],
                'timestamp': audit_entry['timestamp'],
                'requiresResponse': audit_entry['severity'] == 'critical'
            }
            
            # Store alert
            alert_ref = self.db.collection('securityAlerts').document(alert_data['alertId'])
            alert_ref.set(alert_data)
            
            print(f"Security alert triggered for {audit_entry['severity']} event: {audit_entry['action']}")
            
        except Exception as e:
            print(f"Error triggering security alert: {e}")
    
    def verify_log_integrity(self, log_id: str) -> Tuple[bool, Optional[str]]:
        """
        Verify the integrity of an audit log entry.
        
        Args:
            log_id: Log ID to verify
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # Retrieve log entry
            log_ref = self.db.collection('auditLogs').document(log_id)
            log_doc = log_ref.get()
            
            if not log_doc.exists:
                return False, "Log entry not found"
            
            log_data = log_doc.to_dict()
            stored_hash = log_data.pop('integrityHash', '')
            
            # Recalculate hash
            calculated_hash = self._generate_integrity_hash(log_data)
            
            # Compare hashes
            if stored_hash == calculated_hash:
                self.metrics['integrity_checks'] += 1
                return True, None
            else:
                return False, "Integrity hash mismatch - log may have been tampered with"
                
        except Exception as e:
            return False, f"Error verifying integrity: {e}"
    
    def batch_verify_integrity(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """
        Verify integrity of multiple log entries in a date range.
        
        Args:
            start_date: Start date for verification
            end_date: End date for verification
            
        Returns:
            Dictionary with verification results
        """
        try:
            results = {
                'total_logs': 0,
                'verified_logs': 0,
                'failed_logs': 0,
                'tampered_logs': [],
                'errors': []
            }
            
            # Query logs in date range
            logs_ref = self.db.collection('auditLogs')
            query = logs_ref.where('timestamp', '>=', start_date).where('timestamp', '<=', end_date)
            
            for doc in query.stream():
                results['total_logs'] += 1
                log_data = doc.to_dict()
                
                is_valid, error_msg = self.verify_log_integrity(log_data['logId'])
                
                if is_valid:
                    results['verified_logs'] += 1
                else:
                    results['failed_logs'] += 1
                    results['tampered_logs'].append({
                        'logId': log_data['logId'],
                        'timestamp': log_data['timestamp'],
                        'error': error_msg
                    })
            
            return results
            
        except Exception as e:
            return {'error': f"Batch verification failed: {e}"}
    
    # Convenience methods for specific event types
    def log_device_validation(self, user_id: str, device_id: str, validation_result: bool, 
                            similarity_score: float, ip_address: str = None, **kwargs):
        """Log device fingerprint validation event"""
        return self.log_comprehensive_event(
            event_type='device_registration',
            sub_type='validate',
            user_id=user_id,
            device_id=device_id,
            action=f"Device fingerprint validation {'successful' if validation_result else 'failed'}",
            result='success' if validation_result else 'failure',
            ip_address=ip_address,
            confidence_score=similarity_score,
            severity='low' if validation_result else 'medium',
            additional_details={
                'similarityScore': similarity_score,
                'validationResult': validation_result,
                **kwargs
            }
        )
    
    def log_jit_access_event(self, user_id: str, resource_segment_id: str, action: str, 
                           result: str, session_id: str = None, **kwargs):
        """Log JIT access event"""
        severity_map = {
            'request': 'low',
            'grant': 'medium',
            'deny': 'medium',
            'expire': 'low',
            'revoke': 'high'
        }
        
        return self.log_comprehensive_event(
            event_type='jit_access',
            sub_type=action,
            user_id=user_id,
            resource_segment_id=resource_segment_id,
            session_id=session_id,
            action=f"JIT access {action}",
            result=result,
            severity=severity_map.get(action, 'medium'),
            **kwargs
        )
    
    def log_break_glass_event(self, user_id: str, emergency_type: str, action: str, 
                            result: str, session_id: str = None, **kwargs):
        """Log break-glass emergency access event"""
        return self.log_comprehensive_event(
            event_type='break_glass',
            sub_type=action,
            user_id=user_id,
            action=f"Break-glass {action} for {emergency_type}",
            result=result,
            session_id=session_id,
            severity='high',
            compliance_flags=['SOX', 'ISO27001'],
            retention_category='extended',
            additional_details={'emergency_type': emergency_type, **kwargs}
        )
    
    def log_visitor_activity(self, visitor_id: str, host_id: str, action: str, 
                           result: str, **kwargs):
        """Log visitor management activity"""
        return self.log_comprehensive_event(
            event_type='visitor_management',
            sub_type=action,
            user_id=host_id,
            visitor_id=visitor_id,
            action=f"Visitor {action}",
            result=result,
            severity='low' if result == 'success' else 'medium',
            additional_details=kwargs
        )
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get audit service performance metrics"""
        return {
            **self.metrics,
            'encryption_enabled': self.cipher is not None,
            'geoip_enabled': self.geoip_reader is not None,
            'supported_event_types': len(self.EVENT_TYPES),
            'retention_categories': list(self.RETENTION_CATEGORIES.keys())
        }


# Singleton instance
enhanced_audit_service = EnhancedAuditService()

class AuditRetentionService:
    """
    Service for managing audit log retention, archival, and compliance reporting.
    Implements 7-year retention policy with automated archival to Cloud Storage.
    """
    
    def __init__(self, audit_service: EnhancedAuditService):
        self.audit_service = audit_service
        self.db = audit_service.db
        self.storage_service = audit_service.storage_service
        
        # Retention configuration
        self.retention_policies = {
            'standard': 2555,  # 7 years in days
            'extended': 3653,  # 10 years in days
            'permanent': -1    # Never delete
        }
        
        # Storage thresholds
        self.storage_warning_threshold = 0.8  # 80%
        self.storage_critical_threshold = 0.95  # 95%
        
        # Archival configuration
        self.archival_batch_size = int(os.getenv('ARCHIVAL_BATCH_SIZE', '1000'))
        self.archival_bucket = os.getenv('AUDIT_ARCHIVAL_BUCKET', 'audit-archives')
        
        # Compliance configuration
        self.compliance_officer_email = os.getenv('COMPLIANCE_OFFICER_EMAIL')
        
    def check_storage_capacity(self) -> Dict[str, Any]:
        """
        Check current storage capacity and alert if thresholds are exceeded.
        
        Returns:
            Dictionary with storage information and alerts
        """
        try:
            # Get collection statistics
            logs_ref = self.db.collection('auditLogs')
            
            # Count total documents (this is an approximation)
            total_logs = 0
            batch_size = 1000
            last_doc = None
            
            while True:
                query = logs_ref.limit(batch_size)
                if last_doc:
                    query = query.start_after(last_doc)
                
                docs = list(query.stream())
                if not docs:
                    break
                
                total_logs += len(docs)
                last_doc = docs[-1]
                
                # Break if we have a reasonable sample for estimation
                if total_logs >= 10000:
                    break
            
            # Estimate storage usage (rough calculation)
            # Average audit log size is approximately 2KB
            estimated_size_mb = (total_logs * 2) / 1024
            
            # Get Firestore limits (approximate)
            firestore_limit_mb = 1024 * 1024  # 1TB limit for Firestore
            usage_percentage = estimated_size_mb / firestore_limit_mb
            
            storage_info = {
                'total_logs': total_logs,
                'estimated_size_mb': estimated_size_mb,
                'usage_percentage': usage_percentage,
                'warning_threshold': self.storage_warning_threshold,
                'critical_threshold': self.storage_critical_threshold,
                'needs_attention': usage_percentage >= self.storage_warning_threshold,
                'critical': usage_percentage >= self.storage_critical_threshold
            }
            
            # Send alerts if thresholds exceeded
            if usage_percentage >= self.storage_critical_threshold:
                self._send_storage_alert('critical', storage_info)
            elif usage_percentage >= self.storage_warning_threshold:
                self._send_storage_alert('warning', storage_info)
            
            return storage_info
            
        except Exception as e:
            print(f"Error checking storage capacity: {e}")
            return {'error': str(e)}
    
    def _send_storage_alert(self, alert_type: str, storage_info: Dict[str, Any]):
        """Send storage capacity alert to administrators"""
        try:
            alert_data = {
                'alertId': str(uuid.uuid4()),
                'alertType': 'storage_capacity',
                'severity': alert_type,
                'timestamp': datetime.utcnow(),
                'storageInfo': storage_info,
                'message': f"Audit log storage at {storage_info['usage_percentage']:.1%} capacity"
            }
            
            # Store alert
            alert_ref = self.db.collection('systemAlerts').document(alert_data['alertId'])
            alert_ref.set(alert_data)
            
            print(f"Storage capacity {alert_type} alert sent: {alert_data['message']}")
            
        except Exception as e:
            print(f"Error sending storage alert: {e}")
    
    def archive_old_logs(self, cutoff_date: datetime = None) -> Dict[str, Any]:
        """
        Archive audit logs older than the specified cutoff date to Cloud Storage.
        
        Args:
            cutoff_date: Date before which logs should be archived (default: 90 days ago)
            
        Returns:
            Dictionary with archival results
        """
        try:
            if not cutoff_date:
                cutoff_date = datetime.utcnow() - timedelta(days=self.audit_service.archival_threshold_days)
            
            results = {
                'cutoff_date': cutoff_date,
                'logs_processed': 0,
                'logs_archived': 0,
                'logs_failed': 0,
                'archive_files_created': 0,
                'errors': []
            }
            
            # Query logs older than cutoff date
            logs_ref = self.db.collection('auditLogs')
            query = logs_ref.where('timestamp', '<', cutoff_date).limit(self.archival_batch_size)
            
            batch_number = 0
            
            while True:
                docs = list(query.stream())
                if not docs:
                    break
                
                batch_number += 1
                batch_logs = []
                
                for doc in docs:
                    results['logs_processed'] += 1
                    log_data = doc.to_dict()
                    
                    # Verify integrity before archiving
                    is_valid, error_msg = self.audit_service.verify_log_integrity(log_data['logId'])
                    
                    if is_valid:
                        batch_logs.append(log_data)
                    else:
                        results['logs_failed'] += 1
                        results['errors'].append({
                            'logId': log_data['logId'],
                            'error': f"Integrity check failed: {error_msg}"
                        })
                
                # Archive batch to Cloud Storage
                if batch_logs:
                    archive_success = self._archive_batch_to_storage(batch_logs, batch_number, cutoff_date)
                    
                    if archive_success:
                        results['logs_archived'] += len(batch_logs)
                        results['archive_files_created'] += 1
                        
                        # Delete archived logs from Firestore
                        self._delete_archived_logs([log['logId'] for log in batch_logs])
                    else:
                        results['logs_failed'] += len(batch_logs)
                        results['errors'].append(f"Failed to archive batch {batch_number}")
                
                # Continue with next batch
                if len(docs) < self.archival_batch_size:
                    break
                
                query = logs_ref.where('timestamp', '<', cutoff_date).start_after(docs[-1]).limit(self.archival_batch_size)
            
            # Update metrics
            self.audit_service.metrics['archival_operations'] += 1
            
            return results
            
        except Exception as e:
            return {'error': f"Archival process failed: {e}"}
    
    def _archive_batch_to_storage(self, logs: List[Dict[str, Any]], batch_number: int, cutoff_date: datetime) -> bool:
        """Archive a batch of logs to Cloud Storage"""
        try:
            # Create archive filename
            date_str = cutoff_date.strftime('%Y-%m-%d')
            filename = f"audit-logs-{date_str}-batch-{batch_number:04d}.json"
            
            # Prepare archive data
            archive_data = {
                'metadata': {
                    'archive_date': datetime.utcnow().isoformat(),
                    'cutoff_date': cutoff_date.isoformat(),
                    'batch_number': batch_number,
                    'log_count': len(logs),
                    'format_version': '2.0'
                },
                'logs': logs
            }
            
            # Convert to JSON
            json_data = json.dumps(archive_data, default=str, indent=2)
            
            # Upload to Cloud Storage
            blob_path = f"audit-archives/{date_str[:7]}/{filename}"  # Organize by year-month
            
            success = self.storage_service.upload_file_content(
                content=json_data.encode('utf-8'),
                blob_path=blob_path,
                content_type='application/json'
            )
            
            if success:
                print(f"Archived {len(logs)} logs to {blob_path}")
                return True
            else:
                print(f"Failed to upload archive {filename}")
                return False
                
        except Exception as e:
            print(f"Error archiving batch: {e}")
            return False
    
    def _delete_archived_logs(self, log_ids: List[str]):
        """Delete logs from Firestore after successful archival"""
        try:
            batch = self.db.batch()
            
            for log_id in log_ids:
                log_ref = self.db.collection('auditLogs').document(log_id)
                batch.delete(log_ref)
            
            batch.commit()
            print(f"Deleted {len(log_ids)} archived logs from Firestore")
            
        except Exception as e:
            print(f"Error deleting archived logs: {e}")
    
    def generate_compliance_report(
        self,
        start_date: datetime,
        end_date: datetime,
        event_types: List[str] = None,
        compliance_flags: List[str] = None,
        include_archived: bool = False
    ) -> Dict[str, Any]:
        """
        Generate comprehensive compliance report for specified time period.
        
        Args:
            start_date: Report start date
            end_date: Report end date
            event_types: Filter by specific event types
            compliance_flags: Filter by compliance flags
            include_archived: Whether to include archived logs
            
        Returns:
            Dictionary with compliance report data
        """
        try:
            report_start_time = datetime.utcnow()
            
            report = {
                'metadata': {
                    'report_id': str(uuid.uuid4()),
                    'generated_at': report_start_time,
                    'start_date': start_date,
                    'end_date': end_date,
                    'event_types_filter': event_types,
                    'compliance_flags_filter': compliance_flags,
                    'include_archived': include_archived,
                    'generation_time_seconds': None
                },
                'summary': {
                    'total_events': 0,
                    'events_by_type': {},
                    'events_by_severity': {},
                    'events_by_result': {},
                    'unique_users': set(),
                    'unique_devices': set(),
                    'compliance_events': 0
                },
                'security_events': [],
                'policy_changes': [],
                'access_violations': [],
                'integrity_status': {
                    'total_verified': 0,
                    'total_failed': 0,
                    'tampered_logs': []
                },
                'compliance_analysis': {},
                'recommendations': []
            }
            
            # Query active logs
            logs_ref = self.db.collection('auditLogs')
            query = logs_ref.where('timestamp', '>=', start_date).where('timestamp', '<=', end_date)
            
            # Apply filters
            if event_types:
                # Note: Firestore doesn't support IN queries with more than 10 values
                # For production, implement batch queries
                if len(event_types) <= 10:
                    query = query.where('eventType', 'in', event_types)
            
            # Process logs
            for doc in query.stream():
                log_data = doc.to_dict()
                self._process_log_for_report(log_data, report, compliance_flags)
            
            # Include archived logs if requested
            if include_archived:
                archived_logs = self._retrieve_archived_logs(start_date, end_date)
                for log_data in archived_logs:
                    self._process_log_for_report(log_data, report, compliance_flags)
            
            # Finalize report
            report['summary']['unique_users'] = len(report['summary']['unique_users'])
            report['summary']['unique_devices'] = len(report['summary']['unique_devices'])
            
            # Generate compliance analysis
            report['compliance_analysis'] = self._analyze_compliance_data(report)
            
            # Generate recommendations
            report['recommendations'] = self._generate_compliance_recommendations(report)
            
            # Calculate generation time
            generation_time = (datetime.utcnow() - report_start_time).total_seconds()
            report['metadata']['generation_time_seconds'] = generation_time
            
            # Verify generation time requirement (within 30 seconds)
            if generation_time > 30:
                print(f"Warning: Report generation took {generation_time:.2f} seconds (exceeds 30s requirement)")
            
            return report
            
        except Exception as e:
            return {'error': f"Compliance report generation failed: {e}"}
    
    def _process_log_for_report(self, log_data: Dict[str, Any], report: Dict[str, Any], compliance_flags: List[str] = None):
        """Process individual log entry for compliance report"""
        try:
            # Update summary statistics
            report['summary']['total_events'] += 1
            
            event_type = log_data.get('eventType', 'unknown')
            severity = log_data.get('severity', 'low')
            result = log_data.get('result', 'unknown')
            
            # Count by type
            report['summary']['events_by_type'][event_type] = report['summary']['events_by_type'].get(event_type, 0) + 1
            
            # Count by severity
            report['summary']['events_by_severity'][severity] = report['summary']['events_by_severity'].get(severity, 0) + 1
            
            # Count by result
            report['summary']['events_by_result'][result] = report['summary']['events_by_result'].get(result, 0) + 1
            
            # Track unique users and devices
            if log_data.get('userId'):
                report['summary']['unique_users'].add(log_data['userId'])
            
            if log_data.get('deviceId'):
                report['summary']['unique_devices'].add(log_data['deviceId'])
            
            # Check compliance flags
            log_compliance_flags = log_data.get('complianceFlags', [])
            if log_compliance_flags:
                report['summary']['compliance_events'] += 1
                
                # Filter by compliance flags if specified
                if compliance_flags and not any(flag in log_compliance_flags for flag in compliance_flags):
                    return
            
            # Categorize significant events
            if severity in ['high', 'critical']:
                report['security_events'].append({
                    'logId': log_data['logId'],
                    'timestamp': log_data['timestamp'],
                    'eventType': event_type,
                    'severity': severity,
                    'action': log_data.get('action', ''),
                    'userId': log_data.get('userId', ''),
                    'result': result
                })
            
            if event_type == 'policy_change':
                report['policy_changes'].append({
                    'logId': log_data['logId'],
                    'timestamp': log_data['timestamp'],
                    'action': log_data.get('action', ''),
                    'userId': log_data.get('userId', ''),
                    'details': log_data.get('details', {})
                })
            
            if result in ['denied', 'failure'] and event_type in ['access_request', 'jit_access', 'break_glass']:
                report['access_violations'].append({
                    'logId': log_data['logId'],
                    'timestamp': log_data['timestamp'],
                    'eventType': event_type,
                    'action': log_data.get('action', ''),
                    'userId': log_data.get('userId', ''),
                    'reason': log_data.get('details', {}).get('reason', 'Unknown')
                })
            
            # Verify integrity
            is_valid, error_msg = self.audit_service.verify_log_integrity(log_data['logId'])
            if is_valid:
                report['integrity_status']['total_verified'] += 1
            else:
                report['integrity_status']['total_failed'] += 1
                report['integrity_status']['tampered_logs'].append({
                    'logId': log_data['logId'],
                    'timestamp': log_data['timestamp'],
                    'error': error_msg
                })
            
        except Exception as e:
            print(f"Error processing log for report: {e}")
    
    def _retrieve_archived_logs(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """Retrieve archived logs for the specified date range"""
        try:
            archived_logs = []
            
            # List archive files in the date range
            # This is a simplified implementation - in production, implement proper date-based filtering
            archive_files = self.storage_service.list_files(f"audit-archives/")
            
            for file_path in archive_files:
                try:
                    # Download and parse archive file
                    content = self.storage_service.download_file_content(file_path)
                    if content:
                        archive_data = json.loads(content.decode('utf-8'))
                        
                        # Filter logs by date range
                        for log_data in archive_data.get('logs', []):
                            log_timestamp = datetime.fromisoformat(log_data['timestamp'].replace('Z', '+00:00'))
                            if start_date <= log_timestamp <= end_date:
                                archived_logs.append(log_data)
                
                except Exception as e:
                    print(f"Error processing archive file {file_path}: {e}")
            
            return archived_logs
            
        except Exception as e:
            print(f"Error retrieving archived logs: {e}")
            return []
    
    def _analyze_compliance_data(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze compliance data and generate insights"""
        try:
            analysis = {
                'risk_assessment': 'low',
                'security_posture': 'good',
                'compliance_score': 0,
                'key_findings': [],
                'trend_analysis': {}
            }
            
            total_events = report['summary']['total_events']
            security_events = len(report['security_events'])
            access_violations = len(report['access_violations'])
            integrity_failures = report['integrity_status']['total_failed']
            
            # Calculate compliance score (0-100)
            compliance_score = 100
            
            if total_events > 0:
                # Deduct points for security issues
                security_event_ratio = security_events / total_events
                violation_ratio = access_violations / total_events
                integrity_failure_ratio = integrity_failures / total_events if total_events > 0 else 0
                
                compliance_score -= (security_event_ratio * 30)  # Max 30 points for security events
                compliance_score -= (violation_ratio * 25)       # Max 25 points for violations
                compliance_score -= (integrity_failure_ratio * 45)  # Max 45 points for integrity failures
            
            analysis['compliance_score'] = max(0, min(100, compliance_score))
            
            # Risk assessment
            if compliance_score >= 90:
                analysis['risk_assessment'] = 'low'
                analysis['security_posture'] = 'excellent'
            elif compliance_score >= 75:
                analysis['risk_assessment'] = 'medium'
                analysis['security_posture'] = 'good'
            elif compliance_score >= 60:
                analysis['risk_assessment'] = 'high'
                analysis['security_posture'] = 'fair'
            else:
                analysis['risk_assessment'] = 'critical'
                analysis['security_posture'] = 'poor'
            
            # Key findings
            if security_events > 0:
                analysis['key_findings'].append(f"{security_events} high-severity security events detected")
            
            if access_violations > 0:
                analysis['key_findings'].append(f"{access_violations} access violations recorded")
            
            if integrity_failures > 0:
                analysis['key_findings'].append(f"{integrity_failures} audit log integrity failures detected")
            
            return analysis
            
        except Exception as e:
            return {'error': f"Compliance analysis failed: {e}"}
    
    def _generate_compliance_recommendations(self, report: Dict[str, Any]) -> List[str]:
        """Generate compliance recommendations based on report data"""
        try:
            recommendations = []
            
            # Check for integrity issues
            if report['integrity_status']['total_failed'] > 0:
                recommendations.append("Investigate audit log integrity failures immediately")
                recommendations.append("Review access controls for audit log storage")
            
            # Check for security events
            security_events = len(report['security_events'])
            if security_events > 10:
                recommendations.append("High number of security events - review security policies")
            
            # Check for access violations
            violations = len(report['access_violations'])
            if violations > 5:
                recommendations.append("Multiple access violations detected - review user permissions")
            
            # Check compliance score
            compliance_score = report.get('compliance_analysis', {}).get('compliance_score', 100)
            if compliance_score < 75:
                recommendations.append("Compliance score below threshold - implement corrective measures")
            
            # General recommendations
            if not recommendations:
                recommendations.append("Audit posture is good - continue monitoring")
            
            recommendations.append("Schedule regular compliance reviews")
            recommendations.append("Ensure audit log retention policies are followed")
            
            return recommendations
            
        except Exception as e:
            return [f"Error generating recommendations: {e}"]
    
    def export_audit_data(
        self,
        start_date: datetime,
        end_date: datetime,
        format_type: str = 'json',
        event_types: List[str] = None,
        include_archived: bool = False
    ) -> Optional[str]:
        """
        Export audit data for compliance officers.
        
        Args:
            start_date: Export start date
            end_date: Export end date
            format_type: Export format ('json', 'csv')
            event_types: Filter by event types
            include_archived: Include archived logs
            
        Returns:
            File path of exported data or None if failed
        """
        try:
            export_id = str(uuid.uuid4())
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f"audit_export_{timestamp}_{export_id}.{format_type}"
            
            # Collect data
            export_data = {
                'metadata': {
                    'export_id': export_id,
                    'generated_at': datetime.utcnow().isoformat(),
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat(),
                    'format': format_type,
                    'event_types_filter': event_types,
                    'include_archived': include_archived
                },
                'logs': []
            }
            
            # Query active logs
            logs_ref = self.db.collection('auditLogs')
            query = logs_ref.where('timestamp', '>=', start_date).where('timestamp', '<=', end_date)
            
            if event_types and len(event_types) <= 10:
                query = query.where('eventType', 'in', event_types)
            
            for doc in query.stream():
                log_data = doc.to_dict()
                # Convert timestamp to string for JSON serialization
                if 'timestamp' in log_data:
                    log_data['timestamp'] = log_data['timestamp'].isoformat()
                export_data['logs'].append(log_data)
            
            # Include archived logs if requested
            if include_archived:
                archived_logs = self._retrieve_archived_logs(start_date, end_date)
                export_data['logs'].extend(archived_logs)
            
            # Export to Cloud Storage
            if format_type == 'json':
                content = json.dumps(export_data, indent=2, default=str)
                content_type = 'application/json'
            elif format_type == 'csv':
                content = self._convert_to_csv(export_data['logs'])
                content_type = 'text/csv'
            else:
                raise ValueError(f"Unsupported format: {format_type}")
            
            # Upload to storage
            blob_path = f"audit-exports/{filename}"
            success = self.storage_service.upload_file_content(
                content=content.encode('utf-8'),
                blob_path=blob_path,
                content_type=content_type
            )
            
            if success:
                print(f"Audit data exported to {blob_path}")
                return blob_path
            else:
                print("Failed to upload export file")
                return None
                
        except Exception as e:
            print(f"Error exporting audit data: {e}")
            return None
    
    def _convert_to_csv(self, logs: List[Dict[str, Any]]) -> str:
        """Convert logs to CSV format"""
        try:
            import csv
            from io import StringIO
            
            if not logs:
                return ""
            
            output = StringIO()
            
            # Get all possible field names
            fieldnames = set()
            for log in logs:
                fieldnames.update(log.keys())
            
            fieldnames = sorted(list(fieldnames))
            
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            
            for log in logs:
                # Flatten nested objects for CSV
                flattened_log = {}
                for key, value in log.items():
                    if isinstance(value, (dict, list)):
                        flattened_log[key] = json.dumps(value)
                    else:
                        flattened_log[key] = value
                
                writer.writerow(flattened_log)
            
            return output.getvalue()
            
        except Exception as e:
            print(f"Error converting to CSV: {e}")
            return ""


# Singleton instance
audit_retention_service = AuditRetentionService(enhanced_audit_service)