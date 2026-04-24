"""
Automated Threat Detection and Response Service
Implements automated threat detection and response capabilities for the Enhanced Zero Trust Framework
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
import json
import logging
from collections import defaultdict

from app.firebase_config import db
from app.models.threat_prediction import ThreatPrediction, ThreatIndicator
from app.models.device_fingerprint import DeviceFingerprint
from app.models.resource_segment import ResourceSegment
from app.models.notification import create_notification
from app.services.enhanced_audit_service import enhanced_audit_service
from app.services.realtime_event_service import realtime_event_processor

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AutomatedThreatResponse:
    """Service for automated threat detection and response"""
    
    def __init__(self):
        self.failed_attempt_threshold = 10  # Failed attempts within time window
        self.time_window_minutes = 10  # Time window for failed attempts
        self.coordinated_attack_threshold = 3  # Minimum users for coordinated attack
        self.coordinated_attack_attempts = 5  # Minimum attempts per user
        self.blocked_devices = set()  # In-memory cache of blocked devices
        self.locked_segments = set()  # In-memory cache of locked segments
        
    # ==================== Device-Based Threat Detection ====================
    
    async def detect_multiple_failed_attempts(self, device_fingerprint: str = None) -> List[Dict]:
        """
        Detect multiple failed access attempts from same device within 10 minutes
        
        Args:
            device_fingerprint: Optional specific device to check
            
        Returns:
            List of detected threats
        """
        try:
            cutoff_time = datetime.utcnow() - timedelta(minutes=self.time_window_minutes)
            
            # Query failed access attempts
            query = db.collection('audit_logs')\
                     .where('result', '==', 'failure')\
                     .where('timestamp', '>=', cutoff_time)
            
            if device_fingerprint:
                query = query.where('device_fingerprint', '==', device_fingerprint)
            
            docs = query.stream()
            
            # Group by device fingerprint
            device_failures = defaultdict(list)
            
            for doc in docs:
                data = doc.to_dict()
                device_fp = data.get('device_fingerprint')
                if device_fp:
                    device_failures[device_fp].append(data)
            
            threats = []
            
            for device_fp, failures in device_failures.items():
                if len(failures) >= self.failed_attempt_threshold:
                    # Create threat detection
                    threat = {
                        'threat_type': 'multiple_failed_attempts',
                        'device_fingerprint': device_fp,
                        'failed_attempts': len(failures),
                        'time_window_minutes': self.time_window_minutes,
                        'severity': 'high',
                        'detected_at': datetime.utcnow().isoformat(),
                        'user_ids': list(set(f.get('user_id') for f in failures if f.get('user_id'))),
                        'ip_addresses': list(set(f.get('ip_address') for f in failures if f.get('ip_address'))),
                        'failure_details': failures
                    }
                    
                    threats.append(threat)
                    
                    # Automatically block device and alert administrators
                    await self.block_device_fingerprint(device_fp, threat)
                    await self.alert_administrators(threat)
            
            return threats
            
        except Exception as e:
            logger.error(f"Error detecting multiple failed attempts: {e}")
            return []
    
    async def block_device_fingerprint(self, device_fingerprint: str, threat_data: Dict) -> bool:
        """
        Automatically block device fingerprint and alert administrators
        
        Args:
            device_fingerprint: Device fingerprint to block
            threat_data: Threat detection data
            
        Returns:
            bool: True if successful
        """
        try:
            # Add to blocked devices cache
            self.blocked_devices.add(device_fingerprint)
            
            # Update device fingerprint in database
            device_query = db.collection('device_fingerprints')\
                            .where('fingerprint_hash', '==', device_fingerprint)
            
            device_docs = device_query.stream()
            
            for device_doc in device_docs:
                device_ref = db.collection('device_fingerprints').document(device_doc.id)
                device_ref.update({
                    'is_blocked': True,
                    'blocked_at': datetime.utcnow(),
                    'blocked_reason': f"Automated block: {threat_data['failed_attempts']} failed attempts in {threat_data['time_window_minutes']} minutes",
                    'threat_detection_id': threat_data.get('detection_id')
                })
            
            # Create security event
            security_event = {
                'event_type': 'device_blocked',
                'severity': 'high',
                'device_fingerprint': device_fingerprint,
                'threat_data': threat_data,
                'automatic_action': True,
                'timestamp': datetime.utcnow()
            }
            
            # Log to audit system
            enhanced_audit_service.log_security_event(
                event_type='automated_device_block',
                severity='high',
                details={
                    'device_fingerprint': device_fingerprint,
                    'failed_attempts': threat_data['failed_attempts'],
                    'time_window': threat_data['time_window_minutes'],
                    'affected_users': threat_data.get('user_ids', [])
                }
            )
            
            # Broadcast real-time event
            await realtime_event_processor.broadcast_security_event(security_event)
            
            logger.info(f"Device fingerprint {device_fingerprint} blocked automatically")
            return True
            
        except Exception as e:
            logger.error(f"Error blocking device fingerprint: {e}")
            return False
    
    # ==================== Coordinated Attack Detection ====================
    
    async def detect_coordinated_attacks(self) -> List[Dict]:
        """
        Identify coordinated attack patterns across multiple accounts
        
        Returns:
            List of detected coordinated attacks
        """
        try:
            cutoff_time = datetime.utcnow() - timedelta(minutes=self.time_window_minutes)
            
            # Query recent failed/denied attempts
            query = db.collection('audit_logs')\
                     .where('result', 'in', ['failure', 'denied'])\
                     .where('timestamp', '>=', cutoff_time)\
                     .limit(1000)
            
            docs = query.stream()
            
            # Group by resource and action patterns
            attack_patterns = defaultdict(lambda: {
                'users': set(),
                'attempts': [],
                'ip_addresses': set(),
                'device_fingerprints': set()
            })
            
            for doc in docs:
                data = doc.to_dict()
                resource_type = data.get('resource_type', 'unknown')
                action = data.get('action', 'unknown')
                user_id = data.get('user_id')
                ip_address = data.get('ip_address')
                device_fp = data.get('device_fingerprint')
                
                pattern_key = f"{resource_type}:{action}"
                
                if user_id:
                    attack_patterns[pattern_key]['users'].add(user_id)
                if ip_address:
                    attack_patterns[pattern_key]['ip_addresses'].add(ip_address)
                if device_fp:
                    attack_patterns[pattern_key]['device_fingerprints'].add(device_fp)
                
                attack_patterns[pattern_key]['attempts'].append(data)
            
            coordinated_attacks = []
            
            for pattern_key, pattern_data in attack_patterns.items():
                user_count = len(pattern_data['users'])
                attempt_count = len(pattern_data['attempts'])
                
                # Check for coordinated attack criteria
                if (user_count >= self.coordinated_attack_threshold and 
                    attempt_count >= self.coordinated_attack_attempts * user_count):
                    
                    resource_type, action = pattern_key.split(':', 1)
                    
                    attack = {
                        'threat_type': 'coordinated_attack',
                        'resource_type': resource_type,
                        'action': action,
                        'user_count': user_count,
                        'attempt_count': attempt_count,
                        'severity': 'critical',
                        'detected_at': datetime.utcnow().isoformat(),
                        'users': list(pattern_data['users']),
                        'ip_addresses': list(pattern_data['ip_addresses']),
                        'device_fingerprints': list(pattern_data['device_fingerprints']),
                        'time_window_minutes': self.time_window_minutes
                    }
                    
                    coordinated_attacks.append(attack)
                    
                    # Implement temporary lockdown of affected resource segments
                    await self.implement_temporary_lockdown(resource_type, attack)
                    await self.alert_administrators(attack)
            
            return coordinated_attacks
            
        except Exception as e:
            logger.error(f"Error detecting coordinated attacks: {e}")
            return []
    
    async def implement_temporary_lockdown(self, resource_type: str, attack_data: Dict) -> bool:
        """
        Implement temporary lockdowns of affected Resource_Segments
        
        Args:
            resource_type: Type of resource under attack
            attack_data: Attack detection data
            
        Returns:
            bool: True if successful
        """
        try:
            # Find resource segments of the attacked type
            resource_query = db.collection('resource_segments')\
                              .where('category', '==', resource_type)
            
            resource_docs = resource_query.stream()
            
            lockdown_duration = timedelta(hours=1)  # 1-hour temporary lockdown
            lockdown_end = datetime.utcnow() + lockdown_duration
            
            locked_segments = []
            
            for resource_doc in resource_docs:
                resource_data = resource_doc.to_dict()
                segment_id = resource_data.get('segment_id')
                
                if segment_id:
                    # Add to locked segments cache
                    self.locked_segments.add(segment_id)
                    
                    # Update resource segment with temporary lockdown
                    resource_ref = db.collection('resource_segments').document(resource_doc.id)
                    resource_ref.update({
                        'temporary_lockdown': True,
                        'lockdown_start': datetime.utcnow(),
                        'lockdown_end': lockdown_end,
                        'lockdown_reason': f"Coordinated attack detected: {attack_data['user_count']} users, {attack_data['attempt_count']} attempts",
                        'lockdown_threat_id': attack_data.get('detection_id')
                    })
                    
                    locked_segments.append(segment_id)
            
            # Create security event
            security_event = {
                'event_type': 'resource_lockdown',
                'severity': 'critical',
                'resource_type': resource_type,
                'locked_segments': locked_segments,
                'lockdown_duration_hours': 1,
                'attack_data': attack_data,
                'automatic_action': True,
                'timestamp': datetime.utcnow()
            }
            
            # Log to audit system
            enhanced_audit_service.log_security_event(
                event_type='automated_resource_lockdown',
                severity='critical',
                details={
                    'resource_type': resource_type,
                    'locked_segments': locked_segments,
                    'attack_user_count': attack_data['user_count'],
                    'attack_attempt_count': attack_data['attempt_count'],
                    'lockdown_duration_hours': 1
                }
            )
            
            # Broadcast real-time event
            await realtime_event_processor.broadcast_security_event(security_event)
            
            logger.info(f"Temporary lockdown implemented for {len(locked_segments)} segments of type {resource_type}")
            return True
            
        except Exception as e:
            logger.error(f"Error implementing temporary lockdown: {e}")
            return False
    
    # ==================== Administrator Alerting ====================
    
    async def alert_administrators(self, threat_data: Dict) -> bool:
        """
        Send immediate alerts to administrators for detected threats
        
        Args:
            threat_data: Threat detection data
            
        Returns:
            bool: True if alerts sent successfully
        """
        try:
            # Get all admin users
            admin_query = db.collection('users').where('role', '==', 'admin')
            admin_docs = admin_query.stream()
            
            alert_title = self._generate_alert_title(threat_data)
            alert_message = self._generate_alert_message(threat_data)
            
            alerts_sent = 0
            
            for admin_doc in admin_docs:
                admin_data = admin_doc.to_dict()
                admin_id = admin_data.get('user_id') or admin_data.get('uid')
                
                if admin_id:
                    # Create high-priority notification
                    notification_created = create_notification(
                        user_id=admin_id,
                        title=alert_title,
                        message=alert_message,
                        notification_type='security_alert',
                        priority='critical',
                        metadata={
                            'threat_type': threat_data.get('threat_type'),
                            'severity': threat_data.get('severity'),
                            'detection_time': threat_data.get('detected_at'),
                            'automatic_response': True
                        }
                    )
                    
                    if notification_created:
                        alerts_sent += 1
            
            # Also create system-wide security alert
            security_alert = {
                'alert_type': 'automated_threat_detection',
                'threat_data': threat_data,
                'administrators_notified': alerts_sent,
                'timestamp': datetime.utcnow()
            }
            
            # Store alert in security events collection
            db.collection('security_alerts').add(security_alert)
            
            logger.info(f"Administrators alerted: {alerts_sent} notifications sent for {threat_data.get('threat_type')}")
            return alerts_sent > 0
            
        except Exception as e:
            logger.error(f"Error alerting administrators: {e}")
            return False
    
    def _generate_alert_title(self, threat_data: Dict) -> str:
        """Generate alert title based on threat type"""
        threat_type = threat_data.get('threat_type', 'unknown')
        
        if threat_type == 'multiple_failed_attempts':
            return f"🚨 Device Blocked: {threat_data.get('failed_attempts')} Failed Attempts"
        elif threat_type == 'coordinated_attack':
            return f"🚨 Coordinated Attack: {threat_data.get('user_count')} Users Involved"
        else:
            return f"🚨 Security Threat Detected: {threat_type}"
    
    def _generate_alert_message(self, threat_data: Dict) -> str:
        """Generate detailed alert message"""
        threat_type = threat_data.get('threat_type', 'unknown')
        
        if threat_type == 'multiple_failed_attempts':
            return (f"Device fingerprint automatically blocked due to {threat_data.get('failed_attempts')} "
                   f"failed attempts in {threat_data.get('time_window_minutes')} minutes. "
                   f"Affected users: {len(threat_data.get('user_ids', []))}")
        
        elif threat_type == 'coordinated_attack':
            return (f"Coordinated attack detected targeting {threat_data.get('resource_type')} resources. "
                   f"{threat_data.get('user_count')} users made {threat_data.get('attempt_count')} attempts. "
                   f"Temporary lockdown implemented.")
        
        else:
            return f"Automated threat detection triggered. Threat type: {threat_type}. Immediate review required."
    
    # ==================== Threat Response Orchestration ====================
    
    async def run_automated_detection_cycle(self) -> Dict:
        """
        Run complete automated threat detection cycle
        
        Returns:
            Dict with detection results
        """
        try:
            detection_start = datetime.utcnow()
            
            # Run all detection algorithms
            failed_attempt_threats = await self.detect_multiple_failed_attempts()
            coordinated_attack_threats = await self.detect_coordinated_attacks()
            
            all_threats = failed_attempt_threats + coordinated_attack_threats
            
            # Create threat predictions for high-severity threats
            for threat in all_threats:
                if threat.get('severity') in ['high', 'critical']:
                    await self._create_threat_prediction(threat)
            
            detection_end = datetime.utcnow()
            detection_duration = (detection_end - detection_start).total_seconds()
            
            results = {
                'detection_cycle_completed': True,
                'detection_start': detection_start.isoformat(),
                'detection_end': detection_end.isoformat(),
                'detection_duration_seconds': detection_duration,
                'threats_detected': len(all_threats),
                'failed_attempt_threats': len(failed_attempt_threats),
                'coordinated_attack_threats': len(coordinated_attack_threats),
                'devices_blocked': len([t for t in failed_attempt_threats if t.get('device_fingerprint')]),
                'segments_locked': len([t for t in coordinated_attack_threats if t.get('resource_type')]),
                'threats': all_threats
            }
            
            # Log detection cycle completion
            enhanced_audit_service.log_security_event(
                event_type='automated_detection_cycle',
                severity='info',
                details=results
            )
            
            return results
            
        except Exception as e:
            logger.error(f"Error in automated detection cycle: {e}")
            return {
                'detection_cycle_completed': False,
                'error': str(e)
            }
    
    async def _create_threat_prediction(self, threat_data: Dict) -> bool:
        """Create threat prediction from detected threat"""
        try:
            # Map threat data to prediction format
            threat_type = threat_data.get('threat_type')
            severity = threat_data.get('severity', 'medium')
            
            # Calculate confidence based on threat characteristics
            confidence = self._calculate_threat_confidence(threat_data)
            
            # Generate preventive measures
            preventive_measures = self._generate_threat_preventive_measures(threat_data)
            
            # Create threat prediction
            prediction = ThreatPrediction(
                user_id=threat_data.get('user_ids', [None])[0],  # Primary affected user
                threat_type=threat_type,
                confidence=confidence,
                threat_score=self._calculate_threat_score(threat_data),
                indicators=[{
                    'type': threat_type,
                    'severity': severity,
                    'description': self._generate_alert_message(threat_data),
                    'detected_at': threat_data.get('detected_at')
                }],
                preventive_measures=preventive_measures,
                status='confirmed'  # Automatically confirmed since detected by system
            )
            
            return prediction.save()
            
        except Exception as e:
            logger.error(f"Error creating threat prediction: {e}")
            return False
    
    def _calculate_threat_confidence(self, threat_data: Dict) -> float:
        """Calculate confidence score for threat"""
        base_confidence = 0.7
        
        threat_type = threat_data.get('threat_type')
        
        if threat_type == 'multiple_failed_attempts':
            failed_attempts = threat_data.get('failed_attempts', 0)
            # Higher confidence for more failed attempts
            confidence = min(base_confidence + (failed_attempts - 10) * 0.02, 0.95)
        
        elif threat_type == 'coordinated_attack':
            user_count = threat_data.get('user_count', 0)
            attempt_count = threat_data.get('attempt_count', 0)
            # Higher confidence for more users and attempts
            confidence = min(base_confidence + (user_count * 0.05) + (attempt_count * 0.001), 0.98)
        
        else:
            confidence = base_confidence
        
        return round(confidence, 2)
    
    def _calculate_threat_score(self, threat_data: Dict) -> int:
        """Calculate numerical threat score"""
        base_score = 50
        
        threat_type = threat_data.get('threat_type')
        severity = threat_data.get('severity', 'medium')
        
        # Severity multiplier
        severity_multipliers = {'low': 1.0, 'medium': 1.5, 'high': 2.0, 'critical': 2.5}
        multiplier = severity_multipliers.get(severity, 1.0)
        
        if threat_type == 'multiple_failed_attempts':
            failed_attempts = threat_data.get('failed_attempts', 0)
            score = base_score + (failed_attempts * 2)
        
        elif threat_type == 'coordinated_attack':
            user_count = threat_data.get('user_count', 0)
            attempt_count = threat_data.get('attempt_count', 0)
            score = base_score + (user_count * 10) + (attempt_count * 0.5)
        
        else:
            score = base_score
        
        return min(int(score * multiplier), 100)
    
    def _generate_threat_preventive_measures(self, threat_data: Dict) -> List[str]:
        """Generate preventive measures for threat"""
        measures = []
        threat_type = threat_data.get('threat_type')
        
        if threat_type == 'multiple_failed_attempts':
            measures.extend([
                'Device fingerprint has been automatically blocked',
                'Review user accounts associated with blocked device',
                'Monitor for additional attempts from related IP addresses',
                'Consider implementing additional MFA requirements',
                'Investigate potential credential compromise'
            ])
        
        elif threat_type == 'coordinated_attack':
            measures.extend([
                'Temporary lockdown implemented on affected resource segments',
                'Review and strengthen access policies for targeted resources',
                'Investigate user accounts involved in coordinated attempts',
                'Consider implementing network-level IP blocking',
                'Review system logs for additional attack vectors',
                'Notify security team for incident response coordination'
            ])
        
        return measures
    
    # ==================== Status and Management ====================
    
    def get_blocked_devices(self) -> List[str]:
        """Get list of currently blocked device fingerprints"""
        return list(self.blocked_devices)
    
    def get_locked_segments(self) -> List[str]:
        """Get list of currently locked resource segments"""
        return list(self.locked_segments)
    
    async def unblock_device(self, device_fingerprint: str, admin_user_id: str) -> bool:
        """Manually unblock a device fingerprint"""
        try:
            # Remove from blocked devices cache
            self.blocked_devices.discard(device_fingerprint)
            
            # Update device fingerprint in database
            device_query = db.collection('device_fingerprints')\
                            .where('fingerprint_hash', '==', device_fingerprint)
            
            device_docs = device_query.stream()
            
            for device_doc in device_docs:
                device_ref = db.collection('device_fingerprints').document(device_doc.id)
                device_ref.update({
                    'is_blocked': False,
                    'unblocked_at': datetime.utcnow(),
                    'unblocked_by': admin_user_id
                })
            
            # Log the action
            enhanced_audit_service.log_security_event(
                event_type='device_unblocked',
                severity='info',
                user_id=admin_user_id,
                details={
                    'device_fingerprint': device_fingerprint,
                    'unblocked_by': admin_user_id
                }
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Error unblocking device: {e}")
            return False
    
    async def unlock_resource_segment(self, segment_id: str, admin_user_id: str) -> bool:
        """Manually unlock a resource segment"""
        try:
            # Remove from locked segments cache
            self.locked_segments.discard(segment_id)
            
            # Update resource segment in database
            segment_ref = db.collection('resource_segments').document(segment_id)
            segment_ref.update({
                'temporary_lockdown': False,
                'unlocked_at': datetime.utcnow(),
                'unlocked_by': admin_user_id
            })
            
            # Log the action
            enhanced_audit_service.log_security_event(
                event_type='resource_segment_unlocked',
                severity='info',
                user_id=admin_user_id,
                details={
                    'segment_id': segment_id,
                    'unlocked_by': admin_user_id
                }
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Error unlocking resource segment: {e}")
            return False


# Global service instance
automated_threat_response = AutomatedThreatResponse()