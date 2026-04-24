"""
Real-Time Event Processing Service
Processes and distributes real-time security events for dashboard updates
Handles heatmap updates, alert broadcasting, and event aggregation
Requirements: 7.3
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import json
import uuid
from collections import defaultdict, deque
import threading
import time

from app.firebase_config import db
from app.services.audit_logger import audit_logger
from websocket_config import socketio, emit_admin_notification

logger = logging.getLogger(__name__)

class RealTimeEventProcessor:
    """
    Real-time event processor for security events and heatmap updates
    Processes events within 10 seconds and broadcasts to administrators
    """
    
    def __init__(self):
        self.event_queue = deque()
        self.processing_lock = threading.Lock()
        self.heatmap_cache = {}
        self.activity_metrics = defaultdict(int)
        self.alert_history = deque(maxlen=1000)  # Keep last 1000 alerts
        self.coordinated_attack_tracker = defaultdict(list)
        self.processing_thread = None
        self.is_running = False
        
        # Event type mappings for heatmap visualization
        self.event_severity_mapping = {
            'device_mismatch': 'high',
            'route_deviation': 'medium',
            'jit_request': 'low',
            'break_glass': 'critical',
            'risk_elevation': 'high',
            'anomaly_detected': 'medium',
            'failed_login': 'medium',
            'unauthorized_access': 'high',
            'policy_violation': 'medium',
            'session_terminated': 'high'
        }
        
        # Coordinate generation for different event types
        self.event_coordinates = {
            'device_mismatch': {'base_x': 100, 'base_y': 100, 'spread': 50},
            'route_deviation': {'base_x': 200, 'base_y': 150, 'spread': 75},
            'jit_request': {'base_x': 300, 'base_y': 200, 'spread': 60},
            'break_glass': {'base_x': 400, 'base_y': 100, 'spread': 40},
            'risk_elevation': {'base_x': 150, 'base_y': 250, 'spread': 80},
            'anomaly_detected': {'base_x': 350, 'base_y': 300, 'spread': 70}
        }
    
    def start_processing(self):
        """Start the background event processing thread"""
        if not self.is_running:
            self.is_running = True
            self.processing_thread = threading.Thread(target=self._process_events_loop, daemon=True)
            self.processing_thread.start()
            logger.info("Real-time event processor started")
    
    def stop_processing(self):
        """Stop the background event processing"""
        self.is_running = False
        if self.processing_thread:
            self.processing_thread.join(timeout=5)
        logger.info("Real-time event processor stopped")
    
    def process_security_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process incoming security event and update heatmap
        
        Args:
            event_data: Security event data
            
        Returns:
            dict: Processing result with heatmap data
        """
        try:
            # Enrich event data
            enriched_event = self._enrich_event_data(event_data)
            
            # Add to processing queue
            with self.processing_lock:
                self.event_queue.append(enriched_event)
            
            # Update real-time metrics
            self._update_activity_metrics(enriched_event)
            
            # Check for alert conditions
            if self._should_generate_alert(enriched_event):
                alert = self._create_alert(enriched_event)
                self._broadcast_alert(alert)
            
            # Update heatmap data
            heatmap_data = self._update_heatmap_data(enriched_event)
            
            # Store event for historical analysis
            self._store_event(enriched_event)
            
            # Broadcast to connected administrators
            self._broadcast_to_administrators(enriched_event, heatmap_data)
            
            # Check for coordinated attacks
            self._check_coordinated_attacks(enriched_event)
            
            return {
                'success': True,
                'event_id': enriched_event['eventId'],
                'heatmap_data': heatmap_data,
                'alert_generated': self._should_generate_alert(enriched_event)
            }
            
        except Exception as e:
            logger.error(f"Error processing security event: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _enrich_event_data(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich event data with additional context and metadata"""
        enriched = {
            'eventId': event_data.get('eventId') or str(uuid.uuid4()),
            'eventType': event_data.get('eventType', 'unknown'),
            'severity': event_data.get('severity') or self._determine_severity(event_data),
            'timestamp': event_data.get('timestamp') or datetime.utcnow().isoformat(),
            'userId': event_data.get('userId'),
            'deviceId': event_data.get('deviceId'),
            'visitorId': event_data.get('visitorId'),
            'resourceSegmentId': event_data.get('resourceSegmentId'),
            'eventData': event_data.get('eventData', {}),
            'location': self._extract_location_data(event_data),
            'response': {
                'automaticActions': [],
                'alertsSent': [],
                'escalationLevel': 'none',
                'acknowledged': False
            },
            'investigation': {
                'status': 'open',
                'assignedTo': None,
                'findings': None,
                'resolution': None
            },
            'relatedEvents': [],
            'heatmapData': self._generate_heatmap_coordinates(event_data)
        }
        
        # Add risk score if available
        if 'riskScore' in event_data:
            enriched['eventData']['riskScore'] = event_data['riskScore']
        
        # Add confidence score if available
        if 'confidence' in event_data:
            enriched['eventData']['confidence'] = event_data['confidence']
        
        return enriched
    
    def _determine_severity(self, event_data: Dict[str, Any]) -> str:
        """Determine event severity based on event type and context"""
        event_type = event_data.get('eventType', 'unknown')
        
        # Use predefined mapping
        severity = self.event_severity_mapping.get(event_type, 'low')
        
        # Adjust based on context
        if event_data.get('riskScore', 0) > 85:
            severity = 'critical'
        elif event_data.get('riskScore', 0) > 70:
            severity = 'high'
        
        # Break-glass events are always critical
        if event_type == 'break_glass':
            severity = 'critical'
        
        return severity
    
    def _extract_location_data(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract and enrich location data from event"""
        location = {
            'ipAddress': event_data.get('ipAddress', 'unknown'),
            'geolocation': event_data.get('geolocation'),
            'networkSegment': event_data.get('networkSegment', 'unknown')
        }
        
        # Add additional location context if available
        if 'userAgent' in event_data:
            location['userAgent'] = event_data['userAgent']
        
        return location
    
    def _generate_heatmap_coordinates(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate heatmap coordinates for visualization"""
        event_type = event_data.get('eventType', 'unknown')
        
        # Use predefined coordinates or generate random ones
        if event_type in self.event_coordinates:
            coord_config = self.event_coordinates[event_type]
            import random
            x = coord_config['base_x'] + random.randint(-coord_config['spread'], coord_config['spread'])
            y = coord_config['base_y'] + random.randint(-coord_config['spread'], coord_config['spread'])
        else:
            import random
            x = random.randint(50, 750)
            y = random.randint(50, 550)
        
        # Ensure coordinates are within bounds
        x = max(50, min(750, x))
        y = max(50, min(550, y))
        
        # Calculate intensity based on severity and risk score
        intensity = self._calculate_intensity(event_data)
        
        return {
            'coordinates': {'x': x, 'y': y},
            'intensity': intensity,
            'category': event_data.get('category', 'security')
        }
    
    def _calculate_intensity(self, event_data: Dict[str, Any]) -> int:
        """Calculate intensity for heatmap visualization"""
        base_intensity = {
            'low': 25,
            'medium': 50,
            'high': 75,
            'critical': 100
        }
        
        severity = event_data.get('severity', 'low')
        intensity = base_intensity.get(severity, 25)
        
        # Adjust based on risk score
        risk_score = event_data.get('riskScore', 0)
        if risk_score > 0:
            intensity = min(100, intensity + (risk_score * 0.3))
        
        return int(intensity)
    
    def _update_activity_metrics(self, event_data: Dict[str, Any]):
        """Update real-time activity metrics"""
        event_type = event_data.get('eventType')
        severity = event_data.get('severity')
        
        # Update counters
        self.activity_metrics['total_events'] += 1
        self.activity_metrics[f'events_{severity}'] += 1
        self.activity_metrics[f'type_{event_type}'] += 1
        
        # Update hourly metrics
        current_hour = datetime.utcnow().strftime('%Y-%m-%d-%H')
        self.activity_metrics[f'hourly_{current_hour}'] += 1
    
    def _should_generate_alert(self, event_data: Dict[str, Any]) -> bool:
        """Determine if an alert should be generated for the event"""
        severity = event_data.get('severity', 'low')
        event_type = event_data.get('eventType')
        
        # Always alert on critical events
        if severity == 'critical':
            return True
        
        # Alert on high severity events
        if severity == 'high':
            return True
        
        # Alert on specific event types
        alert_event_types = [
            'break_glass',
            'device_mismatch',
            'unauthorized_access',
            'coordinated_attack'
        ]
        
        if event_type in alert_event_types:
            return True
        
        # Alert on high risk scores
        risk_score = event_data.get('eventData', {}).get('riskScore', 0)
        if risk_score > 80:
            return True
        
        return False
    
    def _create_alert(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create alert data structure"""
        alert = {
            'alertId': str(uuid.uuid4()),
            'eventId': event_data['eventId'],
            'alertType': 'security_event',
            'severity': event_data['severity'],
            'title': self._generate_alert_title(event_data),
            'message': self._generate_alert_message(event_data),
            'timestamp': datetime.utcnow().isoformat(),
            'userId': event_data.get('userId'),
            'eventType': event_data.get('eventType'),
            'requiresAction': event_data['severity'] in ['critical', 'high'],
            'autoAcknowledge': False,
            'escalationLevel': self._determine_escalation_level(event_data)
        }
        
        # Add to alert history
        self.alert_history.append(alert)
        
        return alert
    
    def _generate_alert_title(self, event_data: Dict[str, Any]) -> str:
        """Generate human-readable alert title"""
        event_type = event_data.get('eventType', 'unknown')
        severity = event_data.get('severity', 'low')
        
        titles = {
            'device_mismatch': f"{severity.title()} Device Fingerprint Mismatch",
            'route_deviation': f"{severity.title()} Visitor Route Deviation",
            'jit_request': f"JIT Access Request - {severity.title()} Risk",
            'break_glass': f"Emergency Break-Glass Access Activated",
            'risk_elevation': f"{severity.title()} Risk Score Elevation",
            'anomaly_detected': f"{severity.title()} Behavioral Anomaly Detected",
            'failed_login': f"Multiple Failed Login Attempts",
            'unauthorized_access': f"Unauthorized Access Attempt",
            'policy_violation': f"Security Policy Violation"
        }
        
        return titles.get(event_type, f"{severity.title()} Security Event")
    
    def _generate_alert_message(self, event_data: Dict[str, Any]) -> str:
        """Generate detailed alert message"""
        event_type = event_data.get('eventType')
        user_id = event_data.get('userId', 'Unknown')
        timestamp = event_data.get('timestamp')
        
        base_message = f"Security event detected for user {user_id} at {timestamp}"
        
        # Add event-specific details
        event_data_details = event_data.get('eventData', {})
        if 'description' in event_data_details:
            base_message += f"\nDetails: {event_data_details['description']}"
        
        if 'riskScore' in event_data_details:
            base_message += f"\nRisk Score: {event_data_details['riskScore']}"
        
        return base_message
    
    def _determine_escalation_level(self, event_data: Dict[str, Any]) -> str:
        """Determine alert escalation level"""
        severity = event_data.get('severity', 'low')
        event_type = event_data.get('eventType')
        
        if severity == 'critical' or event_type == 'break_glass':
            return 'high'
        elif severity == 'high':
            return 'medium'
        elif severity == 'medium':
            return 'low'
        else:
            return 'none'
    
    def _broadcast_alert(self, alert: Dict[str, Any]):
        """Broadcast alert to administrators"""
        try:
            # Emit to admin room via WebSocket
            emit_admin_notification({
                'type': 'security_alert',
                'alert': alert,
                'timestamp': datetime.utcnow().isoformat()
            })
            
            # Log alert broadcast
            audit_logger.log_event(
                event_type='alert_broadcast',
                user_id='system',
                action='broadcast_security_alert',
                resource='admin_notification',
                result='success',
                details={
                    'alert_id': alert['alertId'],
                    'event_id': alert['eventId'],
                    'severity': alert['severity'],
                    'escalation_level': alert['escalationLevel']
                }
            )
            
        except Exception as e:
            logger.error(f"Error broadcasting alert: {str(e)}")
    
    def _update_heatmap_data(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update heatmap data with new event"""
        heatmap_data = {
            'id': event_data['eventId'],
            'type': 'security_event',
            'eventType': event_data['eventType'],
            'severity': event_data['severity'],
            'timestamp': event_data['timestamp'],
            'userId': event_data.get('userId'),
            'coordinates': event_data['heatmapData']['coordinates'],
            'intensity': event_data['heatmapData']['intensity'],
            'category': event_data['heatmapData']['category'],
            'description': event_data.get('eventData', {}).get('description'),
            'pulsing': True,  # Enable pulsing for new events
            'riskScore': event_data.get('eventData', {}).get('riskScore')
        }
        
        # Cache heatmap data
        self.heatmap_cache[event_data['eventId']] = heatmap_data
        
        return heatmap_data
    
    def _store_event(self, event_data: Dict[str, Any]):
        """Store event in Firestore for historical analysis"""
        try:
            # Store in securityEvents collection
            db.collection('securityEvents').document(event_data['eventId']).set(event_data)
            
            # Log audit event
            audit_logger.log_event(
                event_type='security_event_stored',
                user_id=event_data.get('userId', 'system'),
                action='store_security_event',
                resource='security_event',
                result='success',
                details={
                    'event_id': event_data['eventId'],
                    'event_type': event_data['eventType'],
                    'severity': event_data['severity']
                }
            )
            
        except Exception as e:
            logger.error(f"Error storing security event: {str(e)}")
    
    def _broadcast_to_administrators(self, event_data: Dict[str, Any], heatmap_data: Dict[str, Any]):
        """Broadcast event and heatmap updates to administrators"""
        try:
            if socketio:
                # Broadcast heatmap update
                socketio.emit('heatmap_update', heatmap_data, room='admin_room')
                
                # Broadcast security event
                socketio.emit('security_event', {
                    'eventId': event_data['eventId'],
                    'eventType': event_data['eventType'],
                    'severity': event_data['severity'],
                    'timestamp': event_data['timestamp'],
                    'userId': event_data.get('userId'),
                    'heatmapData': event_data['heatmapData'],
                    'eventData': event_data['eventData']
                }, room='admin_room')
                
                logger.info(f"Broadcasted event {event_data['eventId']} to administrators")
            
        except Exception as e:
            logger.error(f"Error broadcasting to administrators: {str(e)}")
    
    def _check_coordinated_attacks(self, event_data: Dict[str, Any]):
        """Check for coordinated attack patterns"""
        try:
            event_type = event_data.get('eventType')
            device_id = event_data.get('deviceId')
            user_id = event_data.get('userId')
            timestamp = datetime.fromisoformat(event_data['timestamp'].replace('Z', '+00:00'))
            
            # Track failed login attempts by device
            if event_type == 'failed_login' and device_id:
                self.coordinated_attack_tracker[device_id].append(timestamp)
                
                # Check for multiple failures within 10 minutes
                recent_failures = [
                    t for t in self.coordinated_attack_tracker[device_id]
                    if timestamp - t <= timedelta(minutes=10)
                ]
                
                if len(recent_failures) >= 5:
                    # Generate coordinated attack event
                    attack_event = {
                        'eventType': 'coordinated_attack',
                        'severity': 'critical',
                        'deviceId': device_id,
                        'userId': user_id,
                        'eventData': {
                            'description': f'Multiple failed login attempts detected from device {device_id}',
                            'failure_count': len(recent_failures),
                            'time_window': '10 minutes'
                        }
                    }
                    
                    # Process the attack event
                    self.process_security_event(attack_event)
                    
                    # Clear the tracker for this device
                    self.coordinated_attack_tracker[device_id].clear()
            
            # Clean up old entries (older than 1 hour)
            cutoff_time = timestamp - timedelta(hours=1)
            for device_id in list(self.coordinated_attack_tracker.keys()):
                self.coordinated_attack_tracker[device_id] = [
                    t for t in self.coordinated_attack_tracker[device_id]
                    if t > cutoff_time
                ]
                
                # Remove empty entries
                if not self.coordinated_attack_tracker[device_id]:
                    del self.coordinated_attack_tracker[device_id]
                    
        except Exception as e:
            logger.error(f"Error checking coordinated attacks: {str(e)}")
    
    def _process_events_loop(self):
        """Background thread for processing events"""
        while self.is_running:
            try:
                with self.processing_lock:
                    if self.event_queue:
                        event = self.event_queue.popleft()
                        # Additional processing can be done here
                        logger.debug(f"Processed event {event.get('eventId')}")
                
                # Sleep to prevent excessive CPU usage
                time.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error in event processing loop: {str(e)}")
                time.sleep(1)  # Wait longer on error
    
    def get_heatmap_data(self, time_range: str = '1h', user_role: str = None, severity: str = None) -> Dict[str, Any]:
        """
        Get current heatmap data with filtering
        
        Args:
            time_range: Time range for data ('15m', '1h', '4h', '24h', '7d')
            user_role: Filter by user role
            severity: Filter by severity level
            
        Returns:
            dict: Heatmap data and statistics
        """
        try:
            # Calculate time cutoff
            time_deltas = {
                '15m': timedelta(minutes=15),
                '1h': timedelta(hours=1),
                '4h': timedelta(hours=4),
                '24h': timedelta(hours=24),
                '7d': timedelta(days=7)
            }
            
            cutoff_time = datetime.utcnow() - time_deltas.get(time_range, timedelta(hours=1))
            
            # Query Firestore for events
            query = db.collection('securityEvents')\
                .where('timestamp', '>=', cutoff_time.isoformat())\
                .order_by('timestamp', direction='DESCENDING')\
                .limit(500)
            
            events = query.get()
            
            # Process and filter events
            heatmap_data = []
            stats = {
                'totalUsers': set(),
                'activeSessions': 0,
                'securityEvents': 0,
                'highRiskSessions': 0
            }
            
            for event_doc in events:
                event_data = event_doc.to_dict()
                
                # Apply filters
                if user_role and event_data.get('userRole') != user_role:
                    continue
                
                if severity and event_data.get('severity') != severity:
                    continue
                
                # Convert to heatmap format
                heatmap_item = {
                    'id': event_data.get('eventId'),
                    'type': 'security_event',
                    'eventType': event_data.get('eventType'),
                    'severity': event_data.get('severity'),
                    'timestamp': event_data.get('timestamp'),
                    'userId': event_data.get('userId'),
                    'coordinates': event_data.get('heatmapData', {}).get('coordinates', {'x': 0, 'y': 0}),
                    'intensity': event_data.get('heatmapData', {}).get('intensity', 50),
                    'category': event_data.get('heatmapData', {}).get('category', 'security'),
                    'description': event_data.get('eventData', {}).get('description'),
                    'riskScore': event_data.get('eventData', {}).get('riskScore'),
                    'pulsing': False  # Historical events don't pulse
                }
                
                heatmap_data.append(heatmap_item)
                
                # Update statistics
                if event_data.get('userId'):
                    stats['totalUsers'].add(event_data['userId'])
                
                stats['securityEvents'] += 1
                
                if event_data.get('eventData', {}).get('riskScore', 0) > 70:
                    stats['highRiskSessions'] += 1
            
            # Get active sessions count
            try:
                active_sessions_query = db.collection('continuousAuthSessions')\
                    .where('status', '==', 'active')
                active_sessions = active_sessions_query.get()
                stats['activeSessions'] = len(active_sessions)
            except Exception as e:
                logger.error(f"Error getting active sessions: {str(e)}")
                stats['activeSessions'] = 0
            
            # Convert set to count
            stats['totalUsers'] = len(stats['totalUsers'])
            
            return {
                'success': True,
                'data': heatmap_data,
                'stats': stats,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting heatmap data: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'data': [],
                'stats': {
                    'totalUsers': 0,
                    'activeSessions': 0,
                    'securityEvents': 0,
                    'highRiskSessions': 0
                }
            }
    
    def get_activity_metrics(self) -> Dict[str, Any]:
        """Get current activity metrics"""
        return dict(self.activity_metrics)
    
    def get_alert_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent alert history"""
        return list(self.alert_history)[-limit:]


# Global instance
realtime_event_processor = RealTimeEventProcessor()

# Auto-start processing when module is imported
realtime_event_processor.start_processing()