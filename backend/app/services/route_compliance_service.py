"""
Route Compliance Service

Advanced route compliance monitoring and violation detection for visitor management.
Provides real-time tracking, pattern analysis, and automated alert generation.
"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any, Tuple
import uuid
import asyncio

from app.firebase_config import get_firestore_client
from ..models.visitor import Visitor, AccessLogEntry
from ..services.enhanced_firebase_service import EnhancedFirebaseService
from ..utils.error_handler import ValidationError, NotFoundError

logger = logging.getLogger(__name__)


class RouteComplianceService:
    """
    Route Compliance Service
    
    Monitors visitor route compliance in real-time, detects violations,
    and generates alerts for security administrators and hosts.
    """
    
    def __init__(self):
        self.db = get_firestore_client()
        self.firebase_service = EnhancedFirebaseService()
        
        # Compliance thresholds
        self.violation_alert_threshold = 2  # Alert after 2 violations
        self.critical_violation_threshold = 5  # Critical alert after 5 violations
        self.compliance_score_warning = 70  # Warning below 70%
        self.compliance_score_critical = 50  # Critical below 50%
        
        # Time windows for violation analysis
        self.violation_time_window = timedelta(minutes=10)  # 10-minute window for pattern detection
        self.alert_cooldown = timedelta(minutes=2)  # 2-minute cooldown between alerts

    def _require_db(self):
        if not self.db:
            raise ValidationError("Firestore is not available in this environment")
    
    async def monitor_visitor_access(
        self,
        visitor_id: str,
        resource_segment: str,
        action: str,
        location_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Monitor visitor access attempt and check route compliance
        
        Args:
            visitor_id: Visitor ID
            resource_segment: Resource segment being accessed
            action: Action being performed
            location_data: Optional location/context data
            
        Returns:
            Dict containing compliance analysis and decision
        """
        try:
            self._require_db()
            # Get visitor data
            visitor_ref = self.db.collection('visitors').document(visitor_id)
            visitor_doc = visitor_ref.get()
            
            if not visitor_doc.exists:
                raise NotFoundError(f"Visitor {visitor_id} not found")
            
            visitor_data = visitor_doc.to_dict()
            visitor = Visitor(**visitor_data)
            
            # Check if session is active
            if not visitor.is_session_active():
                return {
                    'approved': False,
                    'reason': 'session_expired',
                    'compliance_score': visitor.route_compliance.compliance_score,
                    'alert_generated': False
                }
            
            # Analyze route compliance
            compliance_result = await self._analyze_route_compliance(
                visitor, resource_segment, action, location_data
            )
            
            # Update visitor access log
            visitor.add_access_log_entry(
                resource_segment,
                action,
                compliance_result['approved'],
                compliance_result.get('risk_score')
            )
            
            # Check for violation patterns
            if not compliance_result['approved']:
                pattern_analysis = await self._analyze_violation_patterns(visitor)
                compliance_result.update(pattern_analysis)
                
                # Generate alerts if necessary
                alert_result = await self._handle_route_violation(
                    visitor, resource_segment, action, compliance_result
                )
                compliance_result['alert_generated'] = alert_result['alert_generated']
                compliance_result['alert_severity'] = alert_result.get('severity')
            
            # Update visitor in database
            visitor_ref.update(visitor.dict())
            
            # Log compliance event
            await self._log_compliance_event(visitor_id, compliance_result)
            
            return compliance_result
            
        except Exception as e:
            logger.error(f"Error monitoring visitor access: {str(e)}")
            return {
                'approved': False,
                'reason': 'system_error',
                'compliance_score': 0,
                'alert_generated': False,
                'error': str(e)
            }
    
    async def get_real_time_compliance_status(self, visitor_id: str) -> Dict[str, Any]:
        """
        Get real-time compliance status for a visitor
        
        Args:
            visitor_id: Visitor ID
            
        Returns:
            Dict containing current compliance status and metrics
        """
        try:
            visitor_ref = self.db.collection('visitors').document(visitor_id)
            visitor_doc = visitor_ref.get()
            
            if not visitor_doc.exists:
                raise NotFoundError(f"Visitor {visitor_id} not found")
            
            visitor_data = visitor_doc.to_dict()
            visitor = Visitor(**visitor_data)
            
            # Calculate current metrics
            recent_accesses = [
                entry for entry in visitor.access_log
                if (datetime.utcnow() - entry.timestamp).total_seconds() < 3600  # Last hour
            ]
            
            recent_violations = [
                entry for entry in recent_accesses
                if not entry.approved
            ]
            
            # Analyze access patterns
            access_pattern = await self._analyze_access_patterns(visitor)
            
            # Calculate risk indicators
            risk_indicators = await self._calculate_risk_indicators(visitor)
            
            status = {
                'visitor_id': visitor_id,
                'visitor_name': visitor.name,
                'session_status': 'active' if visitor.is_session_active() else visitor.status,
                'compliance_score': visitor.route_compliance.compliance_score,
                'total_accesses': len(visitor.access_log),
                'total_violations': len(visitor.route_compliance.deviations),
                'recent_accesses': len(recent_accesses),
                'recent_violations': len(recent_violations),
                'time_remaining': str(visitor.get_remaining_time()) if visitor.is_session_active() else None,
                'access_pattern': access_pattern,
                'risk_indicators': risk_indicators,
                'last_access': visitor.access_log[-1].dict() if visitor.access_log else None,
                'assigned_route': visitor.assigned_route.dict(),
                'alerts': visitor.alerts,
                'updated_at': datetime.utcnow().isoformat()
            }
            
            return status
            
        except Exception as e:
            logger.error(f"Error getting compliance status: {str(e)}")
            raise ValidationError(f"Failed to get compliance status: {str(e)}")
    
    async def generate_compliance_alerts(self) -> List[Dict[str, Any]]:
        """
        Generate compliance alerts for all active visitors
        
        Returns:
            List of generated alerts
        """
        try:
            alerts = []
            
            # Query all active visitors
            query = self.db.collection('visitors').where('status', '==', 'active')
            docs = query.stream()
            
            for doc in docs:
                visitor_data = doc.to_dict()
                visitor = Visitor(**visitor_data)
                
                # Check for alert conditions
                visitor_alerts = await self._check_alert_conditions(visitor)
                alerts.extend(visitor_alerts)
            
            # Store alerts in database
            for alert in alerts:
                self.db.collection('compliance_alerts').add(alert)
            
            return alerts
            
        except Exception as e:
            logger.error(f"Error generating compliance alerts: {str(e)}")
            return []
    
    async def get_compliance_dashboard_data(self, host_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get compliance dashboard data for administrators or specific host
        
        Args:
            host_id: Optional host ID to filter visitors
            
        Returns:
            Dict containing dashboard metrics and data
        """
        try:
            # Base query for active visitors
            query = self.db.collection('visitors').where('status', '==', 'active')
            
            # Filter by host if specified
            if host_id:
                query = query.where('host_id', '==', host_id)
            
            visitors = []
            docs = query.stream()
            
            for doc in docs:
                visitor_data = doc.to_dict()
                visitor = Visitor(**visitor_data)
                visitors.append(visitor)
            
            # Calculate aggregate metrics
            total_visitors = len(visitors)
            compliant_visitors = sum(1 for v in visitors if v.route_compliance.compliance_score >= 90)
            warning_visitors = sum(1 for v in visitors if 70 <= v.route_compliance.compliance_score < 90)
            critical_visitors = sum(1 for v in visitors if v.route_compliance.compliance_score < 70)
            
            total_violations = sum(len(v.route_compliance.deviations) for v in visitors)
            avg_compliance = sum(v.route_compliance.compliance_score for v in visitors) / total_visitors if total_visitors > 0 else 100
            
            # Recent activity (last hour)
            recent_accesses = []
            recent_violations = []
            
            for visitor in visitors:
                for entry in visitor.access_log:
                    if (datetime.utcnow() - entry.timestamp).total_seconds() < 3600:
                        recent_accesses.append({
                            'visitor_id': visitor.visitor_id,
                            'visitor_name': visitor.name,
                            'resource_segment': entry.resource_segment,
                            'action': entry.action,
                            'approved': entry.approved,
                            'timestamp': entry.timestamp.isoformat()
                        })
                        
                        if not entry.approved:
                            recent_violations.append({
                                'visitor_id': visitor.visitor_id,
                                'visitor_name': visitor.name,
                                'resource_segment': entry.resource_segment,
                                'action': entry.action,
                                'timestamp': entry.timestamp.isoformat()
                            })
            
            # Sort by timestamp (most recent first)
            recent_accesses.sort(key=lambda x: x['timestamp'], reverse=True)
            recent_violations.sort(key=lambda x: x['timestamp'], reverse=True)
            
            dashboard_data = {
                'summary': {
                    'total_visitors': total_visitors,
                    'compliant_visitors': compliant_visitors,
                    'warning_visitors': warning_visitors,
                    'critical_visitors': critical_visitors,
                    'total_violations': total_violations,
                    'average_compliance_score': round(avg_compliance, 2)
                },
                'recent_activity': {
                    'accesses': recent_accesses[:20],  # Last 20 accesses
                    'violations': recent_violations[:10]  # Last 10 violations
                },
                'visitor_details': [
                    {
                        'visitor_id': v.visitor_id,
                        'name': v.name,
                        'host_name': v.host_name,
                        'compliance_score': v.route_compliance.compliance_score,
                        'violations_count': len(v.route_compliance.deviations),
                        'time_remaining': str(v.get_remaining_time()) if v.is_session_active() else None,
                        'last_access': v.access_log[-1].timestamp.isoformat() if v.access_log else None
                    }
                    for v in visitors
                ],
                'generated_at': datetime.utcnow().isoformat()
            }
            
            return dashboard_data
            
        except Exception as e:
            logger.error(f"Error generating dashboard data: {str(e)}")
            raise ValidationError(f"Failed to generate dashboard data: {str(e)}")
    
    # Private helper methods
    
    async def _analyze_route_compliance(
        self,
        visitor: Visitor,
        resource_segment: str,
        action: str,
        location_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Analyze route compliance for access attempt"""
        
        # Check if resource is in allowed segments
        approved = resource_segment in visitor.assigned_route.allowed_segments
        
        # Check if resource is explicitly restricted
        if resource_segment in visitor.assigned_route.restricted_areas:
            approved = False
            severity = 'high'
        else:
            severity = 'medium' if not approved else 'low'
        
        # Calculate risk score based on various factors
        risk_score = await self._calculate_access_risk_score(visitor, resource_segment, action)
        
        return {
            'approved': approved,
            'reason': 'route_compliant' if approved else 'route_violation',
            'severity': severity,
            'risk_score': risk_score,
            'resource_segment': resource_segment,
            'action': action,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    async def _analyze_violation_patterns(self, visitor: Visitor) -> Dict[str, Any]:
        """Analyze patterns in route violations"""
        
        recent_violations = [
            deviation for deviation in visitor.route_compliance.deviations
            if (datetime.utcnow() - datetime.fromisoformat(deviation['timestamp'])).total_seconds() < self.violation_time_window.total_seconds()
        ]
        
        # Pattern analysis
        patterns = {
            'rapid_violations': len(recent_violations) >= 3,  # 3+ violations in 10 minutes
            'repeated_resource': len(set(v.get('resource_segment') for v in recent_violations)) == 1 and len(recent_violations) > 1,
            'escalating_severity': any(v.get('severity') == 'high' for v in recent_violations),
            'violation_count': len(recent_violations),
            'total_violations': len(visitor.route_compliance.deviations)
        }
        
        return {'patterns': patterns}
    
    async def _handle_route_violation(
        self,
        visitor: Visitor,
        resource_segment: str,
        action: str,
        compliance_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Handle route violation and generate alerts"""
        
        try:
            # Check if we should generate an alert
            total_violations = len(visitor.route_compliance.deviations)
            severity = compliance_result.get('severity', 'medium')
            
            should_alert = (
                total_violations >= self.violation_alert_threshold or
                severity == 'high' or
                compliance_result.get('patterns', {}).get('rapid_violations', False)
            )
            
            if not should_alert:
                return {'alert_generated': False}
            
            # Check alert cooldown
            last_alert_time = getattr(visitor, 'last_alert_time', None)
            if last_alert_time:
                time_since_last = datetime.utcnow() - datetime.fromisoformat(last_alert_time)
                if time_since_last < self.alert_cooldown:
                    return {'alert_generated': False, 'reason': 'cooldown_active'}
            
            # Generate alert
            alert_id = str(uuid.uuid4())
            alert_severity = 'critical' if total_violations >= self.critical_violation_threshold else severity
            
            alert_data = {
                'alert_id': alert_id,
                'type': 'route_violation',
                'severity': alert_severity,
                'visitor_id': visitor.visitor_id,
                'visitor_name': visitor.name,
                'host_id': visitor.host_id,
                'host_name': visitor.host_name,
                'resource_segment': resource_segment,
                'action': action,
                'violation_count': total_violations,
                'compliance_score': visitor.route_compliance.compliance_score,
                'patterns': compliance_result.get('patterns', {}),
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'active'
            }
            
            # Store alert
            self.db.collection('compliance_alerts').document(alert_id).set(alert_data)
            
            # Add alert to visitor
            visitor.alerts.append(alert_id)
            
            # Send notifications
            await self._send_violation_notifications(alert_data)
            
            # Update last alert time
            visitor_ref = self.db.collection('visitors').document(visitor.visitor_id)
            visitor_ref.update({'last_alert_time': datetime.utcnow().isoformat()})
            
            logger.warning(f"Route violation alert generated: {alert_id} for visitor {visitor.visitor_id}")
            
            return {
                'alert_generated': True,
                'alert_id': alert_id,
                'severity': alert_severity
            }
            
        except Exception as e:
            logger.error(f"Error handling route violation: {str(e)}")
            return {'alert_generated': False, 'error': str(e)}
    
    async def _calculate_access_risk_score(
        self,
        visitor: Visitor,
        resource_segment: str,
        action: str
    ) -> float:
        """Calculate risk score for access attempt"""
        
        base_risk = 50.0
        
        # Compliance history factor
        compliance_score = visitor.route_compliance.compliance_score
        compliance_factor = (100 - compliance_score) / 100 * 30  # 0-30 points
        
        # Violation frequency factor
        recent_violations = len([
            d for d in visitor.route_compliance.deviations
            if (datetime.utcnow() - datetime.fromisoformat(d['timestamp'])).total_seconds() < 3600
        ])
        frequency_factor = min(recent_violations * 10, 30)  # 0-30 points
        
        # Resource sensitivity factor
        resource_risk = {
            'academic-resources': 5,
            'library-services': 5,
            'student-commons': 5,
            'conference-rooms': 15,
            'research-labs-basic': 20,
            'administrative-offices': 30,
            'research-labs-advanced': 40,
            'it-infrastructure': 50
        }
        resource_factor = resource_risk.get(resource_segment, 20)
        
        # Time-based factor (higher risk outside normal hours)
        current_hour = datetime.utcnow().hour
        if current_hour < 6 or current_hour > 22:
            time_factor = 20
        elif current_hour < 8 or current_hour > 18:
            time_factor = 10
        else:
            time_factor = 0
        
        total_risk = base_risk + compliance_factor + frequency_factor + resource_factor + time_factor
        return min(max(total_risk, 0), 100)  # Clamp to 0-100
    
    async def _analyze_access_patterns(self, visitor: Visitor) -> Dict[str, Any]:
        """Analyze visitor access patterns"""
        
        if not visitor.access_log:
            return {'pattern_type': 'no_activity'}
        
        # Time-based analysis
        access_times = [entry.timestamp.hour for entry in visitor.access_log]
        peak_hour = max(set(access_times), key=access_times.count) if access_times else None
        
        # Resource diversity
        unique_resources = set(entry.resource_segment for entry in visitor.access_log)
        resource_diversity = len(unique_resources)
        
        # Access frequency
        session_duration = (datetime.utcnow() - visitor.entry_time).total_seconds() / 3600
        access_frequency = len(visitor.access_log) / max(session_duration, 0.1)  # Accesses per hour
        
        return {
            'pattern_type': 'normal',
            'peak_access_hour': peak_hour,
            'resource_diversity': resource_diversity,
            'access_frequency': round(access_frequency, 2),
            'total_accesses': len(visitor.access_log),
            'session_duration_hours': round(session_duration, 2)
        }
    
    async def _calculate_risk_indicators(self, visitor: Visitor) -> Dict[str, Any]:
        """Calculate risk indicators for visitor"""
        
        indicators = {
            'high_violation_rate': visitor.route_compliance.compliance_score < 70,
            'rapid_access_pattern': len(visitor.access_log) > 20 and (datetime.utcnow() - visitor.entry_time).total_seconds() < 3600,
            'restricted_area_attempts': any(
                d.get('severity') == 'high' for d in visitor.route_compliance.deviations
            ),
            'session_near_expiry': visitor.get_remaining_time().total_seconds() < 1800,  # 30 minutes
            'multiple_extensions': len(visitor.session_extensions) > 1
        }
        
        risk_level = 'high' if sum(indicators.values()) >= 3 else 'medium' if sum(indicators.values()) >= 1 else 'low'
        
        return {
            'risk_level': risk_level,
            'indicators': indicators,
            'risk_count': sum(indicators.values())
        }
    
    async def _check_alert_conditions(self, visitor: Visitor) -> List[Dict[str, Any]]:
        """Check for alert conditions for a visitor"""
        
        alerts = []
        
        # Low compliance score alert
        if visitor.route_compliance.compliance_score < self.compliance_score_critical:
            alerts.append({
                'type': 'critical_compliance',
                'visitor_id': visitor.visitor_id,
                'visitor_name': visitor.name,
                'host_id': visitor.host_id,
                'compliance_score': visitor.route_compliance.compliance_score,
                'severity': 'critical',
                'timestamp': datetime.utcnow().isoformat()
            })
        elif visitor.route_compliance.compliance_score < self.compliance_score_warning:
            alerts.append({
                'type': 'low_compliance',
                'visitor_id': visitor.visitor_id,
                'visitor_name': visitor.name,
                'host_id': visitor.host_id,
                'compliance_score': visitor.route_compliance.compliance_score,
                'severity': 'warning',
                'timestamp': datetime.utcnow().isoformat()
            })
        
        # Session expiring soon alert
        remaining_time = visitor.get_remaining_time()
        if remaining_time.total_seconds() < 1800 and remaining_time.total_seconds() > 0:  # 30 minutes
            alerts.append({
                'type': 'session_expiring',
                'visitor_id': visitor.visitor_id,
                'visitor_name': visitor.name,
                'host_id': visitor.host_id,
                'time_remaining': str(remaining_time),
                'severity': 'warning',
                'timestamp': datetime.utcnow().isoformat()
            })
        
        return alerts
    
    async def _send_violation_notifications(self, alert_data: Dict[str, Any]):
        """Send notifications for route violations"""
        
        try:
            # Notification for host
            host_notification = {
                'type': 'route_violation',
                'title': f'{alert_data["severity"].title()} Route Violation',
                'message': f'Visitor {alert_data["visitor_name"]} violated route: unauthorized access to {alert_data["resource_segment"]}',
                'alert_id': alert_data['alert_id'],
                'visitor_id': alert_data['visitor_id'],
                'severity': alert_data['severity'],
                'timestamp': alert_data['timestamp']
            }
            
            await self.firebase_service.send_notification(alert_data['host_id'], host_notification)
            
            # Notification for administrators (critical violations only)
            if alert_data['severity'] == 'critical':
                admin_notification = {
                    'type': 'critical_route_violation',
                    'title': 'Critical Route Violation',
                    'message': f'Visitor {alert_data["visitor_name"]} (Host: {alert_data["host_name"]}) has {alert_data["violation_count"]} route violations',
                    'alert_id': alert_data['alert_id'],
                    'visitor_id': alert_data['visitor_id'],
                    'host_id': alert_data['host_id'],
                    'severity': 'critical',
                    'timestamp': alert_data['timestamp']
                }
                
                await self.firebase_service.broadcast_to_admins(admin_notification)
            
        except Exception as e:
            logger.error(f"Error sending violation notifications: {str(e)}")
    
    async def _log_compliance_event(self, visitor_id: str, compliance_result: Dict[str, Any]):
        """Log compliance event for audit purposes"""
        
        try:
            log_entry = {
                'event_id': str(uuid.uuid4()),
                'event_type': 'route_compliance_check',
                'visitor_id': visitor_id,
                'result': compliance_result,
                'timestamp': datetime.utcnow().isoformat(),
                'source': 'route_compliance_service'
            }
            
            self.db.collection('compliance_logs').add(log_entry)
            
        except Exception as e:
            logger.error(f"Error logging compliance event: {str(e)}")


# Global route compliance service instance
route_compliance_service = RouteComplianceService()