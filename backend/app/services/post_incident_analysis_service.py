"""
Post-Incident Analysis and Reporting Service
Generates detailed reports with timeline analysis, impact assessment, and recommendations
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
import json
import statistics
from collections import defaultdict

from app.firebase_config import db
from app.services.enhanced_audit_service import enhanced_audit_service
from app.models.threat_prediction import ThreatPrediction

logger = logging.getLogger(__name__)


class IncidentSeverity(Enum):
    """Incident severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentCategory(Enum):
    """Incident categories"""
    SECURITY_BREACH = "security_breach"
    SYSTEM_OUTAGE = "system_outage"
    DATA_LOSS = "data_loss"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    POLICY_VIOLATION = "policy_violation"
    OPERATIONAL_ERROR = "operational_error"


class PostIncidentAnalysisService:
    """Service for post-incident analysis and reporting"""
    
    def __init__(self):
        self.analysis_window_hours = 24  # Default analysis window
        self.pattern_detection_threshold = 3  # Minimum occurrences for pattern
        
    async def generate_incident_report(self, incident_id: str, 
                                     incident_type: str = None) -> Dict[str, Any]:
        """
        Generate comprehensive incident report with timeline analysis and impact assessment
        
        Args:
            incident_id: Incident identifier (session_id, request_id, etc.)
            incident_type: Type of incident for context
            
        Returns:
            dict: Comprehensive incident report
        """
        try:
            logger.info(f"Generating incident report for {incident_id}")
            
            # Gather incident data
            incident_data = await self._gather_incident_data(incident_id, incident_type)
            
            if not incident_data:
                return {
                    'success': False,
                    'error': f'No incident data found for {incident_id}'
                }
            
            # Perform timeline analysis
            timeline_analysis = await self._analyze_incident_timeline(incident_data)
            
            # Assess impact
            impact_assessment = await self._assess_incident_impact(incident_data)
            
            # Identify patterns
            pattern_analysis = await self._identify_incident_patterns(incident_data)
            
            # Generate recommendations
            recommendations = await self._generate_incident_recommendations(
                incident_data, timeline_analysis, impact_assessment, pattern_analysis
            )
            
            # Compile comprehensive report
            report = {
                'incident_id': incident_id,
                'incident_type': incident_type,
                'generated_at': datetime.utcnow().isoformat(),
                'report_version': '1.0',
                'incident_summary': self._create_incident_summary(incident_data),
                'timeline_analysis': timeline_analysis,
                'impact_assessment': impact_assessment,
                'pattern_analysis': pattern_analysis,
                'recommendations': recommendations,
                'lessons_learned': self._extract_lessons_learned(incident_data, recommendations),
                'compliance_analysis': await self._analyze_compliance_impact(incident_data),
                'follow_up_actions': self._generate_follow_up_actions(recommendations),
                'report_metadata': {
                    'analysis_window_hours': self.analysis_window_hours,
                    'data_sources': incident_data.get('data_sources', []),
                    'analysis_completeness': self._calculate_analysis_completeness(incident_data)
                }
            }
            
            # Store report
            await self._store_incident_report(incident_id, report)
            
            logger.info(f"Incident report generated successfully for {incident_id}")
            return {
                'success': True,
                'report': report
            }
            
        except Exception as e:
            logger.error(f"Error generating incident report: {e}")
            return {
                'success': False,
                'error': f'Failed to generate incident report: {str(e)}'
            }
    
    async def _gather_incident_data(self, incident_id: str, 
                                  incident_type: str = None) -> Dict[str, Any]:
        """Gather all relevant data for the incident"""
        try:
            incident_data = {
                'incident_id': incident_id,
                'incident_type': incident_type,
                'data_sources': [],
                'events': [],
                'audit_logs': [],
                'security_events': [],
                'user_activities': [],
                'system_metrics': [],
                'related_incidents': []
            }
            
            # Gather audit logs
            audit_logs = await self._get_incident_audit_logs(incident_id)
            if audit_logs:
                incident_data['audit_logs'] = audit_logs
                incident_data['data_sources'].append('audit_logs')
            
            # Gather security events
            security_events = await self._get_incident_security_events(incident_id)
            if security_events:
                incident_data['security_events'] = security_events
                incident_data['data_sources'].append('security_events')
            
            # Gather break-glass session data if applicable
            if incident_type == 'break_glass':
                session_data = await self._get_break_glass_session_data(incident_id)
                if session_data:
                    incident_data['session_data'] = session_data
                    incident_data['data_sources'].append('break_glass_session')
            
            # Gather threat predictions
            threat_predictions = await self._get_related_threat_predictions(incident_id)
            if threat_predictions:
                incident_data['threat_predictions'] = threat_predictions
                incident_data['data_sources'].append('threat_predictions')
            
            # Gather user activity data
            user_activities = await self._get_incident_user_activities(incident_id)
            if user_activities:
                incident_data['user_activities'] = user_activities
                incident_data['data_sources'].append('user_activities')
            
            # Find related incidents
            related_incidents = await self._find_related_incidents(incident_id)
            if related_incidents:
                incident_data['related_incidents'] = related_incidents
                incident_data['data_sources'].append('related_incidents')
            
            return incident_data
            
        except Exception as e:
            logger.error(f"Error gathering incident data: {e}")
            return None
    
    async def _get_incident_audit_logs(self, incident_id: str) -> List[Dict[str, Any]]:
        """Get audit logs related to the incident"""
        try:
            # Query audit logs by session_id or related fields
            audit_query = db.collection('audit_logs')\
                           .where('session_id', '==', incident_id)\
                           .order_by('timestamp')
            
            audit_logs = []
            for doc in audit_query.stream():
                audit_logs.append(doc.to_dict())
            
            # Also search by resource_id or other identifiers
            if not audit_logs:
                resource_query = db.collection('audit_logs')\
                               .where('resource_id', '==', incident_id)\
                               .order_by('timestamp')
                
                for doc in resource_query.stream():
                    audit_logs.append(doc.to_dict())
            
            return audit_logs
            
        except Exception as e:
            logger.error(f"Error getting incident audit logs: {e}")
            return []
    
    async def _get_incident_security_events(self, incident_id: str) -> List[Dict[str, Any]]:
        """Get security events related to the incident"""
        try:
            # Query security events
            events_query = db.collection('security_events')\
                            .where('incident_id', '==', incident_id)\
                            .order_by('timestamp')
            
            security_events = []
            for doc in events_query.stream():
                security_events.append(doc.to_dict())
            
            return security_events
            
        except Exception as e:
            logger.error(f"Error getting incident security events: {e}")
            return []
    
    async def _get_break_glass_session_data(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get break-glass session data"""
        try:
            session_ref = db.collection('emergency_sessions').document(session_id)
            session_doc = session_ref.get()
            
            if session_doc.exists:
                return session_doc.to_dict()
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting break-glass session data: {e}")
            return None
    
    async def _get_related_threat_predictions(self, incident_id: str) -> List[Dict[str, Any]]:
        """Get threat predictions related to the incident"""
        try:
            # Query threat predictions that might be related
            predictions_query = db.collection('threat_predictions')\
                               .where('status', '==', 'confirmed')\
                               .order_by('predicted_at', direction='DESCENDING')\
                               .limit(10)
            
            predictions = []
            for doc in predictions_query.stream():
                prediction_data = doc.to_dict()
                # Check if prediction is related to this incident
                if self._is_prediction_related(prediction_data, incident_id):
                    predictions.append(prediction_data)
            
            return predictions
            
        except Exception as e:
            logger.error(f"Error getting related threat predictions: {e}")
            return []
    
    def _is_prediction_related(self, prediction: Dict[str, Any], incident_id: str) -> bool:
        """Check if a threat prediction is related to the incident"""
        # Simple heuristic - in a real implementation, this would be more sophisticated
        prediction_id = prediction.get('prediction_id', '')
        user_id = prediction.get('user_id', '')
        
        return (incident_id in prediction_id or 
                incident_id in str(prediction.get('indicators', [])) or
                any(incident_id in str(measure) for measure in prediction.get('preventive_measures', [])))
    
    async def _get_incident_user_activities(self, incident_id: str) -> List[Dict[str, Any]]:
        """Get user activities related to the incident"""
        try:
            # This would query user activity logs, access logs, etc.
            # For now, return empty list as this would depend on specific logging implementation
            return []
            
        except Exception as e:
            logger.error(f"Error getting incident user activities: {e}")
            return []
    
    async def _find_related_incidents(self, incident_id: str) -> List[Dict[str, Any]]:
        """Find incidents related to this one"""
        try:
            # Query for incidents with similar patterns, users, or timeframes
            # This is a simplified implementation
            related_incidents = []
            
            # Query recent incidents
            cutoff_time = datetime.utcnow() - timedelta(days=7)
            incidents_query = db.collection('incident_reports')\
                               .where('generated_at', '>=', cutoff_time)\
                               .order_by('generated_at', direction='DESCENDING')\
                               .limit(20)
            
            for doc in incidents_query.stream():
                incident_data = doc.to_dict()
                if incident_data.get('incident_id') != incident_id:
                    # Simple similarity check
                    if self._calculate_incident_similarity(incident_id, incident_data) > 0.5:
                        related_incidents.append(incident_data)
            
            return related_incidents
            
        except Exception as e:
            logger.error(f"Error finding related incidents: {e}")
            return []
    
    def _calculate_incident_similarity(self, incident_id: str, other_incident: Dict[str, Any]) -> float:
        """Calculate similarity between incidents (simplified)"""
        # This is a placeholder - real implementation would use more sophisticated similarity metrics
        return 0.3  # Default low similarity
    
    async def _analyze_incident_timeline(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze incident timeline with key events and phases"""
        try:
            all_events = []
            
            # Collect all timestamped events
            for audit_log in incident_data.get('audit_logs', []):
                all_events.append({
                    'timestamp': audit_log.get('timestamp'),
                    'type': 'audit_log',
                    'event': audit_log.get('action', 'Unknown action'),
                    'severity': audit_log.get('severity', 'info'),
                    'user_id': audit_log.get('user_id'),
                    'details': audit_log
                })
            
            for security_event in incident_data.get('security_events', []):
                all_events.append({
                    'timestamp': security_event.get('timestamp'),
                    'type': 'security_event',
                    'event': security_event.get('event_type', 'Unknown security event'),
                    'severity': security_event.get('severity', 'medium'),
                    'details': security_event
                })
            
            # Sort events by timestamp
            all_events.sort(key=lambda x: x.get('timestamp', datetime.min))
            
            # Identify key phases
            phases = self._identify_incident_phases(all_events)
            
            # Calculate timeline metrics
            timeline_metrics = self._calculate_timeline_metrics(all_events, phases)
            
            return {
                'total_events': len(all_events),
                'timeline_events': all_events,
                'incident_phases': phases,
                'timeline_metrics': timeline_metrics,
                'critical_events': [e for e in all_events if e.get('severity') in ['high', 'critical']],
                'event_frequency': self._calculate_event_frequency(all_events)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing incident timeline: {e}")
            return {'error': str(e)}
    
    def _identify_incident_phases(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify distinct phases in the incident timeline"""
        if not events:
            return []
        
        phases = []
        current_phase = None
        phase_start = None
        
        for event in events:
            event_type = event.get('type')
            severity = event.get('severity', 'info')
            
            # Determine phase based on event characteristics
            if severity in ['high', 'critical'] and current_phase != 'critical':
                if current_phase:
                    phases.append({
                        'phase': current_phase,
                        'start_time': phase_start,
                        'end_time': event.get('timestamp'),
                        'duration_seconds': self._calculate_duration(phase_start, event.get('timestamp'))
                    })
                
                current_phase = 'critical'
                phase_start = event.get('timestamp')
            
            elif event_type == 'security_event' and current_phase != 'response':
                if current_phase:
                    phases.append({
                        'phase': current_phase,
                        'start_time': phase_start,
                        'end_time': event.get('timestamp'),
                        'duration_seconds': self._calculate_duration(phase_start, event.get('timestamp'))
                    })
                
                current_phase = 'response'
                phase_start = event.get('timestamp')
            
            elif not current_phase:
                current_phase = 'initial'
                phase_start = event.get('timestamp')
        
        # Close final phase
        if current_phase and events:
            phases.append({
                'phase': current_phase,
                'start_time': phase_start,
                'end_time': events[-1].get('timestamp'),
                'duration_seconds': self._calculate_duration(phase_start, events[-1].get('timestamp'))
            })
        
        return phases
    
    def _calculate_duration(self, start_time: datetime, end_time: datetime) -> int:
        """Calculate duration between two timestamps in seconds"""
        try:
            if isinstance(start_time, str):
                start_time = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            if isinstance(end_time, str):
                end_time = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
            
            return int((end_time - start_time).total_seconds())
        except:
            return 0
    
    def _calculate_timeline_metrics(self, events: List[Dict[str, Any]], 
                                  phases: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate timeline metrics"""
        if not events:
            return {}
        
        # Calculate total incident duration
        start_time = events[0].get('timestamp')
        end_time = events[-1].get('timestamp')
        total_duration = self._calculate_duration(start_time, end_time)
        
        # Calculate phase durations
        phase_durations = {phase['phase']: phase['duration_seconds'] for phase in phases}
        
        # Calculate event density
        event_density = len(events) / max(total_duration / 3600, 1)  # events per hour
        
        return {
            'total_duration_seconds': total_duration,
            'total_duration_formatted': f"{total_duration // 3600}h {(total_duration % 3600) // 60}m",
            'phase_durations': phase_durations,
            'event_density_per_hour': round(event_density, 2),
            'peak_activity_period': self._find_peak_activity_period(events)
        }
    
    def _find_peak_activity_period(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Find the period with highest activity"""
        if not events:
            return {}
        
        # Group events by hour
        hourly_counts = defaultdict(int)
        
        for event in events:
            timestamp = event.get('timestamp')
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            
            hour_key = timestamp.replace(minute=0, second=0, microsecond=0)
            hourly_counts[hour_key] += 1
        
        if not hourly_counts:
            return {}
        
        peak_hour = max(hourly_counts.items(), key=lambda x: x[1])
        
        return {
            'peak_hour': peak_hour[0].isoformat(),
            'event_count': peak_hour[1],
            'percentage_of_total': round((peak_hour[1] / len(events)) * 100, 2)
        }
    
    def _calculate_event_frequency(self, events: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate frequency of different event types"""
        frequency = defaultdict(int)
        
        for event in events:
            event_type = event.get('type', 'unknown')
            frequency[event_type] += 1
        
        return dict(frequency)
    
    async def _assess_incident_impact(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess the impact of the incident"""
        try:
            impact_assessment = {
                'severity': self._determine_incident_severity(incident_data),
                'affected_systems': self._identify_affected_systems(incident_data),
                'affected_users': self._identify_affected_users(incident_data),
                'data_impact': self._assess_data_impact(incident_data),
                'business_impact': self._assess_business_impact(incident_data),
                'security_impact': self._assess_security_impact(incident_data),
                'compliance_impact': self._assess_compliance_impact(incident_data),
                'financial_impact': self._estimate_financial_impact(incident_data)
            }
            
            return impact_assessment
            
        except Exception as e:
            logger.error(f"Error assessing incident impact: {e}")
            return {'error': str(e)}
    
    def _determine_incident_severity(self, incident_data: Dict[str, Any]) -> str:
        """Determine overall incident severity"""
        severity_scores = []
        
        # Check audit log severities
        for audit_log in incident_data.get('audit_logs', []):
            severity = audit_log.get('severity', 'info')
            if severity == 'critical':
                severity_scores.append(4)
            elif severity == 'high':
                severity_scores.append(3)
            elif severity == 'medium':
                severity_scores.append(2)
            else:
                severity_scores.append(1)
        
        # Check security event severities
        for security_event in incident_data.get('security_events', []):
            severity = security_event.get('severity', 'medium')
            if severity == 'critical':
                severity_scores.append(4)
            elif severity == 'high':
                severity_scores.append(3)
            elif severity == 'medium':
                severity_scores.append(2)
            else:
                severity_scores.append(1)
        
        if not severity_scores:
            return 'low'
        
        avg_severity = statistics.mean(severity_scores)
        
        if avg_severity >= 3.5:
            return 'critical'
        elif avg_severity >= 2.5:
            return 'high'
        elif avg_severity >= 1.5:
            return 'medium'
        else:
            return 'low'
    
    def _identify_affected_systems(self, incident_data: Dict[str, Any]) -> List[str]:
        """Identify systems affected by the incident"""
        affected_systems = set()
        
        for audit_log in incident_data.get('audit_logs', []):
            resource_type = audit_log.get('resource_type')
            if resource_type:
                affected_systems.add(resource_type)
        
        for security_event in incident_data.get('security_events', []):
            affected_resources = security_event.get('affected_resources', [])
            affected_systems.update(affected_resources)
        
        return list(affected_systems)
    
    def _identify_affected_users(self, incident_data: Dict[str, Any]) -> List[str]:
        """Identify users affected by the incident"""
        affected_users = set()
        
        for audit_log in incident_data.get('audit_logs', []):
            user_id = audit_log.get('user_id')
            target_user_id = audit_log.get('target_user_id')
            if user_id:
                affected_users.add(user_id)
            if target_user_id:
                affected_users.add(target_user_id)
        
        return list(affected_users)
    
    def _assess_data_impact(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess impact on data"""
        data_accessed = []
        data_modified = []
        data_deleted = []
        
        for audit_log in incident_data.get('audit_logs', []):
            action = audit_log.get('action', '').lower()
            data_accessed_list = audit_log.get('data_accessed', [])
            
            if 'read' in action or 'view' in action:
                data_accessed.extend(data_accessed_list)
            elif 'modify' in action or 'update' in action:
                data_modified.extend(data_accessed_list)
            elif 'delete' in action:
                data_deleted.extend(data_accessed_list)
        
        return {
            'data_accessed_count': len(data_accessed),
            'data_modified_count': len(data_modified),
            'data_deleted_count': len(data_deleted),
            'data_categories_affected': list(set(item.get('data_type', 'unknown') 
                                               for item in data_accessed + data_modified + data_deleted 
                                               if isinstance(item, dict)))
        }
    
    def _assess_business_impact(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess business impact"""
        # Simplified business impact assessment
        affected_systems = self._identify_affected_systems(incident_data)
        affected_users = self._identify_affected_users(incident_data)
        
        # Determine business criticality based on affected systems
        critical_systems = ['authentication', 'database', 'payment', 'core_application']
        critical_system_affected = any(system in critical_systems for system in affected_systems)
        
        return {
            'service_disruption': critical_system_affected,
            'user_impact_count': len(affected_users),
            'system_availability_impact': 'high' if critical_system_affected else 'low',
            'estimated_downtime_minutes': self._estimate_downtime(incident_data)
        }
    
    def _assess_security_impact(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess security impact"""
        security_events = incident_data.get('security_events', [])
        threat_predictions = incident_data.get('threat_predictions', [])
        
        return {
            'security_events_count': len(security_events),
            'threat_predictions_count': len(threat_predictions),
            'potential_breach': any(event.get('event_type') == 'potential_breach' 
                                  for event in security_events),
            'unauthorized_access': any(event.get('event_type') == 'unauthorized_access' 
                                     for event in security_events)
        }
    
    def _assess_compliance_impact(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess compliance impact"""
        # Check for compliance-related flags in audit logs
        compliance_flags = []
        
        for audit_log in incident_data.get('audit_logs', []):
            flags = audit_log.get('compliance_flags', [])
            compliance_flags.extend(flags)
        
        return {
            'compliance_flags': list(set(compliance_flags)),
            'requires_regulatory_notification': len(compliance_flags) > 0,
            'gdpr_impact': 'gdpr' in compliance_flags,
            'hipaa_impact': 'hipaa' in compliance_flags
        }
    
    def _estimate_financial_impact(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Estimate financial impact (simplified)"""
        affected_users_count = len(self._identify_affected_users(incident_data))
        downtime_minutes = self._estimate_downtime(incident_data)
        
        # Simplified cost calculation (would be more sophisticated in real implementation)
        cost_per_user_per_hour = 10  # Example cost
        cost_per_downtime_minute = 100  # Example cost
        
        user_impact_cost = affected_users_count * (downtime_minutes / 60) * cost_per_user_per_hour
        downtime_cost = downtime_minutes * cost_per_downtime_minute
        
        total_estimated_cost = user_impact_cost + downtime_cost
        
        return {
            'estimated_total_cost': round(total_estimated_cost, 2),
            'user_impact_cost': round(user_impact_cost, 2),
            'downtime_cost': round(downtime_cost, 2),
            'cost_calculation_basis': 'simplified_estimate'
        }
    
    def _estimate_downtime(self, incident_data: Dict[str, Any]) -> int:
        """Estimate downtime in minutes"""
        # Simplified downtime estimation based on incident duration
        audit_logs = incident_data.get('audit_logs', [])
        if not audit_logs:
            return 0
        
        # Find first and last events
        timestamps = [log.get('timestamp') for log in audit_logs if log.get('timestamp')]
        if len(timestamps) < 2:
            return 0
        
        first_event = min(timestamps)
        last_event = max(timestamps)
        
        duration_seconds = self._calculate_duration(first_event, last_event)
        return duration_seconds // 60  # Convert to minutes
    
    async def _identify_incident_patterns(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Identify patterns in the incident data"""
        try:
            patterns = {
                'temporal_patterns': self._analyze_temporal_patterns(incident_data),
                'user_behavior_patterns': self._analyze_user_behavior_patterns(incident_data),
                'system_access_patterns': self._analyze_system_access_patterns(incident_data),
                'error_patterns': self._analyze_error_patterns(incident_data),
                'security_patterns': self._analyze_security_patterns(incident_data)
            }
            
            return patterns
            
        except Exception as e:
            logger.error(f"Error identifying incident patterns: {e}")
            return {'error': str(e)}
    
    def _analyze_temporal_patterns(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze temporal patterns in the incident"""
        audit_logs = incident_data.get('audit_logs', [])
        
        if not audit_logs:
            return {}
        
        # Group events by hour of day
        hourly_distribution = defaultdict(int)
        
        for log in audit_logs:
            timestamp = log.get('timestamp')
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            
            hour = timestamp.hour
            hourly_distribution[hour] += 1
        
        # Find peak hours
        if hourly_distribution:
            peak_hour = max(hourly_distribution.items(), key=lambda x: x[1])
            
            return {
                'hourly_distribution': dict(hourly_distribution),
                'peak_hour': peak_hour[0],
                'peak_hour_events': peak_hour[1],
                'off_hours_activity': sum(count for hour, count in hourly_distribution.items() 
                                        if hour < 8 or hour > 18)
            }
        
        return {}
    
    def _analyze_user_behavior_patterns(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze user behavior patterns"""
        audit_logs = incident_data.get('audit_logs', [])
        
        user_actions = defaultdict(list)
        
        for log in audit_logs:
            user_id = log.get('user_id')
            action = log.get('action')
            
            if user_id and action:
                user_actions[user_id].append(action)
        
        # Analyze patterns
        patterns = {}
        
        for user_id, actions in user_actions.items():
            action_frequency = defaultdict(int)
            for action in actions:
                action_frequency[action] += 1
            
            patterns[user_id] = {
                'total_actions': len(actions),
                'unique_actions': len(set(actions)),
                'most_common_action': max(action_frequency.items(), key=lambda x: x[1]) if action_frequency else None,
                'action_diversity': len(set(actions)) / len(actions) if actions else 0
            }
        
        return patterns
    
    def _analyze_system_access_patterns(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze system access patterns"""
        audit_logs = incident_data.get('audit_logs', [])
        
        resource_access = defaultdict(int)
        access_results = defaultdict(int)
        
        for log in audit_logs:
            resource_type = log.get('resource_type')
            result = log.get('result')
            
            if resource_type:
                resource_access[resource_type] += 1
            if result:
                access_results[result] += 1
        
        return {
            'resource_access_frequency': dict(resource_access),
            'access_result_distribution': dict(access_results),
            'failure_rate': access_results.get('failure', 0) / sum(access_results.values()) if access_results else 0
        }
    
    def _analyze_error_patterns(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze error patterns"""
        audit_logs = incident_data.get('audit_logs', [])
        
        error_types = defaultdict(int)
        error_timeline = []
        
        for log in audit_logs:
            if log.get('result') in ['failure', 'error', 'denied']:
                error_type = log.get('action', 'unknown_error')
                error_types[error_type] += 1
                
                error_timeline.append({
                    'timestamp': log.get('timestamp'),
                    'error_type': error_type,
                    'user_id': log.get('user_id')
                })
        
        return {
            'error_frequency': dict(error_types),
            'total_errors': sum(error_types.values()),
            'error_timeline': error_timeline,
            'most_common_error': max(error_types.items(), key=lambda x: x[1]) if error_types else None
        }
    
    def _analyze_security_patterns(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security-related patterns"""
        security_events = incident_data.get('security_events', [])
        threat_predictions = incident_data.get('threat_predictions', [])
        
        security_event_types = defaultdict(int)
        threat_types = defaultdict(int)
        
        for event in security_events:
            event_type = event.get('event_type', 'unknown')
            security_event_types[event_type] += 1
        
        for prediction in threat_predictions:
            threat_type = prediction.get('threat_type', 'unknown')
            threat_types[threat_type] += 1
        
        return {
            'security_event_types': dict(security_event_types),
            'threat_prediction_types': dict(threat_types),
            'security_escalation': len([e for e in security_events if e.get('severity') == 'critical'])
        }
    
    async def _generate_incident_recommendations(self, incident_data: Dict[str, Any],
                                               timeline_analysis: Dict[str, Any],
                                               impact_assessment: Dict[str, Any],
                                               pattern_analysis: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate recommendations based on incident analysis"""
        recommendations = []
        
        # Analyze severity and generate appropriate recommendations
        severity = impact_assessment.get('severity', 'low')
        
        if severity in ['high', 'critical']:
            recommendations.append({
                'category': 'immediate',
                'priority': 'high',
                'recommendation': 'Conduct immediate security review of all affected systems',
                'rationale': f'High severity incident ({severity}) requires immediate attention'
            })
        
        # Analyze patterns for recommendations
        temporal_patterns = pattern_analysis.get('temporal_patterns', {})
        off_hours_activity = temporal_patterns.get('off_hours_activity', 0)
        
        if off_hours_activity > 0:
            recommendations.append({
                'category': 'security',
                'priority': 'medium',
                'recommendation': 'Review and strengthen off-hours access controls',
                'rationale': f'Detected {off_hours_activity} off-hours activities during incident'
            })
        
        # Analyze error patterns
        error_patterns = pattern_analysis.get('error_patterns', {})
        failure_rate = pattern_analysis.get('system_access_patterns', {}).get('failure_rate', 0)
        
        if failure_rate > 0.2:  # More than 20% failure rate
            recommendations.append({
                'category': 'system',
                'priority': 'medium',
                'recommendation': 'Investigate and address high failure rate in system access',
                'rationale': f'High failure rate detected: {failure_rate:.1%}'
            })
        
        # Timeline-based recommendations
        timeline_metrics = timeline_analysis.get('timeline_metrics', {})
        total_duration = timeline_metrics.get('total_duration_seconds', 0)
        
        if total_duration > 3600:  # More than 1 hour
            recommendations.append({
                'category': 'process',
                'priority': 'medium',
                'recommendation': 'Review incident response procedures to reduce resolution time',
                'rationale': f'Incident duration was {total_duration // 3600}+ hours'
            })
        
        # Compliance recommendations
        compliance_impact = impact_assessment.get('compliance_impact', {})
        if compliance_impact.get('requires_regulatory_notification'):
            recommendations.append({
                'category': 'compliance',
                'priority': 'high',
                'recommendation': 'Prepare regulatory notifications as required by compliance frameworks',
                'rationale': 'Incident has compliance implications requiring notification'
            })
        
        # Default recommendations if none generated
        if not recommendations:
            recommendations.append({
                'category': 'general',
                'priority': 'low',
                'recommendation': 'Document lessons learned and update incident response procedures',
                'rationale': 'Standard post-incident improvement practice'
            })
        
        return recommendations
    
    def _create_incident_summary(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create executive summary of the incident"""
        audit_logs = incident_data.get('audit_logs', [])
        security_events = incident_data.get('security_events', [])
        
        return {
            'incident_id': incident_data.get('incident_id'),
            'incident_type': incident_data.get('incident_type'),
            'total_events': len(audit_logs) + len(security_events),
            'affected_users_count': len(self._identify_affected_users(incident_data)),
            'affected_systems_count': len(self._identify_affected_systems(incident_data)),
            'data_sources_used': incident_data.get('data_sources', []),
            'analysis_completeness': self._calculate_analysis_completeness(incident_data)
        }
    
    def _extract_lessons_learned(self, incident_data: Dict[str, Any], 
                                recommendations: List[Dict[str, str]]) -> List[str]:
        """Extract lessons learned from the incident"""
        lessons = []
        
        # Extract lessons from high-priority recommendations
        for rec in recommendations:
            if rec.get('priority') == 'high':
                lessons.append(f"Critical lesson: {rec.get('rationale', 'Unknown')}")
        
        # Add general lessons based on incident characteristics
        if len(incident_data.get('security_events', [])) > 0:
            lessons.append("Security monitoring systems successfully detected and reported the incident")
        
        if len(incident_data.get('audit_logs', [])) > 10:
            lessons.append("Comprehensive audit logging provided detailed incident reconstruction")
        
        # Default lesson if none identified
        if not lessons:
            lessons.append("Incident response procedures were followed and documentation was maintained")
        
        return lessons
    
    async def _analyze_compliance_impact(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze compliance impact in detail"""
        compliance_flags = []
        
        for audit_log in incident_data.get('audit_logs', []):
            flags = audit_log.get('compliance_flags', [])
            compliance_flags.extend(flags)
        
        unique_flags = list(set(compliance_flags))
        
        return {
            'compliance_frameworks_affected': unique_flags,
            'notification_requirements': self._determine_notification_requirements(unique_flags),
            'documentation_requirements': self._determine_documentation_requirements(unique_flags),
            'timeline_requirements': self._determine_timeline_requirements(unique_flags)
        }
    
    def _determine_notification_requirements(self, compliance_flags: List[str]) -> List[Dict[str, str]]:
        """Determine notification requirements based on compliance flags"""
        notifications = []
        
        if 'gdpr' in compliance_flags:
            notifications.append({
                'framework': 'GDPR',
                'timeline': '72 hours',
                'authority': 'Data Protection Authority',
                'required': True
            })
        
        if 'hipaa' in compliance_flags:
            notifications.append({
                'framework': 'HIPAA',
                'timeline': '60 days',
                'authority': 'HHS Office for Civil Rights',
                'required': True
            })
        
        return notifications
    
    def _determine_documentation_requirements(self, compliance_flags: List[str]) -> List[str]:
        """Determine documentation requirements"""
        requirements = []
        
        if compliance_flags:
            requirements.extend([
                'Detailed incident timeline with all actions taken',
                'Impact assessment including affected data and individuals',
                'Root cause analysis and contributing factors',
                'Remediation actions taken and planned',
                'Measures to prevent recurrence'
            ])
        
        return requirements
    
    def _determine_timeline_requirements(self, compliance_flags: List[str]) -> Dict[str, str]:
        """Determine timeline requirements for compliance"""
        timelines = {}
        
        if 'gdpr' in compliance_flags:
            timelines['gdpr_notification'] = '72 hours from discovery'
            timelines['gdpr_individual_notification'] = 'Without undue delay if high risk'
        
        if 'hipaa' in compliance_flags:
            timelines['hipaa_notification'] = '60 days from discovery'
        
        return timelines
    
    def _generate_follow_up_actions(self, recommendations: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """Generate specific follow-up actions from recommendations"""
        actions = []
        
        for rec in recommendations:
            action = {
                'action': rec.get('recommendation'),
                'category': rec.get('category'),
                'priority': rec.get('priority'),
                'estimated_effort': self._estimate_action_effort(rec),
                'responsible_team': self._determine_responsible_team(rec),
                'target_completion': self._calculate_target_completion(rec)
            }
            actions.append(action)
        
        return actions
    
    def _estimate_action_effort(self, recommendation: Dict[str, str]) -> str:
        """Estimate effort required for recommendation"""
        category = recommendation.get('category', '')
        priority = recommendation.get('priority', '')
        
        if priority == 'high':
            return 'high'
        elif category in ['system', 'security']:
            return 'medium'
        else:
            return 'low'
    
    def _determine_responsible_team(self, recommendation: Dict[str, str]) -> str:
        """Determine responsible team for recommendation"""
        category = recommendation.get('category', '')
        
        team_mapping = {
            'security': 'Security Team',
            'system': 'IT Operations',
            'compliance': 'Compliance Team',
            'process': 'Process Improvement',
            'immediate': 'Incident Response Team',
            'general': 'IT Management'
        }
        
        return team_mapping.get(category, 'IT Management')
    
    def _calculate_target_completion(self, recommendation: Dict[str, str]) -> str:
        """Calculate target completion date"""
        priority = recommendation.get('priority', 'low')
        
        if priority == 'high':
            return '1 week'
        elif priority == 'medium':
            return '2 weeks'
        else:
            return '1 month'
    
    def _calculate_analysis_completeness(self, incident_data: Dict[str, Any]) -> float:
        """Calculate completeness of the analysis"""
        total_possible_sources = 6  # audit_logs, security_events, session_data, etc.
        available_sources = len(incident_data.get('data_sources', []))
        
        return round((available_sources / total_possible_sources) * 100, 2)
    
    async def _store_incident_report(self, incident_id: str, report: Dict[str, Any]) -> bool:
        """Store the incident report in Firestore"""
        try:
            report_ref = db.collection('incident_reports').document(incident_id)
            report_ref.set(report)
            
            logger.info(f"Incident report stored for {incident_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error storing incident report: {e}")
            return False
    
    async def get_incident_statistics(self, days: int = 30) -> Dict[str, Any]:
        """Get incident statistics for the specified period"""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Query incident reports
            reports_query = db.collection('incident_reports')\
                             .where('generated_at', '>=', cutoff_date)
            
            reports = list(reports_query.stream())
            
            if not reports:
                return {
                    'period_days': days,
                    'total_incidents': 0,
                    'message': 'No incidents found in the specified period'
                }
            
            # Analyze statistics
            severity_distribution = defaultdict(int)
            category_distribution = defaultdict(int)
            monthly_trend = defaultdict(int)
            
            for doc in reports:
                report_data = doc.to_dict()
                
                # Severity distribution
                severity = report_data.get('impact_assessment', {}).get('severity', 'unknown')
                severity_distribution[severity] += 1
                
                # Category distribution
                incident_type = report_data.get('incident_type', 'unknown')
                category_distribution[incident_type] += 1
                
                # Monthly trend
                generated_at = report_data.get('generated_at')
                if isinstance(generated_at, str):
                    generated_at = datetime.fromisoformat(generated_at.replace('Z', '+00:00'))
                
                month_key = generated_at.strftime('%Y-%m')
                monthly_trend[month_key] += 1
            
            return {
                'period_days': days,
                'total_incidents': len(reports),
                'severity_distribution': dict(severity_distribution),
                'category_distribution': dict(category_distribution),
                'monthly_trend': dict(monthly_trend),
                'average_incidents_per_day': round(len(reports) / days, 2),
                'generated_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting incident statistics: {e}")
            return {
                'error': f'Failed to get incident statistics: {str(e)}'
            }


# Global service instance
post_incident_analysis_service = PostIncidentAnalysisService()