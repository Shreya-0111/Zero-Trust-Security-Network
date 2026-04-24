"""
Monitoring Integration Service
Coordinates all monitoring and observability components
"""

import logging
import os
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import threading
import time
from app.services.metrics_service import metrics_service
from app.services.logging_service import logging_service
from app.services.sentry_service import sentry_service
from app.services.performance_monitor_service import performance_monitor
from app.services.cache_service import cache_service

logger = logging.getLogger(__name__)

class MonitoringIntegrationService:
    """Service that integrates all monitoring and observability components"""
    
    def __init__(self):
        self.enabled = True
        self.health_check_interval = 60  # 1 minute
        self.metrics_export_interval = 30  # 30 seconds
        self.log_aggregation_interval = 300  # 5 minutes
        
        # Component status tracking
        self.component_status = {
            'metrics_service': True,
            'logging_service': True,
            'sentry_service': sentry_service.enabled,
            'performance_monitor': True,
            'prometheus_endpoint': True,
            'elasticsearch': self._check_elasticsearch_connection(),
            'grafana': self._check_grafana_connection()
        }
        
        # Start monitoring threads
        self._start_health_monitoring()
        self._start_metrics_export()
        self._start_log_aggregation()
        
        logger.info("Monitoring integration service initialized")
    
    def _check_elasticsearch_connection(self) -> bool:
        """Check if Elasticsearch is available"""
        try:
            # This would implement actual Elasticsearch health check
            elasticsearch_host = os.getenv('ELASTICSEARCH_HOST', 'localhost:9200')
            # Placeholder - would use actual elasticsearch client
            return True
        except Exception as e:
            logger.warning(f"Elasticsearch connection check failed: {e}")
            return False
    
    def _check_grafana_connection(self) -> bool:
        """Check if Grafana is available"""
        try:
            # This would implement actual Grafana health check
            grafana_host = os.getenv('GRAFANA_HOST', 'localhost:3000')
            # Placeholder - would use actual HTTP request
            return True
        except Exception as e:
            logger.warning(f"Grafana connection check failed: {e}")
            return False
    
    def _start_health_monitoring(self):
        """Start health monitoring thread"""
        def monitor_health():
            while self.enabled:
                try:
                    self._perform_health_checks()
                    time.sleep(self.health_check_interval)
                except Exception as e:
                    logger.error(f"Error in health monitoring: {e}")
                    time.sleep(60)
        
        thread = threading.Thread(target=monitor_health, daemon=True)
        thread.start()
        logger.info("Health monitoring started")
    
    def _start_metrics_export(self):
        """Start metrics export thread"""
        def export_metrics():
            while self.enabled:
                try:
                    self._export_custom_metrics()
                    time.sleep(self.metrics_export_interval)
                except Exception as e:
                    logger.error(f"Error in metrics export: {e}")
                    time.sleep(60)
        
        thread = threading.Thread(target=export_metrics, daemon=True)
        thread.start()
        logger.info("Metrics export started")
    
    def _start_log_aggregation(self):
        """Start log aggregation thread"""
        def aggregate_logs():
            while self.enabled:
                try:
                    self._aggregate_log_metrics()
                    time.sleep(self.log_aggregation_interval)
                except Exception as e:
                    logger.error(f"Error in log aggregation: {e}")
                    time.sleep(60)
        
        thread = threading.Thread(target=aggregate_logs, daemon=True)
        thread.start()
        logger.info("Log aggregation started")
    
    def _perform_health_checks(self):
        """Perform health checks on all monitoring components"""
        try:
            # Check metrics service
            try:
                metrics_summary = metrics_service.get_metrics_summary()
                self.component_status['metrics_service'] = 'error' not in metrics_summary
            except Exception as e:
                self.component_status['metrics_service'] = False
                logger.error(f"Metrics service health check failed: {e}")
            
            # Check logging service
            try:
                log_summary = logging_service.get_log_summary(1)
                self.component_status['logging_service'] = 'error' not in log_summary
            except Exception as e:
                self.component_status['logging_service'] = False
                logger.error(f"Logging service health check failed: {e}")
            
            # Check performance monitor
            try:
                perf_summary = performance_monitor.get_performance_summary()
                self.component_status['performance_monitor'] = perf_summary['status'] != 'error'
            except Exception as e:
                self.component_status['performance_monitor'] = False
                logger.error(f"Performance monitor health check failed: {e}")
            
            # Check external services
            self.component_status['elasticsearch'] = self._check_elasticsearch_connection()
            self.component_status['grafana'] = self._check_grafana_connection()
            
            # Update overall health status
            healthy_components = sum(1 for status in self.component_status.values() if status)
            total_components = len(self.component_status)
            health_percentage = (healthy_components / total_components) * 100
            
            # Cache health status
            health_status = {
                'timestamp': datetime.utcnow().isoformat(),
                'overall_health': health_percentage,
                'component_status': self.component_status,
                'healthy_components': healthy_components,
                'total_components': total_components
            }
            
            cache_service.cache_device_profile("monitoring_health_status", health_status, 120)
            
            # Log health status
            if health_percentage < 80:
                logging_service.log_critical_error(
                    "monitoring_health_degraded",
                    f"Monitoring system health degraded: {health_percentage:.1f}%",
                    impact="Reduced observability capabilities"
                )
            
        except Exception as e:
            logger.error(f"Error performing health checks: {e}")
    
    def _export_custom_metrics(self):
        """Export custom application metrics"""
        try:
            # Get current system state and export as metrics
            current_time = datetime.utcnow()
            
            # Export active session counts by user type
            # This would query actual session data
            session_counts = self._get_session_counts()
            for user_type, count in session_counts.items():
                metrics_service.update_active_sessions(user_type, count)
            
            # Export current risk scores
            # This would query actual risk score data
            risk_scores = self._get_current_risk_scores()
            for user_id, score_data in risk_scores.items():
                metrics_service.update_user_risk_score(
                    user_id, 
                    score_data['score'], 
                    score_data.get('category', 'overall')
                )
            
            # Export WebSocket connection counts
            # This would query actual WebSocket data
            ws_connections = self._get_websocket_connections()
            for connection_type, count in ws_connections.items():
                metrics_service.update_websocket_connections(connection_type, count)
            
        except Exception as e:
            logger.error(f"Error exporting custom metrics: {e}")
    
    def _aggregate_log_metrics(self):
        """Aggregate log data into metrics"""
        try:
            # This would query actual log data and create metrics
            # For now, we'll create placeholder aggregations
            
            # Get log summary for the last hour
            log_summary = logging_service.get_log_summary(1)
            
            if 'error' not in log_summary:
                # Export security event metrics
                security_events = log_summary.get('security_events', {})
                for event_type, count in security_events.items():
                    if count > 0:
                        # This would map to appropriate metrics
                        pass
                
                # Export performance metrics
                performance_events = log_summary.get('performance_events', {})
                if performance_events.get('performance_alerts', 0) > 0:
                    # Record performance issues
                    pass
            
        except Exception as e:
            logger.error(f"Error aggregating log metrics: {e}")
    
    def _get_session_counts(self) -> Dict[str, int]:
        """Get current session counts by user type (placeholder)"""
        # This would query actual session data
        return {
            'student': 0,
            'faculty': 0,
            'admin': 0,
            'visitor': 0
        }
    
    def _get_current_risk_scores(self) -> Dict[str, Dict[str, Any]]:
        """Get current user risk scores (placeholder)"""
        # This would query actual risk score data
        return {}
    
    def _get_websocket_connections(self) -> Dict[str, int]:
        """Get current WebSocket connection counts (placeholder)"""
        # This would query actual WebSocket data
        return {
            'admin_dashboard': 0,
            'security_monitoring': 0,
            'real_time_alerts': 0
        }
    
    # Public methods for recording events
    def record_security_event(self, event_type: str, user_id: str, details: Dict[str, Any]):
        """Record a security event across all monitoring systems"""
        try:
            # Record in metrics
            if event_type == 'authentication_attempt':
                metrics_service.record_authentication_attempt(
                    details.get('result', 'unknown'),
                    details.get('method', 'password')
                )
            elif event_type == 'security_violation':
                metrics_service.record_security_violation(
                    details.get('violation_type', 'unknown'),
                    details.get('severity', 'medium')
                )
            elif event_type == 'break_glass_access':
                metrics_service.record_break_glass_access(
                    details.get('status', 'unknown'),
                    details.get('urgency', 'medium')
                )
            
            # Record in structured logs
            if event_type == 'authentication_attempt':
                logging_service.log_authentication_attempt(
                    user_id,
                    details.get('method', 'password'),
                    details.get('result', 'unknown'),
                    details.get('ip_address', ''),
                    details.get('user_agent', ''),
                    **details
                )
            elif event_type == 'security_violation':
                logging_service.log_security_violation(
                    user_id,
                    details.get('violation_type', 'unknown'),
                    details.get('severity', 'medium'),
                    details.get('description', ''),
                    details.get('ip_address', ''),
                    **details
                )
            elif event_type == 'break_glass_access':
                logging_service.log_break_glass_access(
                    user_id,
                    details.get('request_id', ''),
                    details.get('status', 'unknown'),
                    details.get('urgency', 'medium'),
                    details.get('justification', ''),
                    details.get('approvers', []),
                    **details
                )
            
            # Record in Sentry for critical events
            if details.get('severity') in ['critical', 'high'] or event_type == 'break_glass_access':
                if event_type == 'security_violation':
                    sentry_service.capture_security_violation(
                        details.get('violation_type', 'unknown'),
                        user_id,
                        details.get('ip_address', ''),
                        details
                    )
                elif event_type == 'break_glass_access':
                    sentry_service.capture_break_glass_access(
                        user_id,
                        details.get('request_id', ''),
                        details.get('urgency', 'medium'),
                        details.get('justification', '')
                    )
            
        except Exception as e:
            logger.error(f"Error recording security event: {e}")
    
    def record_performance_event(self, metric_name: str, value: float, **kwargs):
        """Record a performance event across all monitoring systems"""
        try:
            # Record in metrics
            if metric_name.startswith('http_'):
                metrics_service.record_http_request(
                    kwargs.get('method', 'GET'),
                    kwargs.get('endpoint', '/'),
                    kwargs.get('status', 200),
                    value
                )
            
            # Record in structured logs
            logging_service.log_performance_metric(
                metric_name,
                value,
                kwargs.get('unit', ''),
                kwargs.get('threshold'),
                kwargs.get('status', 'normal'),
                **kwargs
            )
            
            # Record in Sentry for performance issues
            if kwargs.get('status') in ['critical', 'degraded']:
                sentry_service.capture_performance_issue(
                    metric_name,
                    value,
                    kwargs.get('threshold', 0),
                    kwargs.get('severity', 'medium')
                )
            
        except Exception as e:
            logger.error(f"Error recording performance event: {e}")
    
    def record_application_event(self, event_type: str, **kwargs):
        """Record an application event across all monitoring systems"""
        try:
            # Record in metrics based on event type
            if event_type == 'ml_prediction':
                metrics_service.record_ml_prediction(
                    kwargs.get('model_type', 'unknown'),
                    kwargs.get('confidence', 0.0)
                )
            elif event_type == 'policy_evaluation':
                metrics_service.record_policy_evaluation(
                    kwargs.get('policy_type', 'unknown'),
                    kwargs.get('result', 'unknown')
                )
            elif event_type == 'database_operation':
                metrics_service.record_database_operation(
                    kwargs.get('operation', 'unknown'),
                    kwargs.get('collection', 'unknown'),
                    kwargs.get('result', 'success')
                )
            
            # Record in structured logs
            if event_type == 'ml_prediction':
                logging_service.log_ml_prediction(
                    kwargs.get('model_type', 'unknown'),
                    kwargs.get('input_features', {}),
                    kwargs.get('prediction'),
                    kwargs.get('confidence', 0.0),
                    kwargs.get('processing_time_ms', 0.0),
                    **kwargs
                )
            elif event_type == 'policy_evaluation':
                logging_service.log_policy_evaluation(
                    kwargs.get('policy_type', 'unknown'),
                    kwargs.get('input_data', {}),
                    kwargs.get('result', 'unknown'),
                    kwargs.get('confidence', 0.0),
                    kwargs.get('factors', []),
                    **kwargs
                )
            
        except Exception as e:
            logger.error(f"Error recording application event: {e}")
    
    def get_monitoring_dashboard_data(self) -> Dict[str, Any]:
        """Get comprehensive monitoring data for dashboard"""
        try:
            # Get data from all monitoring components
            metrics_summary = metrics_service.get_metrics_summary()
            log_summary = logging_service.get_log_summary(24)
            performance_summary = performance_monitor.get_performance_summary()
            error_summary = sentry_service.get_error_summary(24)
            health_status = cache_service.get_device_profile("monitoring_health_status") or {}
            
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'health_status': health_status,
                'metrics_summary': metrics_summary,
                'log_summary': log_summary,
                'performance_summary': performance_summary,
                'error_summary': error_summary,
                'component_status': self.component_status
            }
            
        except Exception as e:
            logger.error(f"Error getting monitoring dashboard data: {e}")
            return {
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get current health status of monitoring system"""
        return cache_service.get_device_profile("monitoring_health_status") or {
            'overall_health': 0,
            'component_status': self.component_status,
            'timestamp': datetime.utcnow().isoformat()
        }

# Global monitoring integration service instance
monitoring_integration = MonitoringIntegrationService()