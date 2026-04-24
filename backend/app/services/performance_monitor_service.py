"""
Performance Monitoring Service
Collects and analyzes system performance metrics with alerting
"""

import logging
import time
import threading
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from collections import deque
import statistics

logger = logging.getLogger(__name__)

# Check if performance monitoring should be enabled
ENABLE_PERFORMANCE_MONITORING = os.getenv('ENABLE_PERFORMANCE_MONITORING', 'false').lower() == 'true'

# Conditional imports to avoid heavy loading during development
if ENABLE_PERFORMANCE_MONITORING:
    try:
        from app.services.cache_service import cache_service
        from app.services.load_balancer_service import graceful_degradation_service
    except ImportError:
        ENABLE_PERFORMANCE_MONITORING = False
        logger.warning("Performance monitoring dependencies not available")
else:
    # Mock services for development
    class MockCacheService:
        def cache_device_profile(self, *args, **kwargs): pass
        def get_device_profile(self, *args, **kwargs): return None
        def is_available(self): return False
        def get_cache_stats(self): return {}
    
    class MockGracefulDegradationService:
        def get_current_metrics(self): return None
    
    cache_service = MockCacheService()
    graceful_degradation_service = MockGracefulDegradationService()

@dataclass
class PerformanceMetric:
    """Individual performance metric data point"""
    timestamp: datetime
    metric_name: str
    value: float
    unit: str
    tags: Dict[str, str] = None
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'metric_name': self.metric_name,
            'value': self.value,
            'unit': self.unit,
            'tags': self.tags or {}
        }

@dataclass
class PerformanceAlert:
    """Performance alert definition"""
    alert_id: str
    metric_name: str
    threshold: float
    comparison: str  # 'gt', 'lt', 'eq'
    duration_seconds: int
    severity: str  # 'low', 'medium', 'high', 'critical'
    message: str
    enabled: bool = True
    
class PerformanceMonitorService:
    """Service for monitoring system performance with 5-minute update intervals"""
    
    def __init__(self):
        self.metrics_history = {}  # metric_name -> deque of PerformanceMetric
        self.alerts = {}  # alert_id -> PerformanceAlert
        self.active_alerts = {}  # alert_id -> alert_start_time
        self.monitoring_active = False
        self.update_interval = 300  # 5 minutes in seconds
        self._lock = threading.Lock()
        
        # Keep metrics for 24 hours (288 data points at 5-minute intervals)
        self.max_history_points = 288
        
        # Only initialize if monitoring is enabled
        if ENABLE_PERFORMANCE_MONITORING:
            # Initialize default alerts
            self._setup_default_alerts()
            
            # Start monitoring
            self._start_monitoring()
        else:
            logger.info("Performance monitoring disabled - running in lightweight mode")
    
    def _setup_default_alerts(self):
        """Setup default performance alerts"""
        default_alerts = [
            PerformanceAlert(
                alert_id="high_response_time",
                metric_name="response_time_avg",
                threshold=2000,  # 2 seconds
                comparison="gt",
                duration_seconds=300,  # 5 minutes
                severity="high",
                message="Average response time exceeds 2 seconds"
            ),
            PerformanceAlert(
                alert_id="high_error_rate",
                metric_name="error_rate",
                threshold=5.0,  # 5%
                comparison="gt",
                duration_seconds=300,
                severity="high",
                message="Error rate exceeds 5%"
            ),
            PerformanceAlert(
                alert_id="high_cpu_usage",
                metric_name="cpu_percent",
                threshold=85.0,
                comparison="gt",
                duration_seconds=600,  # 10 minutes
                severity="medium",
                message="CPU usage exceeds 85%"
            ),
            PerformanceAlert(
                alert_id="high_memory_usage",
                metric_name="memory_percent",
                threshold=90.0,
                comparison="gt",
                duration_seconds=600,
                severity="high",
                message="Memory usage exceeds 90%"
            ),
            PerformanceAlert(
                alert_id="critical_system_load",
                metric_name="overall_load",
                threshold=95.0,
                comparison="gt",
                duration_seconds=180,  # 3 minutes
                severity="critical",
                message="System load is critical (>95%)"
            )
        ]
        
        for alert in default_alerts:
            self.alerts[alert.alert_id] = alert
    
    def _start_monitoring(self):
        """Start performance monitoring thread"""
        if not ENABLE_PERFORMANCE_MONITORING:
            return
            
        def monitor():
            while self.monitoring_active:
                try:
                    self._collect_performance_metrics()
                    self._evaluate_alerts()
                    time.sleep(self.update_interval)
                except Exception as e:
                    logger.error(f"Error in performance monitoring: {e}")
                    time.sleep(60)  # Wait 1 minute on error
        
        self.monitoring_active = True
        monitor_thread = threading.Thread(target=monitor, daemon=True)
        monitor_thread.start()
        logger.info(f"Performance monitoring started with {self.update_interval}s intervals")
    
    def _collect_performance_metrics(self):
        """Collect current performance metrics"""
        try:
            current_time = datetime.utcnow()
            
            # Get system metrics from load balancer service
            system_metrics = graceful_degradation_service.get_current_metrics()
            
            if system_metrics:
                # Record individual metrics
                metrics_to_record = [
                    ("cpu_percent", system_metrics.cpu_percent, "%"),
                    ("memory_percent", system_metrics.memory_percent, "%"),
                    ("active_connections", system_metrics.active_connections, "count"),
                    ("request_rate", system_metrics.request_rate, "req/s"),
                    ("response_time_avg", system_metrics.response_time_avg, "ms"),
                    ("error_rate", system_metrics.error_rate, "%"),
                    ("overall_load", system_metrics.overall_load, "%")
                ]
                
                for metric_name, value, unit in metrics_to_record:
                    self._record_metric(metric_name, value, unit, current_time)
            
            # Get connection pool metrics
            from app.services.connection_pool_service import connection_pool_service
            pool_stats = connection_pool_service.get_all_stats()
            
            if pool_stats.get('firestore'):
                firestore_stats = pool_stats['firestore']
                self._record_metric("firestore_active_connections", firestore_stats.get('active_connections', 0), "count", current_time)
                self._record_metric("firestore_pool_utilization", 
                                  (firestore_stats.get('active_connections', 0) / firestore_stats.get('max_connections', 1)) * 100, 
                                  "%", current_time)
            
            if pool_stats.get('redis'):
                redis_stats = pool_stats['redis']
                self._record_metric("redis_active_connections", redis_stats.get('active_connections', 0), "count", current_time)
                self._record_metric("redis_pool_utilization", 
                                  (redis_stats.get('active_connections', 0) / redis_stats.get('max_connections', 1)) * 100, 
                                  "%", current_time)
            
            # Get cache hit rate if available
            if cache_service.is_available():
                cache_stats = cache_service.get_cache_stats()
                if cache_stats and 'hits' in cache_stats and 'misses' in cache_stats:
                    total_requests = cache_stats['hits'] + cache_stats['misses']
                    hit_rate = (cache_stats['hits'] / total_requests * 100) if total_requests > 0 else 0
                    self._record_metric("cache_hit_rate", hit_rate, "%", current_time)
            
            # Cache current metrics for dashboard
            self._cache_current_metrics()
            
        except Exception as e:
            logger.error(f"Error collecting performance metrics: {e}")
    
    def _record_metric(self, metric_name: str, value: float, unit: str, timestamp: datetime, tags: Dict[str, str] = None):
        """Record a performance metric"""
        with self._lock:
            if metric_name not in self.metrics_history:
                self.metrics_history[metric_name] = deque(maxlen=self.max_history_points)
            
            metric = PerformanceMetric(
                timestamp=timestamp,
                metric_name=metric_name,
                value=value,
                unit=unit,
                tags=tags
            )
            
            self.metrics_history[metric_name].append(metric)
    
    def _cache_current_metrics(self):
        """Cache current metrics for dashboard access"""
        try:
            current_metrics = {}
            
            with self._lock:
                for metric_name, history in self.metrics_history.items():
                    if history:
                        latest_metric = history[-1]
                        current_metrics[metric_name] = {
                            'value': latest_metric.value,
                            'unit': latest_metric.unit,
                            'timestamp': latest_metric.timestamp.isoformat(),
                            'tags': latest_metric.tags or {}
                        }
            
            # Cache for 6 minutes (slightly longer than update interval)
            cache_service.cache_device_profile("performance_metrics:current", current_metrics, 360)
            
        except Exception as e:
            logger.error(f"Error caching performance metrics: {e}")
    
    def _evaluate_alerts(self):
        """Evaluate performance alerts"""
        try:
            current_time = datetime.utcnow()
            
            for alert_id, alert in self.alerts.items():
                if not alert.enabled:
                    continue
                
                # Get recent metrics for this alert
                if alert.metric_name not in self.metrics_history:
                    continue
                
                recent_metrics = self._get_recent_metrics(alert.metric_name, alert.duration_seconds)
                
                if not recent_metrics:
                    continue
                
                # Check if alert condition is met
                alert_triggered = self._check_alert_condition(alert, recent_metrics)
                
                if alert_triggered and alert_id not in self.active_alerts:
                    # New alert
                    self.active_alerts[alert_id] = current_time
                    self._trigger_alert(alert, recent_metrics[-1].value)
                    
                elif not alert_triggered and alert_id in self.active_alerts:
                    # Alert resolved
                    del self.active_alerts[alert_id]
                    self._resolve_alert(alert)
                    
        except Exception as e:
            logger.error(f"Error evaluating alerts: {e}")
    
    def _get_recent_metrics(self, metric_name: str, duration_seconds: int) -> List[PerformanceMetric]:
        """Get metrics from the last N seconds"""
        if metric_name not in self.metrics_history:
            return []
        
        cutoff_time = datetime.utcnow() - timedelta(seconds=duration_seconds)
        
        with self._lock:
            recent_metrics = [
                metric for metric in self.metrics_history[metric_name]
                if metric.timestamp >= cutoff_time
            ]
        
        return recent_metrics
    
    def _check_alert_condition(self, alert: PerformanceAlert, metrics: List[PerformanceMetric]) -> bool:
        """Check if alert condition is met"""
        if not metrics:
            return False
        
        # Use average value over the duration
        values = [metric.value for metric in metrics]
        avg_value = statistics.mean(values)
        
        if alert.comparison == "gt":
            return avg_value > alert.threshold
        elif alert.comparison == "lt":
            return avg_value < alert.threshold
        elif alert.comparison == "eq":
            return abs(avg_value - alert.threshold) < 0.01
        
        return False
    
    def _trigger_alert(self, alert: PerformanceAlert, current_value: float):
        """Trigger a performance alert"""
        try:
            alert_data = {
                'alert_id': alert.alert_id,
                'metric_name': alert.metric_name,
                'current_value': current_value,
                'threshold': alert.threshold,
                'severity': alert.severity,
                'message': alert.message,
                'triggered_at': datetime.utcnow().isoformat()
            }
            
            # Cache alert for dashboard
            cache_service.cache_device_profile(f"performance_alert:{alert.alert_id}", alert_data, 3600)
            
            # Log alert
            logger.warning(f"Performance alert triggered: {alert.message} (current: {current_value}, threshold: {alert.threshold})")
            
            # Send notification (integrate with notification service)
            self._send_alert_notification(alert_data)
            
        except Exception as e:
            logger.error(f"Error triggering alert: {e}")
    
    def _resolve_alert(self, alert: PerformanceAlert):
        """Resolve a performance alert"""
        try:
            # Remove from cache
            cache_service.cache_device_profile(f"performance_alert:{alert.alert_id}", None, 1)
            
            logger.info(f"Performance alert resolved: {alert.message}")
            
        except Exception as e:
            logger.error(f"Error resolving alert: {e}")
    
    def _send_alert_notification(self, alert_data: Dict[str, Any]):
        """Send alert notification"""
        try:
            # Cache notification for admin dashboard
            notification_data = {
                'type': 'performance_alert',
                'severity': alert_data['severity'],
                'title': f"Performance Alert: {alert_data['metric_name']}",
                'message': alert_data['message'],
                'data': alert_data,
                'timestamp': alert_data['triggered_at']
            }
            
            cache_service.cache_device_profile("performance_notifications:latest", notification_data, 3600)
            
        except Exception as e:
            logger.error(f"Error sending alert notification: {e}")
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics"""
        try:
            cached_metrics = cache_service.get_device_profile("performance_metrics:current")
            if cached_metrics:
                return cached_metrics
            
            # Fallback to latest metrics from memory
            current_metrics = {}
            
            with self._lock:
                for metric_name, history in self.metrics_history.items():
                    if history:
                        latest_metric = history[-1]
                        current_metrics[metric_name] = {
                            'value': latest_metric.value,
                            'unit': latest_metric.unit,
                            'timestamp': latest_metric.timestamp.isoformat(),
                            'tags': latest_metric.tags or {}
                        }
            
            return current_metrics
            
        except Exception as e:
            logger.error(f"Error getting current metrics: {e}")
            return {}
    
    def get_metric_history(self, metric_name: str, hours: int = 24) -> List[Dict[str, Any]]:
        """Get historical data for a specific metric"""
        try:
            if metric_name not in self.metrics_history:
                return []
            
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            
            with self._lock:
                historical_data = [
                    metric.to_dict() for metric in self.metrics_history[metric_name]
                    if metric.timestamp >= cutoff_time
                ]
            
            return historical_data
            
        except Exception as e:
            logger.error(f"Error getting metric history: {e}")
            return []
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get currently active alerts"""
        try:
            active_alerts = []
            
            for alert_id in self.active_alerts:
                cached_alert = cache_service.get_device_profile(f"performance_alert:{alert_id}")
                if cached_alert:
                    active_alerts.append(cached_alert)
            
            return active_alerts
            
        except Exception as e:
            logger.error(f"Error getting active alerts: {e}")
            return []
    
    def add_custom_alert(self, alert: PerformanceAlert) -> bool:
        """Add a custom performance alert"""
        try:
            self.alerts[alert.alert_id] = alert
            logger.info(f"Added custom alert: {alert.alert_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding custom alert: {e}")
            return False
    
    def remove_alert(self, alert_id: str) -> bool:
        """Remove a performance alert"""
        try:
            if alert_id in self.alerts:
                del self.alerts[alert_id]
                
                # Remove from active alerts if present
                if alert_id in self.active_alerts:
                    del self.active_alerts[alert_id]
                
                logger.info(f"Removed alert: {alert_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error removing alert: {e}")
            return False
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary for dashboard"""
        try:
            current_metrics = self.get_current_metrics()
            active_alerts = self.get_active_alerts()
            
            # Calculate performance score (0-100)
            performance_score = 100
            
            if 'overall_load' in current_metrics:
                load = current_metrics['overall_load']['value']
                performance_score = max(0, 100 - load)
            
            # Determine overall status
            if len(active_alerts) == 0:
                status = "healthy"
            elif any(alert['severity'] == 'critical' for alert in active_alerts):
                status = "critical"
            elif any(alert['severity'] == 'high' for alert in active_alerts):
                status = "degraded"
            else:
                status = "warning"
            
            return {
                'status': status,
                'performance_score': performance_score,
                'active_alerts_count': len(active_alerts),
                'current_metrics': current_metrics,
                'active_alerts': active_alerts,
                'last_updated': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting performance summary: {e}")
            return {
                'status': 'error',
                'performance_score': 0,
                'active_alerts_count': 0,
                'current_metrics': {},
                'active_alerts': [],
                'last_updated': datetime.utcnow().isoformat(),
                'error': str(e)
            }

# Global performance monitor instance - DISABLED FOR FAST STARTUP
# Only initialize if explicitly enabled
if ENABLE_PERFORMANCE_MONITORING:
    performance_monitor = PerformanceMonitorService()
    print("Performance monitoring enabled")
else:
    # Mock performance monitor for development
    class MockPerformanceMonitor:
        def get_current_metrics(self): return {}
        def get_metric_history(self, *args, **kwargs): return []
        def get_active_alerts(self): return []
        def get_performance_summary(self): return {'status': 'disabled', 'performance_score': 100}
        def add_custom_alert(self, *args, **kwargs): return True
        def remove_alert(self, *args, **kwargs): return True
    
    performance_monitor = MockPerformanceMonitor()
    print("Performance monitoring disabled for fast startup")