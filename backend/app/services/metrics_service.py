"""
Metrics Service for Prometheus Integration
Provides comprehensive metrics collection for the Zero Trust Security Framework
"""

import logging
import time
from typing import Dict, Any, Optional, List
from datetime import datetime
from functools import wraps
# from prometheus_client import Counter, Histogram, Gauge, Info, CollectorRegistry, generate_latest  # Temporarily disabled

# Mock classes for when prometheus_client is not available
class MockCounter:
    def __init__(self, name, description, labelnames=None, registry=None):
        self.name = name
        self.description = description
        self.labelnames = labelnames or []
        self.registry = registry
    
    def inc(self, amount=1):
        pass
    
    def labels(self, **kwargs):
        return self

class MockHistogram:
    def __init__(self, name, description, labelnames=None, buckets=None, registry=None):
        self.name = name
        self.description = description
        self.labelnames = labelnames or []
        self.registry = registry
    
    def observe(self, amount):
        pass
    
    def labels(self, **kwargs):
        return self

class MockGauge:
    def __init__(self, name, description, labelnames=None, registry=None):
        self.name = name
        self.description = description
        self.labelnames = labelnames or []
        self.registry = registry
    
    def set(self, value):
        pass
    
    def inc(self, amount=1):
        pass
    
    def dec(self, amount=1):
        pass
    
    def labels(self, **kwargs):
        return self

class MockInfo:
    def __init__(self, name, description, labelnames=None, registry=None):
        self.name = name
        self.description = description
        self.labelnames = labelnames or []
        self.registry = registry
    
    def info(self, data):
        pass
    
    def labels(self, **kwargs):
        return self

# Use mock classes
Counter = MockCounter
Histogram = MockHistogram
Gauge = MockGauge
Info = MockInfo

def generate_latest(registry=None):
    """Mock generate_latest function"""
    return b"# Mock metrics - prometheus_client not available\n"

class MockCollectorRegistry:
    """Mock CollectorRegistry"""
    def __init__(self):
        pass

CollectorRegistry = MockCollectorRegistry
REGISTRY = MockCollectorRegistry()
import psutil
import threading
from app.services.cache_service import cache_service

logger = logging.getLogger(__name__)

class MetricsService:
    """Service for collecting and exposing Prometheus metrics"""
    
    def __init__(self):
        # Create custom registry for our metrics
        self.registry = CollectorRegistry()
        
        # Security metrics
        self.authentication_attempts = Counter(
            'authentication_attempts_total',
            'Total authentication attempts',
            ['result', 'method'],
            registry=self.registry
        )
        
        self.device_fingerprint_validations = Counter(
            'device_fingerprint_validations_total',
            'Total device fingerprint validations',
            ['result', 'similarity_score_range'],
            registry=self.registry
        )
        
        self.security_violations = Counter(
            'security_violations_total',
            'Total security violations',
            ['violation_type', 'severity'],
            registry=self.registry
        )
        
        self.break_glass_access = Counter(
            'break_glass_access_total',
            'Total break-glass access requests',
            ['status', 'urgency'],
            registry=self.registry
        )
        
        self.jit_access_requests = Counter(
            'jit_access_requests_total',
            'Total JIT access requests',
            ['status', 'resource_segment'],
            registry=self.registry
        )
        
        self.visitor_activities = Counter(
            'visitor_activities_total',
            'Total visitor activities',
            ['activity_type', 'compliance_status'],
            registry=self.registry
        )
        
        # Risk and continuous authentication metrics
        self.user_risk_score = Gauge(
            'user_risk_score',
            'Current user risk scores',
            ['user_id', 'risk_category'],
            registry=self.registry
        )
        
        self.continuous_auth_challenges = Counter(
            'continuous_auth_challenges_total',
            'Total continuous authentication challenges',
            ['trigger_reason', 'result'],
            registry=self.registry
        )
        
        self.session_terminations = Counter(
            'session_terminations_total',
            'Total session terminations',
            ['reason', 'risk_level'],
            registry=self.registry
        )
        
        # Performance metrics
        self.http_requests = Counter(
            'http_requests_total',
            'Total HTTP requests',
            ['method', 'endpoint', 'status'],
            registry=self.registry
        )
        
        self.http_request_duration = Histogram(
            'http_request_duration_seconds',
            'HTTP request duration in seconds',
            ['method', 'endpoint'],
            registry=self.registry
        )
        
        self.active_sessions = Gauge(
            'active_sessions',
            'Number of active user sessions',
            ['user_type'],
            registry=self.registry
        )
        
        self.database_operations = Counter(
            'database_operations_total',
            'Total database operations',
            ['operation', 'collection', 'result'],
            registry=self.registry
        )
        
        self.cache_operations = Counter(
            'cache_operations_total',
            'Total cache operations',
            ['operation', 'result'],
            registry=self.registry
        )
        
        # System metrics
        self.system_cpu_usage = Gauge(
            'system_cpu_usage_percent',
            'System CPU usage percentage',
            registry=self.registry
        )
        
        self.system_memory_usage = Gauge(
            'system_memory_usage_percent',
            'System memory usage percentage',
            registry=self.registry
        )
        
        self.system_disk_usage = Gauge(
            'system_disk_usage_percent',
            'System disk usage percentage',
            ['mount_point'],
            registry=self.registry
        )
        
        # Application-specific metrics
        self.ml_model_predictions = Counter(
            'ml_model_predictions_total',
            'Total ML model predictions',
            ['model_type', 'confidence_range'],
            registry=self.registry
        )
        
        self.policy_evaluations = Counter(
            'policy_evaluations_total',
            'Total policy evaluations',
            ['policy_type', 'result'],
            registry=self.registry
        )
        
        self.audit_logs_created = Counter(
            'audit_logs_created_total',
            'Total audit logs created',
            ['event_type', 'severity'],
            registry=self.registry
        )
        
        # WebSocket metrics
        self.websocket_connections = Gauge(
            'websocket_connections_active',
            'Active WebSocket connections',
            ['connection_type'],
            registry=self.registry
        )
        
        self.websocket_messages = Counter(
            'websocket_messages_total',
            'Total WebSocket messages',
            ['message_type', 'direction'],
            registry=self.registry
        )
        
        # Application info
        self.app_info = Info(
            'zero_trust_app_info',
            'Zero Trust Security Framework application information',
            registry=self.registry
        )
        
        # Set application info
        self.app_info.info({
            'version': '1.0.0',
            'environment': 'production',
            'framework': 'enhanced-zero-trust'
        })
        
        # Start system metrics collection
        self._start_system_metrics_collection()
    
    def _start_system_metrics_collection(self):
        """Start background thread for system metrics collection"""
        def collect_system_metrics():
            while True:
                try:
                    # CPU usage
                    cpu_percent = psutil.cpu_percent(interval=1)
                    self.system_cpu_usage.set(cpu_percent)
                    
                    # Memory usage
                    memory = psutil.virtual_memory()
                    self.system_memory_usage.set(memory.percent)
                    
                    # Disk usage
                    for partition in psutil.disk_partitions():
                        try:
                            usage = psutil.disk_usage(partition.mountpoint)
                            self.system_disk_usage.labels(
                                mount_point=partition.mountpoint
                            ).set(usage.percent)
                        except (PermissionError, FileNotFoundError):
                            continue
                    
                    time.sleep(30)  # Collect every 30 seconds
                    
                except Exception as e:
                    logger.error(f"Error collecting system metrics: {e}")
                    time.sleep(60)  # Wait longer on error
        
        thread = threading.Thread(target=collect_system_metrics, daemon=True)
        thread.start()
        logger.info("System metrics collection started")
    
    # Security metrics methods
    def record_authentication_attempt(self, result: str, method: str = 'password'):
        """Record authentication attempt"""
        self.authentication_attempts.labels(result=result, method=method).inc()
    
    def record_device_fingerprint_validation(self, result: str, similarity_score: float):
        """Record device fingerprint validation"""
        # Categorize similarity score
        if similarity_score >= 95:
            score_range = "95-100"
        elif similarity_score >= 85:
            score_range = "85-94"
        elif similarity_score >= 70:
            score_range = "70-84"
        else:
            score_range = "0-69"
        
        self.device_fingerprint_validations.labels(
            result=result,
            similarity_score_range=score_range
        ).inc()
    
    def record_security_violation(self, violation_type: str, severity: str):
        """Record security violation"""
        self.security_violations.labels(
            violation_type=violation_type,
            severity=severity
        ).inc()
    
    def record_break_glass_access(self, status: str, urgency: str):
        """Record break-glass access request"""
        self.break_glass_access.labels(status=status, urgency=urgency).inc()
    
    def record_jit_access_request(self, status: str, resource_segment: str):
        """Record JIT access request"""
        self.jit_access_requests.labels(
            status=status,
            resource_segment=resource_segment
        ).inc()
    
    def record_visitor_activity(self, activity_type: str, compliance_status: str):
        """Record visitor activity"""
        self.visitor_activities.labels(
            activity_type=activity_type,
            compliance_status=compliance_status
        ).inc()
    
    def update_user_risk_score(self, user_id: str, risk_score: float, risk_category: str = 'overall'):
        """Update user risk score"""
        self.user_risk_score.labels(
            user_id=user_id,
            risk_category=risk_category
        ).set(risk_score)
    
    def record_continuous_auth_challenge(self, trigger_reason: str, result: str):
        """Record continuous authentication challenge"""
        self.continuous_auth_challenges.labels(
            trigger_reason=trigger_reason,
            result=result
        ).inc()
    
    def record_session_termination(self, reason: str, risk_level: str):
        """Record session termination"""
        self.session_terminations.labels(reason=reason, risk_level=risk_level).inc()
    
    # Performance metrics methods
    def record_http_request(self, method: str, endpoint: str, status: int, duration: float):
        """Record HTTP request metrics"""
        self.http_requests.labels(
            method=method,
            endpoint=endpoint,
            status=str(status)
        ).inc()
        
        self.http_request_duration.labels(
            method=method,
            endpoint=endpoint
        ).observe(duration)
    
    def update_active_sessions(self, user_type: str, count: int):
        """Update active sessions count"""
        self.active_sessions.labels(user_type=user_type).set(count)
    
    def record_database_operation(self, operation: str, collection: str, result: str):
        """Record database operation"""
        self.database_operations.labels(
            operation=operation,
            collection=collection,
            result=result
        ).inc()
    
    def record_cache_operation(self, operation: str, result: str):
        """Record cache operation"""
        self.cache_operations.labels(operation=operation, result=result).inc()
    
    # Application metrics methods
    def record_ml_prediction(self, model_type: str, confidence: float):
        """Record ML model prediction"""
        # Categorize confidence
        if confidence >= 0.9:
            confidence_range = "90-100"
        elif confidence >= 0.7:
            confidence_range = "70-89"
        elif confidence >= 0.5:
            confidence_range = "50-69"
        else:
            confidence_range = "0-49"
        
        self.ml_model_predictions.labels(
            model_type=model_type,
            confidence_range=confidence_range
        ).inc()
    
    def record_policy_evaluation(self, policy_type: str, result: str):
        """Record policy evaluation"""
        self.policy_evaluations.labels(policy_type=policy_type, result=result).inc()
    
    def record_audit_log(self, event_type: str, severity: str):
        """Record audit log creation"""
        self.audit_logs_created.labels(event_type=event_type, severity=severity).inc()
    
    # WebSocket metrics methods
    def update_websocket_connections(self, connection_type: str, count: int):
        """Update WebSocket connections count"""
        self.websocket_connections.labels(connection_type=connection_type).set(count)
    
    def record_websocket_message(self, message_type: str, direction: str):
        """Record WebSocket message"""
        self.websocket_messages.labels(
            message_type=message_type,
            direction=direction
        ).inc()
    
    def get_metrics(self) -> str:
        """Get Prometheus metrics in text format"""
        return generate_latest(self.registry).decode('utf-8')
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get metrics summary for dashboard"""
        try:
            # Get current metric values
            summary = {
                'timestamp': datetime.utcnow().isoformat(),
                'security': {
                    'authentication_attempts_1h': self._get_counter_rate('authentication_attempts_total', 3600),
                    'security_violations_1h': self._get_counter_rate('security_violations_total', 3600),
                    'break_glass_access_24h': self._get_counter_rate('break_glass_access_total', 86400),
                    'active_high_risk_users': self._count_high_risk_users()
                },
                'performance': {
                    'cpu_usage': psutil.cpu_percent(),
                    'memory_usage': psutil.virtual_memory().percent,
                    'active_sessions': self._get_total_active_sessions(),
                    'avg_response_time': self._get_avg_response_time()
                },
                'application': {
                    'ml_predictions_1h': self._get_counter_rate('ml_model_predictions_total', 3600),
                    'policy_evaluations_1h': self._get_counter_rate('policy_evaluations_total', 3600),
                    'audit_logs_1h': self._get_counter_rate('audit_logs_created_total', 3600)
                }
            }
            
            return summary
            
        except Exception as e:
            logger.error(f"Error getting metrics summary: {e}")
            return {'error': str(e), 'timestamp': datetime.utcnow().isoformat()}
    
    def _get_counter_rate(self, metric_name: str, time_window: int) -> float:
        """Get counter rate over time window (placeholder - would need time series data)"""
        # This is a simplified implementation
        # In production, you'd query the actual time series data
        return 0.0
    
    def _count_high_risk_users(self) -> int:
        """Count users with high risk scores (placeholder)"""
        # This would query actual risk score data
        return 0
    
    def _get_total_active_sessions(self) -> int:
        """Get total active sessions across all user types"""
        # This would sum up actual session counts
        return 0
    
    def _get_avg_response_time(self) -> float:
        """Get average response time (placeholder)"""
        # This would calculate from actual histogram data
        return 0.0

# Decorator for automatic HTTP request metrics
def track_request_metrics(metrics_service: MetricsService):
    """Decorator to automatically track HTTP request metrics"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            
            try:
                result = f(*args, **kwargs)
                duration = time.time() - start_time
                
                # Extract request info (this would need to be adapted based on your Flask setup)
                method = getattr(f, '_method', 'GET')
                endpoint = getattr(f, '_endpoint', f.__name__)
                status = 200  # Default success
                
                metrics_service.record_http_request(method, endpoint, status, duration)
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                method = getattr(f, '_method', 'GET')
                endpoint = getattr(f, '_endpoint', f.__name__)
                status = 500  # Error status
                
                metrics_service.record_http_request(method, endpoint, status, duration)
                raise
        
        return wrapper
    return decorator

# Global metrics service instance
metrics_service = MetricsService()