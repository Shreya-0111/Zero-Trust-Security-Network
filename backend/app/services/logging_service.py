"""
Structured Logging Service with ELK Stack Integration
Provides centralized logging with structured data for the Zero Trust Security Framework
"""

import logging
import json
import sys
from typing import Dict, Any, Optional, List
from datetime import datetime
import structlog
try:
    from logstash_logger import LogstashLogger
except ImportError:
    LogstashLogger = None
import os
from app.services.cache_service import cache_service

class StructuredLoggingService:
    """Service for structured logging with ELK stack integration"""
    
    def __init__(self):
        self.environment = os.getenv('ENVIRONMENT', 'development')
        self.service_name = 'zero-trust-security-framework'
        self.version = '1.0.0'
        
        # Configure structlog
        self._configure_structlog()
        
        # Configure logstash integration if enabled
        self.logstash_enabled = os.getenv('LOGSTASH_ENABLED', 'false').lower() == 'true'
        if self.logstash_enabled:
            self._configure_logstash()
        
        # Create logger instances
        self.security_logger = structlog.get_logger("security")
        self.performance_logger = structlog.get_logger("performance")
        self.audit_logger = structlog.get_logger("audit")
        self.application_logger = structlog.get_logger("application")
        self.error_logger = structlog.get_logger("error")
        
        # Log levels
        self.LOG_LEVELS = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL
        }
    
    def _configure_structlog(self):
        """Configure structlog for structured logging"""
        def add_service_info(logger, method_name, event_dict):
            """Add service information to all log entries"""
            event_dict['service'] = self.service_name
            event_dict['version'] = self.version
            event_dict['environment'] = self.environment
            event_dict['timestamp'] = datetime.utcnow().isoformat()
            return event_dict
        
        def add_correlation_id(logger, method_name, event_dict):
            """Add correlation ID if available"""
            # This would be set by middleware in a real application
            correlation_id = getattr(logger, '_correlation_id', None)
            if correlation_id:
                event_dict['correlation_id'] = correlation_id
            return event_dict
        
        # Configure structlog
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                add_service_info,
                add_correlation_id,
                structlog.processors.TimeStamper(fmt="ISO"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.processors.JSONRenderer()
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
    
    def _configure_logstash(self):
        """Configure Logstash integration"""
        try:
            if LogstashLogger is None:
                print("LogstashLogger not available, skipping Logstash configuration")
                return
                
            logstash_host = os.getenv('LOGSTASH_HOST', 'localhost')
            logstash_port = int(os.getenv('LOGSTASH_PORT', '5000'))
            
            # Create Logstash handler
            logstash_handler = LogstashLogger(
                host=logstash_host,
                port=logstash_port,
                version=1,
                message_type='zero-trust-logs'
            )
            
            # Add to root logger
            root_logger = logging.getLogger()
            root_logger.addHandler(logstash_handler)
            root_logger.setLevel(logging.INFO)
            
        except Exception as e:
            print(f"Failed to configure Logstash: {e}")
    
    # Security logging methods
    def log_authentication_attempt(self, user_id: str, method: str, result: str, 
                                 ip_address: str, user_agent: str, **kwargs):
        """Log authentication attempt"""
        self.security_logger.info(
            "authentication_attempt",
            user_id=user_id,
            method=method,
            result=result,
            ip_address=ip_address,
            user_agent=user_agent,
            event_type="authentication",
            **kwargs
        )
    
    def log_device_fingerprint_validation(self, user_id: str, device_id: str, 
                                        similarity_score: float, result: str, **kwargs):
        """Log device fingerprint validation"""
        self.security_logger.info(
            "device_fingerprint_validation",
            user_id=user_id,
            device_id=device_id,
            similarity_score=similarity_score,
            result=result,
            event_type="device_validation",
            **kwargs
        )
    
    def log_security_violation(self, user_id: str, violation_type: str, severity: str,
                             description: str, ip_address: str, **kwargs):
        """Log security violation"""
        self.security_logger.warning(
            "security_violation",
            user_id=user_id,
            violation_type=violation_type,
            severity=severity,
            description=description,
            ip_address=ip_address,
            event_type="security_violation",
            **kwargs
        )
    
    def log_break_glass_access(self, user_id: str, request_id: str, status: str,
                             urgency: str, justification: str, approvers: list = None, **kwargs):
        """Log break-glass access request"""
        self.security_logger.critical(
            "break_glass_access",
            user_id=user_id,
            request_id=request_id,
            status=status,
            urgency=urgency,
            justification=justification,
            approvers=approvers or [],
            event_type="break_glass",
            **kwargs
        )
    
    def log_jit_access_request(self, user_id: str, resource_segment: str, status: str,
                             duration: int, risk_score: float, **kwargs):
        """Log JIT access request"""
        self.security_logger.info(
            "jit_access_request",
            user_id=user_id,
            resource_segment=resource_segment,
            status=status,
            duration_hours=duration,
            risk_score=risk_score,
            event_type="jit_access",
            **kwargs
        )
    
    def log_visitor_activity(self, visitor_id: str, host_id: str, activity_type: str,
                           resource_segment: str, compliance_status: str, **kwargs):
        """Log visitor activity"""
        self.security_logger.info(
            "visitor_activity",
            visitor_id=visitor_id,
            host_id=host_id,
            activity_type=activity_type,
            resource_segment=resource_segment,
            compliance_status=compliance_status,
            event_type="visitor_activity",
            **kwargs
        )
    
    def log_risk_score_change(self, user_id: str, old_score: float, new_score: float,
                            risk_factors: list, trigger_reason: str, **kwargs):
        """Log risk score change"""
        self.security_logger.info(
            "risk_score_change",
            user_id=user_id,
            old_risk_score=old_score,
            new_risk_score=new_score,
            risk_factors=risk_factors,
            trigger_reason=trigger_reason,
            event_type="risk_assessment",
            **kwargs
        )
    
    def log_session_termination(self, user_id: str, session_id: str, reason: str,
                              risk_level: str, duration_minutes: int, **kwargs):
        """Log session termination"""
        self.security_logger.warning(
            "session_termination",
            user_id=user_id,
            session_id=session_id,
            reason=reason,
            risk_level=risk_level,
            duration_minutes=duration_minutes,
            event_type="session_management",
            **kwargs
        )
    
    # Performance logging methods
    def log_performance_metric(self, metric_name: str, value: float, unit: str,
                             threshold: float = None, status: str = "normal", **kwargs):
        """Log performance metric"""
        self.performance_logger.info(
            "performance_metric",
            metric_name=metric_name,
            value=value,
            unit=unit,
            threshold=threshold,
            status=status,
            event_type="performance",
            **kwargs
        )
    
    def log_performance_alert(self, alert_id: str, metric_name: str, current_value: float,
                            threshold: float, severity: str, **kwargs):
        """Log performance alert"""
        self.performance_logger.warning(
            "performance_alert",
            alert_id=alert_id,
            metric_name=metric_name,
            current_value=current_value,
            threshold=threshold,
            severity=severity,
            event_type="performance_alert",
            **kwargs
        )
    
    def log_http_request(self, method: str, endpoint: str, status_code: int,
                        duration_ms: float, user_id: str = None, ip_address: str = None, **kwargs):
        """Log HTTP request"""
        self.performance_logger.info(
            "http_request",
            method=method,
            endpoint=endpoint,
            status_code=status_code,
            duration_ms=duration_ms,
            user_id=user_id,
            ip_address=ip_address,
            event_type="http_request",
            **kwargs
        )
    
    # Application logging methods
    def log_ml_prediction(self, model_type: str, input_features: dict, prediction: Any,
                         confidence: float, processing_time_ms: float, **kwargs):
        """Log ML model prediction"""
        self.application_logger.info(
            "ml_prediction",
            model_type=model_type,
            input_features=input_features,
            prediction=prediction,
            confidence=confidence,
            processing_time_ms=processing_time_ms,
            event_type="ml_prediction",
            **kwargs
        )
    
    def log_policy_evaluation(self, policy_type: str, input_data: dict, result: str,
                            confidence: float, factors: list, **kwargs):
        """Log policy evaluation"""
        self.application_logger.info(
            "policy_evaluation",
            policy_type=policy_type,
            input_data=input_data,
            result=result,
            confidence=confidence,
            factors=factors,
            event_type="policy_evaluation",
            **kwargs
        )
    
    def log_database_operation(self, operation: str, collection: str, document_id: str = None,
                             duration_ms: float = None, result: str = "success", **kwargs):
        """Log database operation"""
        self.application_logger.debug(
            "database_operation",
            operation=operation,
            collection=collection,
            document_id=document_id,
            duration_ms=duration_ms,
            result=result,
            event_type="database_operation",
            **kwargs
        )
    
    def log_cache_operation(self, operation: str, key: str, hit: bool = None,
                          duration_ms: float = None, **kwargs):
        """Log cache operation"""
        self.application_logger.debug(
            "cache_operation",
            operation=operation,
            key=key,
            hit=hit,
            duration_ms=duration_ms,
            event_type="cache_operation",
            **kwargs
        )
    
    def log_websocket_event(self, event_type: str, connection_id: str, message_type: str,
                          user_id: str = None, data_size: int = None, **kwargs):
        """Log WebSocket event"""
        self.application_logger.info(
            "websocket_event",
            event_type=event_type,
            connection_id=connection_id,
            message_type=message_type,
            user_id=user_id,
            data_size=data_size,
            **kwargs
        )
    
    # Error logging methods
    def log_error(self, error_type: str, error_message: str, stack_trace: str = None,
                 user_id: str = None, request_id: str = None, **kwargs):
        """Log application error"""
        self.error_logger.error(
            "application_error",
            error_type=error_type,
            error_message=error_message,
            stack_trace=stack_trace,
            user_id=user_id,
            request_id=request_id,
            event_type="error",
            **kwargs
        )
    
    def log_critical_error(self, error_type: str, error_message: str, stack_trace: str = None,
                          impact: str = None, **kwargs):
        """Log critical error"""
        self.error_logger.critical(
            "critical_error",
            error_type=error_type,
            error_message=error_message,
            stack_trace=stack_trace,
            impact=impact,
            event_type="critical_error",
            **kwargs
        )
    
    # Audit logging methods
    def log_audit_event(self, event_type: str, user_id: str, resource: str, action: str,
                       result: str, ip_address: str, user_agent: str = None, **kwargs):
        """Log audit event"""
        self.audit_logger.info(
            "audit_event",
            event_type=event_type,
            user_id=user_id,
            resource=resource,
            action=action,
            result=result,
            ip_address=ip_address,
            user_agent=user_agent,
            **kwargs
        )
    
    # Utility methods
    def set_correlation_id(self, correlation_id: str):
        """Set correlation ID for request tracing"""
        # This would be implemented with context variables in a real application
        pass
    
    def get_log_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get log summary for dashboard"""
        try:
            # This would query actual log data from Elasticsearch
            # For now, return cached summary if available
            cached_summary = cache_service.get_device_profile(f"log_summary:{hours}h")
            if cached_summary:
                return cached_summary
            
            # Generate summary (placeholder implementation)
            summary = {
                'timestamp': datetime.utcnow().isoformat(),
                'time_range_hours': hours,
                'security_events': {
                    'authentication_attempts': 0,
                    'security_violations': 0,
                    'break_glass_access': 0,
                    'high_risk_sessions': 0
                },
                'performance_events': {
                    'performance_alerts': 0,
                    'slow_requests': 0,
                    'error_rate': 0.0
                },
                'application_events': {
                    'ml_predictions': 0,
                    'policy_evaluations': 0,
                    'database_operations': 0
                },
                'error_events': {
                    'application_errors': 0,
                    'critical_errors': 0
                }
            }
            
            # Cache for 5 minutes
            cache_service.cache_device_profile(f"log_summary:{hours}h", summary, 300)
            return summary
            
        except Exception as e:
            return {
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def search_logs(self, query: str, time_range: str = "24h", 
                   log_level: str = None, event_type: str = None) -> List[Dict[str, Any]]:
        """Search logs (placeholder for Elasticsearch integration)"""
        try:
            # This would implement actual Elasticsearch queries
            # For now, return empty results
            return []
            
        except Exception as e:
            self.log_error("log_search_error", str(e))
            return []

# Global logging service instance
logging_service = StructuredLoggingService()