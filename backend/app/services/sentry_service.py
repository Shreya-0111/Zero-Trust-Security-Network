"""
Sentry Integration Service for Error Tracking
Provides comprehensive error tracking and performance monitoring
"""

import logging
import os
from typing import Dict, Any, Optional, List
from datetime import datetime
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.redis import RedisIntegration
from sentry_sdk.integrations.celery import CeleryIntegration
from sentry_sdk.integrations.logging import LoggingIntegration
import traceback

logger = logging.getLogger(__name__)

class SentryService:
    """Service for Sentry error tracking and performance monitoring"""
    
    def __init__(self):
        self.enabled = os.getenv('SENTRY_ENABLED', 'false').lower() == 'true'
        self.dsn = os.getenv('SENTRY_DSN')
        self.environment = os.getenv('ENVIRONMENT', 'development')
        self.release = os.getenv('APP_VERSION', '1.0.0')
        
        if self.enabled and self.dsn:
            self._initialize_sentry()
        else:
            logger.warning("Sentry not configured - error tracking disabled")
    
    def _initialize_sentry(self):
        """Initialize Sentry SDK with integrations"""
        try:
            # Configure logging integration
            sentry_logging = LoggingIntegration(
                level=logging.INFO,        # Capture info and above as breadcrumbs
                event_level=logging.ERROR  # Send errors as events
            )
            
            # Initialize Sentry
            sentry_sdk.init(
                dsn=self.dsn,
                environment=self.environment,
                release=self.release,
                integrations=[
                    FlaskIntegration(
                        transaction_style='endpoint'
                    ),
                    RedisIntegration(),
                    CeleryIntegration(),
                    sentry_logging
                ],
                # Performance monitoring
                traces_sample_rate=0.1,  # 10% of transactions
                profiles_sample_rate=0.1,  # 10% of transactions for profiling
                
                # Error filtering
                before_send=self._before_send_filter,
                
                # Additional options
                attach_stacktrace=True,
                send_default_pii=False,  # Don't send PII for privacy
                max_breadcrumbs=50,
                
                # Custom tags
                default_integrations=True
            )
            
            # Set global tags
            sentry_sdk.set_tag("service", "zero-trust-security-framework")
            sentry_sdk.set_tag("component", "backend")
            
            logger.info(f"Sentry initialized for environment: {self.environment}")
            
        except Exception as e:
            logger.error(f"Failed to initialize Sentry: {e}")
            self.enabled = False
    
    def _before_send_filter(self, event, hint):
        """Filter events before sending to Sentry"""
        try:
            # Don't send certain types of errors
            if 'exc_info' in hint:
                exc_type, exc_value, tb = hint['exc_info']
                
                # Filter out common non-critical errors
                if exc_type.__name__ in ['KeyboardInterrupt', 'SystemExit']:
                    return None
                
                # Filter out specific error messages
                error_message = str(exc_value).lower()
                if any(phrase in error_message for phrase in [
                    'connection reset by peer',
                    'broken pipe',
                    'client disconnected'
                ]):
                    return None
            
            # Add custom context
            event['tags'] = event.get('tags', {})
            event['tags']['service'] = 'zero-trust-security-framework'
            
            return event
            
        except Exception as e:
            logger.error(f"Error in Sentry before_send filter: {e}")
            return event
    
    def capture_exception(self, exception: Exception, **kwargs):
        """Capture exception with additional context"""
        if not self.enabled:
            return
        
        try:
            with sentry_sdk.push_scope() as scope:
                # Add custom context
                for key, value in kwargs.items():
                    scope.set_context(key, value)
                
                # Capture the exception
                sentry_sdk.capture_exception(exception)
                
        except Exception as e:
            logger.error(f"Failed to capture exception in Sentry: {e}")
    
    def capture_message(self, message: str, level: str = 'info', **kwargs):
        """Capture custom message"""
        if not self.enabled:
            return
        
        try:
            with sentry_sdk.push_scope() as scope:
                # Add custom context
                for key, value in kwargs.items():
                    scope.set_context(key, value)
                
                # Map log levels
                sentry_level = {
                    'debug': 'debug',
                    'info': 'info',
                    'warning': 'warning',
                    'error': 'error',
                    'critical': 'fatal'
                }.get(level.lower(), 'info')
                
                sentry_sdk.capture_message(message, level=sentry_level)
                
        except Exception as e:
            logger.error(f"Failed to capture message in Sentry: {e}")
    
    def set_user_context(self, user_id: str, email: str = None, role: str = None, **kwargs):
        """Set user context for error tracking"""
        if not self.enabled:
            return
        
        try:
            user_data = {
                'id': user_id,
                'email': email,
                'role': role,
                **kwargs
            }
            
            # Remove None values
            user_data = {k: v for k, v in user_data.items() if v is not None}
            
            sentry_sdk.set_user(user_data)
            
        except Exception as e:
            logger.error(f"Failed to set user context in Sentry: {e}")
    
    def set_request_context(self, method: str, url: str, headers: Dict[str, str] = None,
                          ip_address: str = None, **kwargs):
        """Set request context for error tracking"""
        if not self.enabled:
            return
        
        try:
            request_data = {
                'method': method,
                'url': url,
                'headers': headers or {},
                'env': {
                    'REMOTE_ADDR': ip_address
                } if ip_address else {},
                **kwargs
            }
            
            sentry_sdk.set_context("request", request_data)
            
        except Exception as e:
            logger.error(f"Failed to set request context in Sentry: {e}")
    
    def add_breadcrumb(self, message: str, category: str = 'custom', level: str = 'info',
                      data: Dict[str, Any] = None):
        """Add breadcrumb for debugging context"""
        if not self.enabled:
            return
        
        try:
            sentry_sdk.add_breadcrumb(
                message=message,
                category=category,
                level=level,
                data=data or {}
            )
            
        except Exception as e:
            logger.error(f"Failed to add breadcrumb in Sentry: {e}")
    
    def start_transaction(self, name: str, op: str = 'http.server') -> Optional[Any]:
        """Start performance transaction"""
        if not self.enabled:
            return None
        
        try:
            return sentry_sdk.start_transaction(name=name, op=op)
            
        except Exception as e:
            logger.error(f"Failed to start transaction in Sentry: {e}")
            return None
    
    def set_tag(self, key: str, value: str):
        """Set custom tag"""
        if not self.enabled:
            return
        
        try:
            sentry_sdk.set_tag(key, value)
            
        except Exception as e:
            logger.error(f"Failed to set tag in Sentry: {e}")
    
    def set_context(self, key: str, context: Dict[str, Any]):
        """Set custom context"""
        if not self.enabled:
            return
        
        try:
            sentry_sdk.set_context(key, context)
            
        except Exception as e:
            logger.error(f"Failed to set context in Sentry: {e}")
    
    # Security-specific error tracking methods
    def capture_security_violation(self, violation_type: str, user_id: str, 
                                 ip_address: str, details: Dict[str, Any]):
        """Capture security violation"""
        if not self.enabled:
            return
        
        try:
            with sentry_sdk.push_scope() as scope:
                scope.set_tag("event_type", "security_violation")
                scope.set_tag("violation_type", violation_type)
                scope.set_user({"id": user_id})
                scope.set_context("security", {
                    "violation_type": violation_type,
                    "ip_address": ip_address,
                    "details": details
                })
                
                sentry_sdk.capture_message(
                    f"Security violation: {violation_type}",
                    level='warning'
                )
                
        except Exception as e:
            logger.error(f"Failed to capture security violation: {e}")
    
    def capture_authentication_failure(self, user_id: str, method: str, 
                                     ip_address: str, reason: str):
        """Capture authentication failure"""
        if not self.enabled:
            return
        
        try:
            with sentry_sdk.push_scope() as scope:
                scope.set_tag("event_type", "authentication_failure")
                scope.set_tag("auth_method", method)
                scope.set_user({"id": user_id})
                scope.set_context("authentication", {
                    "method": method,
                    "ip_address": ip_address,
                    "reason": reason
                })
                
                sentry_sdk.capture_message(
                    f"Authentication failure: {reason}",
                    level='warning'
                )
                
        except Exception as e:
            logger.error(f"Failed to capture authentication failure: {e}")
    
    def capture_break_glass_access(self, user_id: str, request_id: str, 
                                 urgency: str, justification: str):
        """Capture break-glass access event"""
        if not self.enabled:
            return
        
        try:
            with sentry_sdk.push_scope() as scope:
                scope.set_tag("event_type", "break_glass_access")
                scope.set_tag("urgency", urgency)
                scope.set_user({"id": user_id})
                scope.set_context("break_glass", {
                    "request_id": request_id,
                    "urgency": urgency,
                    "justification": justification[:200]  # Truncate for privacy
                })
                
                sentry_sdk.capture_message(
                    f"Break-glass access requested: {urgency}",
                    level='error'
                )
                
        except Exception as e:
            logger.error(f"Failed to capture break-glass access: {e}")
    
    def capture_performance_issue(self, metric_name: str, current_value: float,
                                threshold: float, severity: str):
        """Capture performance issue"""
        if not self.enabled:
            return
        
        try:
            with sentry_sdk.push_scope() as scope:
                scope.set_tag("event_type", "performance_issue")
                scope.set_tag("metric_name", metric_name)
                scope.set_tag("severity", severity)
                scope.set_context("performance", {
                    "metric_name": metric_name,
                    "current_value": current_value,
                    "threshold": threshold,
                    "severity": severity
                })
                
                level = 'error' if severity in ['critical', 'high'] else 'warning'
                sentry_sdk.capture_message(
                    f"Performance issue: {metric_name} = {current_value} (threshold: {threshold})",
                    level=level
                )
                
        except Exception as e:
            logger.error(f"Failed to capture performance issue: {e}")
    
    def get_error_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get error summary (placeholder - would integrate with Sentry API)"""
        try:
            # This would use Sentry's API to get actual error statistics
            # For now, return a placeholder summary
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'time_range_hours': hours,
                'total_errors': 0,
                'error_rate': 0.0,
                'top_errors': [],
                'performance_issues': 0,
                'security_violations': 0,
                'sentry_enabled': self.enabled
            }
            
        except Exception as e:
            logger.error(f"Failed to get error summary: {e}")
            return {
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat(),
                'sentry_enabled': self.enabled
            }

# Decorator for automatic error tracking
def track_errors(sentry_service):
    """Decorator to automatically track errors"""
    def decorator(f):
        def wrapper(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except Exception as e:
                sentry_service.capture_exception(e, function=f.__name__)
                raise
        return wrapper
    return decorator

# Global Sentry service instance
sentry_service = SentryService()