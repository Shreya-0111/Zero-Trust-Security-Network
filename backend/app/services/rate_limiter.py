"""
Rate Limiting Service for API Security
Implements rate limiting with burst allowances and API usage tracking
"""

import time
import json
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta
from flask import current_app, request, g
from functools import wraps
from app.services.audit_logger import audit_logger
from app.utils.error_handler import AppError


class RateLimiter:
    """Rate limiting service with Redis backend"""
    
    def __init__(self):
        self.default_limits = {
            'requests_per_hour': 1000,
            'burst_allowance': 50,  # Additional requests allowed in burst
            'burst_window': 60,     # Burst window in seconds
            'emergency_multiplier': 2.0  # Emergency situations get 2x limits
        }
    
    def _get_redis_client(self):
        """Get Redis client from app config"""
        redis_client = current_app.config.get('REDIS_CLIENT')
        if not redis_client:
            raise AppError('REDIS_UNAVAILABLE', 'Rate limiting service unavailable', 503)
        return redis_client
    
    def _get_client_key(self, client_id: str, endpoint: str = None) -> str:
        """Generate Redis key for client rate limiting"""
        base_key = f"rate_limit:{client_id}"
        if endpoint:
            base_key += f":{endpoint}"
        return base_key
    
    def _get_burst_key(self, client_id: str) -> str:
        """Generate Redis key for burst tracking"""
        return f"rate_limit_burst:{client_id}"
    
    def _is_emergency_situation(self) -> bool:
        """Check if current request is during emergency situation"""
        # Check for active break-glass sessions or system alerts
        redis_client = self._get_redis_client()
        
        # Check for active emergency sessions
        emergency_keys = redis_client.keys("break_glass_session:*")
        if emergency_keys:
            return True
        
        # Check for system-wide emergency flag
        emergency_flag = redis_client.get("system_emergency_mode")
        if emergency_flag:
            return True
        
        return False
    
    def check_rate_limit(self, client_id: str, endpoint: str = None, 
                        custom_limits: Dict = None) -> Tuple[bool, Dict]:
        """
        Check if request is within rate limits
        
        Returns:
            Tuple of (allowed: bool, limit_info: Dict)
        """
        redis_client = self._get_redis_client()
        
        # Use custom limits or defaults
        limits = custom_limits or self.default_limits.copy()
        
        # Apply emergency multiplier if needed
        if self._is_emergency_situation():
            limits['requests_per_hour'] = int(limits['requests_per_hour'] * limits['emergency_multiplier'])
            limits['burst_allowance'] = int(limits['burst_allowance'] * limits['emergency_multiplier'])
        
        # Generate keys
        rate_key = self._get_client_key(client_id, endpoint)
        burst_key = self._get_burst_key(client_id)
        
        current_time = int(time.time())
        hour_start = current_time - (current_time % 3600)  # Start of current hour
        
        # Check hourly limit
        hourly_key = f"{rate_key}:{hour_start}"
        current_count = redis_client.get(hourly_key)
        current_count = int(current_count) if current_count else 0
        
        # Check burst limit
        burst_data = redis_client.get(burst_key)
        if burst_data:
            try:
                burst_info = json.loads(burst_data)
                burst_count = burst_info.get('count', 0)
                burst_start = burst_info.get('start_time', current_time)
                
                # Reset burst if window expired
                if current_time - burst_start > limits['burst_window']:
                    burst_count = 0
                    burst_start = current_time
            except (json.JSONDecodeError, KeyError):
                burst_count = 0
                burst_start = current_time
        else:
            burst_count = 0
            burst_start = current_time
        
        # Calculate available limits
        hourly_remaining = max(0, limits['requests_per_hour'] - current_count)
        burst_remaining = max(0, limits['burst_allowance'] - burst_count)
        
        # Check if request is allowed
        allowed = False
        if hourly_remaining > 0:
            allowed = True
        elif burst_remaining > 0:
            allowed = True
        
        # Prepare limit info
        limit_info = {
            'requests_per_hour': limits['requests_per_hour'],
            'hourly_remaining': hourly_remaining,
            'burst_allowance': limits['burst_allowance'],
            'burst_remaining': burst_remaining,
            'reset_time': hour_start + 3600,  # Next hour
            'burst_reset_time': burst_start + limits['burst_window'],
            'emergency_mode': self._is_emergency_situation()
        }
        
        if allowed:
            # Increment counters
            if hourly_remaining > 0:
                # Use hourly allowance
                redis_client.incr(hourly_key)
                redis_client.expire(hourly_key, 3600)  # Expire at end of hour
            else:
                # Use burst allowance
                burst_count += 1
                burst_data = {
                    'count': burst_count,
                    'start_time': burst_start
                }
                redis_client.setex(burst_key, limits['burst_window'], json.dumps(burst_data))
        
        return allowed, limit_info
    
    def log_api_usage(self, client_id: str, endpoint: str, method: str, 
                     status_code: int, response_time: float, user_id: str = None):
        """Log API usage for audit and analytics"""
        redis_client = self._get_redis_client()
        
        # Create usage log entry
        usage_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'client_id': client_id,
            'user_id': user_id,
            'endpoint': endpoint,
            'method': method,
            'status_code': status_code,
            'response_time': response_time,
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'request_size': request.content_length or 0
        }
        
        # Store in Redis list (keep last 10000 entries per client)
        usage_key = f"api_usage:{client_id}"
        redis_client.lpush(usage_key, json.dumps(usage_entry))
        redis_client.ltrim(usage_key, 0, 9999)  # Keep only last 10000 entries
        redis_client.expire(usage_key, 30 * 24 * 3600)  # 30 days retention
        
        # Log to audit system
        audit_logger.log_event(
            event_type='api_usage',
            user_id=user_id,
            action=f'{method} {endpoint}',
            resource=f'api:{endpoint}',
            result='success' if 200 <= status_code < 400 else 'failure',
            details={
                'client_id': client_id,
                'status_code': status_code,
                'response_time': response_time,
                'request_size': usage_entry['request_size']
            },
            severity='low'
        )
    
    def get_usage_stats(self, client_id: str, hours: int = 24) -> Dict:
        """Get API usage statistics for a client"""
        redis_client = self._get_redis_client()
        
        usage_key = f"api_usage:{client_id}"
        usage_entries = redis_client.lrange(usage_key, 0, -1)
        
        if not usage_entries:
            return {
                'total_requests': 0,
                'requests_by_hour': {},
                'requests_by_endpoint': {},
                'average_response_time': 0,
                'error_rate': 0
            }
        
        # Parse entries and filter by time window
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        filtered_entries = []
        
        for entry_json in usage_entries:
            try:
                entry = json.loads(entry_json)
                entry_time = datetime.fromisoformat(entry['timestamp'])
                if entry_time >= cutoff_time:
                    filtered_entries.append(entry)
            except (json.JSONDecodeError, KeyError, ValueError):
                continue
        
        if not filtered_entries:
            return {
                'total_requests': 0,
                'requests_by_hour': {},
                'requests_by_endpoint': {},
                'average_response_time': 0,
                'error_rate': 0
            }
        
        # Calculate statistics
        total_requests = len(filtered_entries)
        requests_by_hour = {}
        requests_by_endpoint = {}
        total_response_time = 0
        error_count = 0
        
        for entry in filtered_entries:
            # Group by hour
            hour_key = entry['timestamp'][:13]  # YYYY-MM-DDTHH
            requests_by_hour[hour_key] = requests_by_hour.get(hour_key, 0) + 1
            
            # Group by endpoint
            endpoint = entry['endpoint']
            requests_by_endpoint[endpoint] = requests_by_endpoint.get(endpoint, 0) + 1
            
            # Response time
            total_response_time += entry['response_time']
            
            # Error count
            if entry['status_code'] >= 400:
                error_count += 1
        
        return {
            'total_requests': total_requests,
            'requests_by_hour': requests_by_hour,
            'requests_by_endpoint': requests_by_endpoint,
            'average_response_time': total_response_time / total_requests,
            'error_rate': (error_count / total_requests) * 100
        }
    
    def set_emergency_mode(self, enabled: bool, duration_minutes: int = 60):
        """Enable/disable emergency mode for increased rate limits"""
        redis_client = self._get_redis_client()
        
        if enabled:
            redis_client.setex("system_emergency_mode", duration_minutes * 60, "true")
            audit_logger.log_event(
                event_type='emergency_mode_enabled',
                user_id=getattr(request, 'user_id', None),
                action='enable_emergency_mode',
                resource='system',
                result='success',
                details={'duration_minutes': duration_minutes},
                severity='high'
            )
        else:
            redis_client.delete("system_emergency_mode")
            audit_logger.log_event(
                event_type='emergency_mode_disabled',
                user_id=getattr(request, 'user_id', None),
                action='disable_emergency_mode',
                resource='system',
                result='success',
                details={},
                severity='medium'
            )


# Global rate limiter instance
rate_limiter = RateLimiter()


def rate_limit(requests_per_hour: int = None, burst_allowance: int = None, 
               endpoint_specific: bool = True):
    """
    Decorator for rate limiting API endpoints
    
    Args:
        requests_per_hour: Custom hourly limit (uses default if None)
        burst_allowance: Custom burst limit (uses default if None)
        endpoint_specific: Whether to apply limits per endpoint or globally
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get client ID from OAuth token or API key
            client_id = getattr(request, 'client_id', None)
            if not client_id:
                # Try to get from API key header
                api_key = request.headers.get('X-API-Key')
                if api_key:
                    client_id = f"api_key:{api_key}"
                else:
                    client_id = f"ip:{request.remote_addr}"
            
            # Determine endpoint for rate limiting
            endpoint = f"{request.method}:{request.endpoint}" if endpoint_specific else "global"
            
            # Custom limits
            custom_limits = {}
            if requests_per_hour is not None:
                custom_limits['requests_per_hour'] = requests_per_hour
            if burst_allowance is not None:
                custom_limits['burst_allowance'] = burst_allowance
            
            # Check rate limit
            start_time = time.time()
            allowed, limit_info = rate_limiter.check_rate_limit(
                client_id, endpoint, custom_limits
            )
            
            if not allowed:
                # Log rate limit exceeded
                audit_logger.log_event(
                    event_type='rate_limit_exceeded',
                    user_id=getattr(request, 'user_id', None),
                    action='rate_limit_check',
                    resource=endpoint,
                    result='failure',
                    details={
                        'client_id': client_id,
                        'limit_info': limit_info
                    },
                    severity='medium'
                )
                
                raise AppError(
                    'RATE_LIMIT_EXCEEDED',
                    'Rate limit exceeded. Please try again later.',
                    429,
                    details=limit_info
                )
            
            # Execute the function
            try:
                response = f(*args, **kwargs)
                status_code = 200
                if isinstance(response, tuple):
                    status_code = response[1] if len(response) > 1 else 200
                
                return response
            except Exception as e:
                status_code = getattr(e, 'status_code', 500)
                raise
            finally:
                # Log API usage
                response_time = (time.time() - start_time) * 1000  # Convert to milliseconds
                rate_limiter.log_api_usage(
                    client_id=client_id,
                    endpoint=endpoint,
                    method=request.method,
                    status_code=status_code,
                    response_time=response_time,
                    user_id=getattr(request, 'user_id', None)
                )
        
        return decorated_function
    return decorator


def get_rate_limit_headers(limit_info: Dict) -> Dict[str, str]:
    """Generate rate limit headers for API responses"""
    return {
        'X-RateLimit-Limit': str(limit_info['requests_per_hour']),
        'X-RateLimit-Remaining': str(limit_info['hourly_remaining']),
        'X-RateLimit-Reset': str(limit_info['reset_time']),
        'X-RateLimit-Burst-Limit': str(limit_info['burst_allowance']),
        'X-RateLimit-Burst-Remaining': str(limit_info['burst_remaining']),
        'X-RateLimit-Emergency-Mode': str(limit_info['emergency_mode']).lower()
    }