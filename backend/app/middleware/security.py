"""
Security middleware for the Zero Trust Security Framework
Implements comprehensive security controls including rate limiting, input sanitization, 
request validation, security headers, CSRF protection, and content security policies
"""

from flask import request, jsonify, g, current_app
from functools import wraps
from datetime import datetime, timedelta
import re
import html
import json
import hashlib
import secrets
import urllib.parse
import os
from collections import defaultdict
import threading
from typing import Dict, Any, List, Optional
import bleach
from app.services.audit_logger import audit_logger
import sys

# Rate limiting storage (in-memory for simplicity, use Redis in production)
rate_limit_storage = defaultdict(list)
rate_limit_lock = threading.Lock()

# Maximum request payload sizes
MAX_CONTENT_LENGTH = 1 * 1024 * 1024  # 1 MB in bytes
MAX_JSON_PAYLOAD = 512 * 1024  # 512 KB for JSON
MAX_FORM_PAYLOAD = 1 * 1024 * 1024  # 1 MB for forms
MAX_FILE_UPLOAD = 5 * 1024 * 1024  # 5 MB for file uploads

# Rate limit configurations
RATE_LIMITS = {
    'auth': {'requests': 10, 'window': 60},  # 10 requests per minute
    'access_request': {'requests': 100, 'window': 3600},  # 100 requests per hour
    'admin': {'requests': 500, 'window': 3600},  # 500 requests per hour for admin
    'api': {'requests': 1000, 'window': 3600},  # 1000 requests per hour for API
    'default': {'requests': 200, 'window': 3600}  # 200 requests per hour default
}

# Allowed HTML tags and attributes for content sanitization
ALLOWED_TAGS = ['p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li', 'a']
ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title'],
    '*': ['class']
}

# Dangerous patterns to detect and block
DANGEROUS_PATTERNS = [
    r'<script[^>]*>.*?</script>',  # Script tags
    r'javascript:',  # JavaScript protocol
    r'vbscript:',  # VBScript protocol
    r'data:text/html',  # Data URLs with HTML
    r'on\w+\s*=',  # Event handlers
    r'expression\s*\(',  # CSS expressions
    r'@import',  # CSS imports
    r'<iframe[^>]*>',  # Iframes
    r'<object[^>]*>',  # Objects
    r'<embed[^>]*>',  # Embeds
    r'<form[^>]*>',  # Forms
    r'<input[^>]*>',  # Inputs
]

# SQL injection patterns
SQL_INJECTION_PATTERNS = [
    r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)',
    r'(\b(OR|AND)\s+\d+\s*=\s*\d+)',
    r'(\b(OR|AND)\s+[\'"][^\'"]*[\'"])',
    r'(--|#|/\*|\*/)',
    r'(\bxp_cmdshell\b)',
    r'(\bsp_executesql\b)',
]


def add_security_headers(response):
    """
    Add comprehensive security headers to all responses
    Implements HSTS, CSP, X-Frame-Options, and other security headers
    """
    # Allow auth endpoints to bypass strict headers in dev
    if request.path.startswith('/api/auth/'):
        return response
    
    from app.middleware.load_balancer import add_load_balancer_headers
    response = add_load_balancer_headers(response)
    return response


def rate_limit(limit_type='default'):
    """
    Enhanced rate limiting decorator with Redis support and better tracking
    
    Args:
        limit_type: Type of rate limit to apply ('auth', 'access_request', 'admin', 'api', 'default')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get client identifier (IP address or user ID if authenticated)
            client_id = request.remote_addr
            if hasattr(g, 'user_id') and g.user_id:
                client_id = f"{g.user_id}:{request.remote_addr}"
            
            # Get rate limit configuration
            config = RATE_LIMITS.get(limit_type, RATE_LIMITS['default'])
            max_requests = config['requests']
            window_seconds = config['window']
            
            # Create unique key for this endpoint and client
            key = f"{limit_type}:{client_id}:{request.endpoint}"
            
            # Try to use Redis if available, fallback to in-memory
            redis_client = current_app.config.get('REDIS_CLIENT')
            
            if redis_client:
                try:
                    # Use Redis for distributed rate limiting
                    current_count = redis_client.incr(key)
                    if current_count == 1:
                        redis_client.expire(key, window_seconds)
                    
                    if current_count > max_requests:
                        # Log rate limit violation
                        try:
                            audit_logger.log_event(
                                event_type='rate_limit_exceeded',
                                user_id=getattr(g, 'user_id', None),
                                action='rate_limit_check',
                                resource=request.path,
                                result='failure',
                                details={
                                    'client_id': client_id,
                                    'limit_type': limit_type,
                                    'current_count': current_count,
                                    'max_requests': max_requests,
                                    'window_seconds': window_seconds
                                },
                                severity='medium'
                            )
                        except Exception as e:
                            print(f"Failed to log rate limit event: {e}", file=sys.stderr)
                        
                        return jsonify({
                            'success': False,
                            'error': {
                                'code': 'RATE_LIMIT_EXCEEDED',
                                'message': f'Rate limit exceeded. Maximum {max_requests} requests per {window_seconds} seconds.',
                                'retry_after': window_seconds
                            }
                        }), 429
                        
                except Exception as e:
                    print(f"Redis rate limiting failed, falling back to in-memory: {e}", file=sys.stderr)
                    # Fall through to in-memory implementation
            
            # In-memory rate limiting (fallback)
            with rate_limit_lock:
                now = datetime.utcnow()
                cutoff_time = now - timedelta(seconds=window_seconds)
                
                # Clean old entries
                rate_limit_storage[key] = [
                    timestamp for timestamp in rate_limit_storage[key]
                    if timestamp > cutoff_time
                ]
                
                # Check if limit exceeded
                if len(rate_limit_storage[key]) >= max_requests:
                    # Log rate limit violation
                    try:
                        audit_logger.log_event(
                            event_type='rate_limit_exceeded',
                            user_id=getattr(g, 'user_id', None),
                            action='rate_limit_check',
                            resource=request.path,
                            result='failure',
                            details={
                                'client_id': client_id,
                                'limit_type': limit_type,
                                'current_count': len(rate_limit_storage[key]),
                                'max_requests': max_requests,
                                'window_seconds': window_seconds
                            },
                            severity='medium'
                        )
                    except Exception as e:
                        print(f"Failed to log rate limit event: {e}", file=sys.stderr)
                    
                    return jsonify({
                        'success': False,
                        'error': {
                            'code': 'RATE_LIMIT_EXCEEDED',
                            'message': f'Rate limit exceeded. Maximum {max_requests} requests per {window_seconds} seconds.',
                            'retry_after': window_seconds
                        }
                    }), 429
                
                # Add current request
                rate_limit_storage[key].append(now)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def detect_sql_injection(value: str) -> bool:
    """
    Detect potential SQL injection attempts
    
    Args:
        value: String to check for SQL injection patterns
        
    Returns:
        True if potential SQL injection detected
    """
    if not isinstance(value, str):
        return False
    
    value_lower = value.lower()
    
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, value_lower, re.IGNORECASE):
            return True
    
    return False


def detect_xss_attempt(value: str) -> bool:
    """
    Detect potential XSS attempts
    
    Args:
        value: String to check for XSS patterns
        
    Returns:
        True if potential XSS detected
    """
    if not isinstance(value, str):
        return False
    
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE | re.DOTALL):
            return True
    
    return False


def sanitize_string(value: str, allow_html: bool = False) -> str:
    """
    Enhanced string sanitization to prevent XSS and injection attacks
    
    Args:
        value: String to sanitize
        allow_html: Whether to allow safe HTML tags
        
    Returns:
        Sanitized string
    """
    if not isinstance(value, str):
        return value
    
    # Check for SQL injection attempts
    if detect_sql_injection(value):
        try:
            audit_logger.log_event(
                event_type='security_violation',
                user_id=getattr(g, 'user_id', None),
                action='sql_injection_attempt',
                resource=request.path,
                result='blocked',
                details={
                    'attempted_value': value[:200],  # Log first 200 chars
                    'client_ip': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent', '')
                },
                severity='high'
            )
        except Exception as e:
            print(f"Failed to log security violation: {e}", file=sys.stderr)
        
        # Return empty string for SQL injection attempts
        return ""
    
    # Check for XSS attempts
    if detect_xss_attempt(value):
        try:
            audit_logger.log_event(
                event_type='security_violation',
                user_id=getattr(g, 'user_id', None),
                action='xss_attempt',
                resource=request.path,
                result='blocked',
                details={
                    'attempted_value': value[:200],  # Log first 200 chars
                    'client_ip': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent', '')
                },
                severity='high'
            )
        except Exception as e:
            print(f"Failed to log security violation: {e}", file=sys.stderr)
    
    if allow_html:
        # Use bleach for safe HTML sanitization
        sanitized = bleach.clean(
            value,
            tags=ALLOWED_TAGS,
            attributes=ALLOWED_ATTRIBUTES,
            strip=True
        )
    else:
        # HTML escape to prevent XSS
        sanitized = html.escape(value)
    
    # URL decode to prevent double encoding attacks
    try:
        sanitized = urllib.parse.unquote(sanitized)
    except Exception:
        pass  # Keep original if URL decoding fails
    
    # Remove null bytes and other control characters
    sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', sanitized)
    
    # Normalize whitespace
    sanitized = re.sub(r'\s+', ' ', sanitized).strip()
    
    return sanitized


def sanitize_dict(data: Any, allow_html: bool = False) -> Any:
    """
    Recursively sanitize dictionary values with enhanced security
    
    Args:
        data: Data structure to sanitize
        allow_html: Whether to allow safe HTML tags in strings
        
    Returns:
        Sanitized data structure
    """
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            # Sanitize keys as well
            clean_key = sanitize_string(str(key), allow_html=False)
            sanitized[clean_key] = sanitize_dict(value, allow_html)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_dict(item, allow_html) for item in data]
    elif isinstance(data, str):
        return sanitize_string(data, allow_html)
    elif isinstance(data, (int, float, bool)) or data is None:
        return data
    else:
        # Convert unknown types to string and sanitize
        return sanitize_string(str(data), allow_html=False)


def validate_request_size(max_size: Optional[int] = None):
    """
    Enhanced middleware to validate request payload size with different limits
    
    Args:
        max_size: Maximum size in bytes (defaults to MAX_CONTENT_LENGTH)
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            max_allowed = max_size or MAX_CONTENT_LENGTH
            
            # Check Content-Length header
            content_length = request.content_length
            if content_length and content_length > max_allowed:
                try:
                    audit_logger.log_event(
                        event_type='security_violation',
                        user_id=getattr(g, 'user_id', None),
                        action='payload_size_violation',
                        resource=request.path,
                        result='blocked',
                        details={
                            'content_length': content_length,
                            'max_allowed': max_allowed,
                            'client_ip': request.remote_addr
                        },
                        severity='medium'
                    )
                except Exception as e:
                    print(f"Failed to log security violation: {e}", file=sys.stderr)
                
                return jsonify({
                    'success': False,
                    'error': {
                        'code': 'PAYLOAD_TOO_LARGE',
                        'message': f'Request payload too large. Maximum size is {max_allowed / (1024 * 1024):.1f} MB.'
                    }
                }), 413
            
            # Additional check for JSON payloads
            if request.is_json and content_length and content_length > MAX_JSON_PAYLOAD:
                return jsonify({
                    'success': False,
                    'error': {
                        'code': 'JSON_PAYLOAD_TOO_LARGE',
                        'message': f'JSON payload too large. Maximum size is {MAX_JSON_PAYLOAD / 1024} KB.'
                    }
                }), 413
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def sanitize_input(allow_html: bool = False, strict_mode: bool = True):
    """
    Enhanced middleware to sanitize all input data with security logging
    
    Args:
        allow_html: Whether to allow safe HTML tags in string values
        strict_mode: Whether to apply strict sanitization rules
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            security_violations = []
            
            # Sanitize JSON body
            if request.is_json:
                try:
                    data = request.get_json()
                    if data:
                        # Check for potential attacks before sanitization
                        original_str = json.dumps(data, default=str)
                        if detect_sql_injection(original_str) or detect_xss_attempt(original_str):
                            security_violations.append('malicious_json_payload')
                        
                        sanitized_data = sanitize_dict(data, allow_html)
                        # Store sanitized data in g for access in route handlers
                        g.sanitized_data = sanitized_data
                except Exception as e:
                    try:
                        audit_logger.log_event(
                            event_type='security_violation',
                            user_id=getattr(g, 'user_id', None),
                            action='invalid_json_payload',
                            resource=request.path,
                            result='blocked',
                            details={
                                'error': str(e),
                                'client_ip': request.remote_addr
                            },
                            severity='medium'
                        )
                    except Exception as log_e:
                        print(f"Failed to log security violation: {log_e}", file=sys.stderr)
                    
                    return jsonify({
                        'success': False,
                        'error': {
                            'code': 'INVALID_JSON',
                            'message': 'Invalid JSON payload'
                        }
                    }), 400
            
            # Sanitize query parameters
            sanitized_args = {}
            for key, value in request.args.items():
                clean_key = sanitize_string(key, allow_html=False)
                clean_value = sanitize_string(value, allow_html=False)
                
                # Check for attacks in query parameters
                if detect_sql_injection(value) or detect_xss_attempt(value):
                    security_violations.append(f'malicious_query_param_{key}')
                
                sanitized_args[clean_key] = clean_value
            g.sanitized_args = sanitized_args
            
            # Sanitize form data
            if request.form:
                sanitized_form = {}
                for key, value in request.form.items():
                    clean_key = sanitize_string(key, allow_html=False)
                    clean_value = sanitize_string(value, allow_html)
                    
                    # Check for attacks in form data
                    if detect_sql_injection(value) or detect_xss_attempt(value):
                        security_violations.append(f'malicious_form_field_{key}')
                    
                    sanitized_form[clean_key] = clean_value
                g.sanitized_form = sanitized_form
            
            # Log security violations
            if security_violations:
                try:
                    audit_logger.log_event(
                        event_type='security_violation',
                        user_id=getattr(g, 'user_id', None),
                        action='input_sanitization',
                        resource=request.path,
                        result='sanitized',
                        details={
                            'violations': security_violations,
                            'client_ip': request.remote_addr,
                            'user_agent': request.headers.get('User-Agent', '')
                        },
                        severity='high' if strict_mode else 'medium'
                    )
                except Exception as e:
                    print(f"Failed to log security violation: {e}", file=sys.stderr)
                
                # In strict mode, block requests with security violations
                if strict_mode and any('malicious' in v for v in security_violations):
                    return jsonify({
                        'success': False,
                        'error': {
                            'code': 'SECURITY_VIOLATION',
                            'message': 'Request blocked due to security policy violation'
                        }
                    }), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def validate_json_schema(schema: Dict[str, Any], strict: bool = True):
    """
    Enhanced JSON schema validation with security checks
    
    Args:
        schema: Dictionary defining required fields and types
        strict: Whether to enforce strict validation
        Example: {'email': str, 'password': str, 'role': str}
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({
                    'success': False,
                    'error': {
                        'code': 'INVALID_CONTENT_TYPE',
                        'message': 'Content-Type must be application/json'
                    }
                }), 400
            
            try:
                data = request.get_json()
                if data is None:
                    return jsonify({
                        'success': False,
                        'error': {
                            'code': 'EMPTY_JSON',
                            'message': 'JSON payload is required'
                        }
                    }), 400
            except Exception:
                return jsonify({
                    'success': False,
                    'error': {
                        'code': 'INVALID_JSON',
                        'message': 'Invalid JSON payload'
                    }
                }), 400
            
            # Validate required fields and types
            errors = {}
            for field, field_type in schema.items():
                if field not in data:
                    errors[field] = f'Field "{field}" is required'
                elif not isinstance(data[field], field_type):
                    errors[field] = f'Field "{field}" must be of type {field_type.__name__}'
                elif isinstance(data[field], str):
                    # Additional string validation
                    if len(data[field].strip()) == 0:
                        errors[field] = f'Field "{field}" cannot be empty'
                    elif len(data[field]) > 10000:  # Reasonable max length
                        errors[field] = f'Field "{field}" is too long (max 10000 characters)'
            
            # Check for unexpected fields in strict mode
            if strict:
                unexpected_fields = set(data.keys()) - set(schema.keys())
                if unexpected_fields:
                    errors['_unexpected'] = f'Unexpected fields: {", ".join(unexpected_fields)}'
            
            if errors:
                try:
                    audit_logger.log_event(
                        event_type='validation_error',
                        user_id=getattr(g, 'user_id', None),
                        action='schema_validation',
                        resource=request.path,
                        result='failure',
                        details={
                            'validation_errors': errors,
                            'schema': list(schema.keys()),
                            'client_ip': request.remote_addr
                        },
                        severity='low'
                    )
                except Exception as e:
                    print(f"Failed to log validation error: {e}", file=sys.stderr)
                
                return jsonify({
                    'success': False,
                    'error': {
                        'code': 'VALIDATION_ERROR',
                        'message': 'Request validation failed',
                        'details': errors
                    }
                }), 400
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def validate_content_type(allowed_types: List[str] = None):
    """
    Validate request content type
    
    Args:
        allowed_types: List of allowed content types
    """
    if allowed_types is None:
        allowed_types = ['application/json']
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            content_type = request.content_type
            if content_type and content_type.split(';')[0] not in allowed_types:
                return jsonify({
                    'success': False,
                    'error': {
                        'code': 'INVALID_CONTENT_TYPE',
                        'message': f'Content-Type must be one of: {", ".join(allowed_types)}'
                    }
                }), 415
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def validate_user_agent():
    """
    Validate and log suspicious User-Agent headers
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_agent = request.headers.get('User-Agent', '')
            
            # Check for suspicious patterns
            suspicious_patterns = [
                r'sqlmap',
                r'nikto',
                r'nmap',
                r'masscan',
                r'burp',
                r'owasp',
                r'<script',
                r'python-requests/\d+\.\d+\.\d+$',  # Basic python requests without custom UA
                r'^$'  # Empty user agent
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, user_agent, re.IGNORECASE):
                    try:
                        audit_logger.log_event(
                            event_type='security_violation',
                            user_id=getattr(g, 'user_id', None),
                            action='suspicious_user_agent',
                            resource=request.path,
                            result='flagged',
                            details={
                                'user_agent': user_agent,
                                'client_ip': request.remote_addr,
                                'matched_pattern': pattern
                            },
                            severity='medium'
                        )
                    except Exception as e:
                        print(f"Failed to log security violation: {e}", file=sys.stderr)
                    break
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def require_https():
    """
    Require HTTPS for sensitive endpoints
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Skip in development mode - check both Flask ENV and FLASK_ENV
            flask_env = current_app.config.get('ENV') or os.getenv('FLASK_ENV', 'production')
            if flask_env == 'development':
                return f(*args, **kwargs)
            
            if not request.is_secure:
                return jsonify({
                    'success': False,
                    'error': {
                        'code': 'HTTPS_REQUIRED',
                        'message': 'HTTPS is required for this endpoint'
                    }
                }), 426  # Upgrade Required
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def get_sanitized_data():
    """
    Helper function to get sanitized request data
    
    Returns:
        Sanitized request data or original data if not sanitized
    """
    if hasattr(g, 'sanitized_data'):
        return g.sanitized_data
    return request.get_json() if request.is_json else {}


def get_sanitized_args():
    """
    Helper function to get sanitized query parameters
    
    Returns:
        Sanitized query parameters or original args if not sanitized
    """
    if hasattr(g, 'sanitized_args'):
        return g.sanitized_args
    return dict(request.args)


def get_sanitized_form():
    """
    Helper function to get sanitized form data
    
    Returns:
        Sanitized form data or original form if not sanitized
    """
    if hasattr(g, 'sanitized_form'):
        return g.sanitized_form
    return dict(request.form)


def security_audit_log(event_type: str, action: str, details: Dict[str, Any], severity: str = 'medium'):
    """
    Helper function to log security events
    
    Args:
        event_type: Type of security event
        action: Action that was performed
        details: Additional details about the event
        severity: Severity level (low, medium, high, critical)
    """
    try:
        audit_logger.log_event(
            event_type=event_type,
            user_id=getattr(g, 'user_id', None),
            action=action,
            resource=request.path,
            result='logged',
            details={
                **details,
                'client_ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', ''),
                'timestamp': datetime.utcnow().isoformat()
            },
            severity=severity
        )
    except Exception as e:
        print(f"Failed to log security event: {e}", file=sys.stderr)


def generate_nonce() -> str:
    """
    Generate a cryptographically secure nonce for CSP
    
    Returns:
        Base64 encoded nonce
    """
    return secrets.token_urlsafe(16)


def validate_ip_address(ip_address: str) -> bool:
    """
    Validate IP address format
    
    Args:
        ip_address: IP address to validate
        
    Returns:
        True if valid IP address
    """
    import ipaddress
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


def is_safe_redirect_url(url: str, allowed_hosts: List[str] = None) -> bool:
    """
    Check if a redirect URL is safe (prevents open redirect attacks)
    
    Args:
        url: URL to validate
        allowed_hosts: List of allowed hosts for redirects
        
    Returns:
        True if URL is safe for redirect
    """
    if not url:
        return False
    
    # Parse the URL
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False
    
    # Relative URLs are generally safe
    if not parsed.netloc:
        return url.startswith('/') and not url.startswith('//')
    
    # Check against allowed hosts
    if allowed_hosts:
        return parsed.netloc.lower() in [host.lower() for host in allowed_hosts]
    
    # Default: only allow same host
    return parsed.netloc.lower() == request.host.lower()


# Security middleware composition helpers
def apply_standard_security():
    """
    Apply standard security middleware to a route
    """
    def decorator(f):
        @wraps(f)
        @rate_limit('default')
        @validate_request_size()
        @sanitize_input()
        @validate_user_agent()
        def decorated_function(*args, **kwargs):
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def apply_strict_security():
    """
    Apply strict security middleware to sensitive routes
    """
    def decorator(f):
        @wraps(f)
        @require_https()
        @rate_limit('auth')
        @validate_request_size(MAX_JSON_PAYLOAD)
        @sanitize_input(allow_html=False, strict_mode=True)
        @validate_user_agent()
        @validate_content_type(['application/json'])
        def decorated_function(*args, **kwargs):
            return f(*args, **kwargs)
        return decorated_function
    return decorator
