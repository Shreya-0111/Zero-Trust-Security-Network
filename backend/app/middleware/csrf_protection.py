"""
Enhanced CSRF Protection Middleware
Validates CSRF tokens on state-changing requests with improved security
"""

from flask import request, jsonify, g, current_app
from functools import wraps
import secrets
import hashlib
import hmac
import time
from typing import Optional
from app.services.auth_service import auth_service
from app.services.audit_logger import audit_logger
import sys


class CSRFProtection:
    """Enhanced CSRF protection with token generation and validation"""
    
    def __init__(self):
        self.secret_key = None
        self.token_lifetime = 3600  # 1 hour
        self.exempt_blueprints = set()
    
    def init_app(self, app):
        """Initialize CSRF protection with Flask app"""
        self.secret_key = app.config.get('SECRET_KEY', 'default-secret')
        if self.secret_key == 'default-secret':
            # Generate a temporary secret key for testing
            import secrets
            self.secret_key = secrets.token_hex(32)
        self.token_lifetime = app.config.get('CSRF_TOKEN_LIFETIME', 3600)
    
    def exempt(self, blueprint):
        """Exempt a blueprint from CSRF protection"""
        self.exempt_blueprints.add(blueprint.name)
    
    def generate_csrf_token(self, user_id: str, session_id: Optional[str] = None) -> str:
        """
        Generate a CSRF token for the user
        
        Args:
            user_id: User identifier
            session_id: Optional session identifier
            
        Returns:
            CSRF token string
        """
        timestamp = str(int(time.time()))
        session_part = session_id or 'no-session'
        
        # Create token data
        token_data = f"{user_id}:{session_part}:{timestamp}"
        
        # Generate HMAC signature
        signature = hmac.new(
            self.secret_key.encode(),
            token_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Combine data and signature
        token = f"{token_data}:{signature}"
        
        # Base64 encode for safe transport
        import base64
        return base64.b64encode(token.encode()).decode()
    
    def validate_csrf_token(self, token: str, user_id: str, session_id: Optional[str] = None) -> bool:
        """
        Validate a CSRF token
        
        Args:
            token: CSRF token to validate
            user_id: Expected user identifier
            session_id: Optional session identifier
            
        Returns:
            True if token is valid
        """
        try:
            # Base64 decode
            import base64
            decoded_token = base64.b64decode(token.encode()).decode()
            
            # Split token parts
            parts = decoded_token.split(':')
            if len(parts) != 4:
                return False
            
            token_user_id, token_session_id, timestamp, signature = parts
            
            # Verify user ID matches
            if token_user_id != user_id:
                return False
            
            # Verify session ID if provided
            session_part = session_id or 'no-session'
            if token_session_id != session_part:
                return False
            
            # Check token age
            token_time = int(timestamp)
            current_time = int(time.time())
            if current_time - token_time > self.token_lifetime:
                return False
            
            # Verify signature
            expected_data = f"{token_user_id}:{token_session_id}:{timestamp}"
            expected_signature = hmac.new(
                self.secret_key.encode(),
                expected_data.encode(),
                hashlib.sha256
            ).hexdigest()
            
            return hmac.compare_digest(signature, expected_signature)
            
        except Exception:
            return False


# Global CSRF protection instance
csrf_protection = CSRFProtection()


def require_csrf(f):
    """
    Enhanced decorator to require CSRF token for state-changing operations
    Must be used after require_auth decorator
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Skip CSRF check for GET, HEAD, OPTIONS requests
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return f(*args, **kwargs)
        
        # Skip CSRF for development mode on auth routes
        import os
        if os.getenv('FLASK_ENV') == 'development':
            if request.path.startswith('/api/auth/'):
                return f(*args, **kwargs)
        
        # Skip CSRF for API endpoints with OAuth authentication
        if request.path.startswith('/api/') and request.headers.get('Authorization'):
            oauth_header = request.headers.get('Authorization', '')
            if oauth_header.startswith('Bearer '):
                return f(*args, **kwargs)
        
        # Get CSRF token from header or form data
        csrf_token = (
            request.headers.get('X-CSRF-Token') or 
            request.headers.get('X-CSRFToken') or
            request.form.get('csrf_token') or
            request.json.get('csrf_token') if request.is_json else None
        )
        
        if not csrf_token:
            try:
                audit_logger.log_event(
                    event_type='security_violation',
                    user_id=getattr(g, 'user_id', None),
                    action='csrf_token_missing',
                    resource=request.path,
                    result='blocked',
                    details={
                        'method': request.method,
                        'client_ip': request.remote_addr,
                        'user_agent': request.headers.get('User-Agent', '')
                    },
                    severity='medium'
                )
            except Exception as e:
                print(f"Failed to log CSRF violation: {e}", file=sys.stderr)
            
            return jsonify({
                'success': False,
                'error': {
                    'code': 'CSRF_TOKEN_MISSING',
                    'message': 'CSRF token required for this operation'
                }
            }), 403
        
        try:
            # Get user ID from request context
            user_id = getattr(g, 'user_id', None) or getattr(request, 'user_id', None)
            if not user_id:
                return jsonify({
                    'success': False,
                    'error': {
                        'code': 'AUTH_REQUIRED',
                        'message': 'Authentication required'
                    }
                }), 401
            
            # Get session ID if available
            session_id = getattr(g, 'session_id', None)
            
            # Validate CSRF token
            if not csrf_protection.validate_csrf_token(csrf_token, user_id, session_id):
                try:
                    audit_logger.log_event(
                        event_type='security_violation',
                        user_id=user_id,
                        action='csrf_token_invalid',
                        resource=request.path,
                        result='blocked',
                        details={
                            'method': request.method,
                            'client_ip': request.remote_addr,
                            'user_agent': request.headers.get('User-Agent', ''),
                            'token_provided': bool(csrf_token)
                        },
                        severity='high'
                    )
                except Exception as e:
                    print(f"Failed to log CSRF violation: {e}", file=sys.stderr)
                
                return jsonify({
                    'success': False,
                    'error': {
                        'code': 'CSRF_TOKEN_INVALID',
                        'message': 'Invalid or expired CSRF token'
                    }
                }), 403
            
            return f(*args, **kwargs)
            
        except Exception as e:
            try:
                audit_logger.log_event(
                    event_type='security_violation',
                    user_id=getattr(g, 'user_id', None),
                    action='csrf_validation_error',
                    resource=request.path,
                    result='blocked',
                    details={
                        'error': str(e),
                        'method': request.method,
                        'client_ip': request.remote_addr
                    },
                    severity='high'
                )
            except Exception as log_e:
                print(f"Failed to log CSRF error: {log_e}", file=sys.stderr)
            
            return jsonify({
                'success': False,
                'error': {
                    'code': 'CSRF_VALIDATION_ERROR',
                    'message': 'CSRF token validation failed'
                }
            }), 403
    
    return decorated_function


def generate_csrf_token_for_user(user_id: str, session_id: Optional[str] = None) -> str:
    """
    Helper function to generate CSRF token for a user
    
    Args:
        user_id: User identifier
        session_id: Optional session identifier
        
    Returns:
        CSRF token string
    """
    return csrf_protection.generate_csrf_token(user_id, session_id)


def validate_csrf_double_submit(f):
    """
    Alternative CSRF protection using double-submit cookie pattern
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Skip CSRF check for GET, HEAD, OPTIONS requests
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return f(*args, **kwargs)
        
        # Get CSRF token from header and cookie
        header_token = request.headers.get('X-CSRF-Token')
        cookie_token = request.cookies.get('csrf_token')
        
        if not header_token or not cookie_token:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'CSRF_TOKEN_MISSING',
                    'message': 'CSRF token required in both header and cookie'
                }
            }), 403
        
        # Verify tokens match
        if not hmac.compare_digest(header_token, cookie_token):
            try:
                audit_logger.log_event(
                    event_type='security_violation',
                    user_id=getattr(g, 'user_id', None),
                    action='csrf_double_submit_mismatch',
                    resource=request.path,
                    result='blocked',
                    details={
                        'method': request.method,
                        'client_ip': request.remote_addr
                    },
                    severity='high'
                )
            except Exception as e:
                print(f"Failed to log CSRF violation: {e}", file=sys.stderr)
            
            return jsonify({
                'success': False,
                'error': {
                    'code': 'CSRF_TOKEN_MISMATCH',
                    'message': 'CSRF token mismatch between header and cookie'
                }
            }), 403
        
        return f(*args, **kwargs)
    
    return decorated_function
