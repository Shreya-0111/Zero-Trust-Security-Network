"""
Authorization Middleware
Role-based access control decorators for API endpoints
"""

import os
from flask import request, jsonify, make_response
from functools import wraps
from app.services.auth_service_simple import auth_service
import inspect


def require_auth(f):
    """
    Decorator to require authentication for routes
    Verifies JWT session token, checks inactivity timeout, and adds user info to request
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get session token from cookie
        session_token = request.cookies.get('session_token')
        
        if not session_token:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'AUTH_REQUIRED',
                    'message': 'Authentication required'
                }
            }), 401
        
        try:
            # Verify session token (includes inactivity check)
            payload = auth_service.verify_session_token(session_token, check_inactivity=True)
            request.user_id = payload['user_id']
            request.user_role = payload['role']
            request.user_email = payload.get('email')
            request.current_user = {
                'uid': payload.get('user_id'),
                'role': payload.get('role'),
                'email': payload.get('email')
            }
            
            # Update last activity timestamp for non-GET requests
            if request.method not in ['GET', 'HEAD', 'OPTIONS']:
                auth_service.update_last_activity(payload['user_id'])

            # Keep middleware synchronous to avoid requiring Flask[async]
            return f(*args, **kwargs)
        except Exception as e:
            error_message = str(e)
            
            # Clear cookies if session is invalid or expired
            response = make_response(jsonify({
                'success': False,
                'error': {
                    'code': 'AUTH_INVALID_TOKEN',
                    'message': error_message
                }
            }), 401)
            
            if "timeout" in error_message.lower() or "expired" in error_message.lower():
                is_development = os.getenv('FLASK_ENV') == 'development'
                cookie_secure = not is_development
                cookie_samesite = 'Lax' if is_development else 'Strict'
                
                response.set_cookie('session_token', '', max_age=0, httponly=True, secure=cookie_secure, samesite=cookie_samesite)
                response.set_cookie('refresh_token', '', max_age=0, httponly=True, secure=cookie_secure, samesite=cookie_samesite)
                response.set_cookie('csrf_token', '', max_age=0, samesite=cookie_samesite)
            
            return response
    
    return decorated_function


def require_role(*allowed_roles):
    """
    Decorator to require specific role(s) for routes
    Must be used after @require_auth decorator
    
    Usage:
        @require_role('admin')
        @require_role('admin', 'faculty')
    
    Args:
        *allowed_roles: Variable number of role strings
    """
    if len(allowed_roles) == 1 and isinstance(allowed_roles[0], (list, tuple, set)):
        allowed_roles = tuple(allowed_roles[0])

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check if user_role is set by require_auth
            if not hasattr(request, 'user_role'):
                return jsonify({
                    'success': False,
                    'error': {
                        'code': 'AUTH_REQUIRED',
                        'message': 'Authentication required'
                    }
                }), 401
            
            # Check if user has required role
            if request.user_role not in allowed_roles:
                return jsonify({
                    'success': False,
                    'error': {
                        'code': 'FORBIDDEN',
                        'message': f'Access denied. Required role: {", ".join(allowed_roles)}'
                    }
                }), 403

            # Keep middleware synchronous to avoid requiring Flask[async]
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def require_admin(f):
    """
    Decorator to require admin role
    Shorthand for @require_role('admin')
    """
    @wraps(f)
    @require_auth
    @require_role('admin')
    def decorated_function(*args, **kwargs):
        return f(*args, **kwargs)
    
    return decorated_function


def require_faculty_or_admin(f):
    """
    Decorator to require faculty or admin role
    Shorthand for @require_role('faculty', 'admin')
    """
    @wraps(f)
    @require_auth
    @require_role('faculty', 'admin')
    def decorated_function(*args, **kwargs):
        return f(*args, **kwargs)
    
    return decorated_function


def get_current_user():
    """
    Get current authenticated user information from request
    Must be called within a route protected by @require_auth
    
    Returns:
        dict: User information (user_id, role, email)
        None: If not authenticated
    """
    if hasattr(request, 'user_id'):
        return {
            'user_id': request.user_id,
            'role': request.user_role,
            'email': getattr(request, 'user_email', None)
        }
    return None
