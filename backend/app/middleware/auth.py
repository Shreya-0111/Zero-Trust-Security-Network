"""
Authentication middleware for Zero Trust Security Framework
"""

from functools import wraps
from flask import request, jsonify, g
from app.services.auth_service import auth_service
import jwt
import os

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # Get token from header
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return jsonify({'error': 'No authorization header'}), 401
            
            # Extract token
            try:
                token = auth_header.split(' ')[1]  # Bearer <token>
            except IndexError:
                return jsonify({'error': 'Invalid authorization header format'}), 401
            
            # Verify token
            try:
                payload = jwt.decode(
                    token, 
                    os.getenv('JWT_SECRET_KEY', 'default-secret'), 
                    algorithms=['HS256']
                )
                g.current_user_id = payload.get('user_id')
                g.current_user = payload
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Token has expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'error': 'Invalid token'}), 401
            
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({'error': 'Authentication failed'}), 401
    
    return decorated_function

def require_role(required_role):
    """Decorator to require specific role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Check if user is authenticated
                if not hasattr(g, 'current_user'):
                    return jsonify({'error': 'Authentication required'}), 401
                
                # Check role
                user_role = g.current_user.get('role', 'user')
                if user_role != required_role and user_role != 'admin':
                    return jsonify({'error': 'Insufficient permissions'}), 403
                
                return f(*args, **kwargs)
            except Exception as e:
                return jsonify({'error': 'Authorization failed'}), 403
        
        return decorated_function
    return decorator

def optional_auth(f):
    """Decorator for optional authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # Get token from header
            auth_header = request.headers.get('Authorization')
            if auth_header:
                try:
                    token = auth_header.split(' ')[1]  # Bearer <token>
                    payload = jwt.decode(
                        token, 
                        os.getenv('JWT_SECRET_KEY', 'default-secret'), 
                        algorithms=['HS256']
                    )
                    g.current_user_id = payload.get('user_id')
                    g.current_user = payload
                except:
                    # If token is invalid, continue without authentication
                    g.current_user_id = None
                    g.current_user = None
            else:
                g.current_user_id = None
                g.current_user = None
            
            return f(*args, **kwargs)
        except Exception as e:
            # Continue without authentication on any error
            g.current_user_id = None
            g.current_user = None
            return f(*args, **kwargs)
    
    return decorated_function