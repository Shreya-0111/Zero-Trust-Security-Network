"""
Authentication Routes - Firebase Integration
Fast and reliable Firebase authentication with backend session management
"""

import os
import jwt
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Blueprint, request, jsonify, make_response

# Firebase imports
try:
    from app.firebase_config import verify_firebase_token, get_firestore_client
    FIREBASE_AVAILABLE = True
except Exception as e:
    print(f"Firebase import error: {e}")
    verify_firebase_token = None
    get_firestore_client = None
    FIREBASE_AVAILABLE = False

bp = Blueprint("auth", __name__, url_prefix="/api/auth")

IS_DEV = os.getenv("FLASK_ENV", "development") == "development"
JWT_SECRET = os.getenv("JWT_SECRET_KEY", "dev_jwt_secret")
BYPASS_FIREBASE = os.getenv("BYPASS_FIREBASE_NETWORK_ERRORS", "false").lower() == "true"


def _cors_preflight_response(methods: str):
    response = make_response()
    origin = request.headers.get("Origin")
    allowed_origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",") if o.strip()]
    if origin and origin in allowed_origins:
        response.headers.add("Access-Control-Allow-Origin", origin)
    response.headers.add("Vary", "Origin")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization,X-CSRF-Token")
    response.headers.add("Access-Control-Allow-Methods", methods)
    response.headers.add("Access-Control-Allow-Credentials", "true")
    return response

# =======================================================
# HELPERS
# =======================================================

def create_session_token(user_data):
    """Create JWT session token"""
    now = datetime.utcnow()
    payload = {
        'user_id': user_data.get('uid'),
        'email': user_data.get('email'),
        'name': user_data.get('name', ''),
        'role': user_data.get('role', 'user'),
        'exp': now + timedelta(hours=1),
        'iat': now,
        'type': 'access',
        'last_activity': now.isoformat()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_session_token(token):
    """Verify JWT session token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        raise Exception("Token expired")
    except jwt.InvalidTokenError:
        raise Exception("Invalid token")

def get_user_from_firestore(uid):
    """Get user data from Firestore with fallback"""
    if not FIREBASE_AVAILABLE or not get_firestore_client:
        return None
    
    try:
        db = get_firestore_client()
        if not db:
            return None
            
        user_doc = db.collection('users').document(uid).get()
        
        if user_doc.exists:
            return user_doc.to_dict()
        return None
    except Exception as e:
        print(f"Error getting user from Firestore: {e}")
        return None

def create_user_in_firestore(user_data):
    """Create user document in Firestore with fallback"""
    if not FIREBASE_AVAILABLE or not get_firestore_client:
        if IS_DEV and BYPASS_FIREBASE:
            print("Development mode: Skipping Firestore user creation")
            return True
        return False
    
    try:
        db = get_firestore_client()
        if not db:
            return False
            
        uid = user_data.get('uid') or user_data.get('user_id') or user_data.get('id')
        if not uid:
            return False

        user_ref = db.collection('users').document(uid)
        
        user_doc = {
            'uid': uid,
            'email': user_data.get('email'),
            'name': user_data.get('name', ''),
            'role': user_data.get('role', 'user'),
            'created_at': datetime.utcnow(),
            'last_login': datetime.utcnow(),
            'email_verified': user_data.get('email_verified', False)
        }
        
        user_ref.set(user_doc)
        return True
    except Exception as e:
        print(f"Error creating user in Firestore: {e}")
        if IS_DEV and BYPASS_FIREBASE:
            print("Development mode: Allowing user creation to proceed")
            return True
        return False

def _clear_auth_cookies(resp):
    """Clear authentication cookies"""
    secure = not IS_DEV
    samesite = "Lax" if IS_DEV else "Strict"
    resp.set_cookie("session_token", "", max_age=0, secure=secure, samesite=samesite, path="/")
    resp.set_cookie("csrf_token", "", max_age=0, secure=secure, samesite=samesite, path="/")

def _set_auth_cookies(resp, session_token, csrf_token):
    """Set authentication cookies"""
    secure = not IS_DEV
    samesite = "Lax" if IS_DEV else "Strict"
    
    resp.set_cookie(
        "session_token",
        session_token,
        httponly=True,
        secure=secure,
        samesite=samesite,
        path="/",
        max_age=3600  # 1 hour
    )
    
    resp.set_cookie(
        "csrf_token",
        csrf_token,
        httponly=False,  # Accessible to JS
        secure=secure,
        samesite=samesite,
        path="/",
        max_age=3600
    )

# =======================================================
# AUTHENTICATION DECORATOR
# =======================================================

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.cookies.get("session_token")
        if not token:
            return jsonify({
                "success": False,
                "error": {"code": "AUTH_REQUIRED", "message": "Login required"}
            }), 401

        try:
            payload = verify_session_token(token)
            request.user_id = payload["user_id"]
            request.user_email = payload.get("email")
            request.user_role = payload.get("role")
            return f(*args, **kwargs)
        except Exception as e:
            resp = make_response(jsonify({
                "success": False,
                "error": {"code": "AUTH_INVALID", "message": str(e)}
            }), 401)
            _clear_auth_cookies(resp)
            return resp
    return wrapper

# =======================================================
# ROUTES
# =======================================================

@bp.route("/health", methods=["GET"])
def health():
    """Simple health check for auth service"""
    return jsonify({
        "status": "healthy",
        "service": "auth",
        "firebase_available": FIREBASE_AVAILABLE,
        "bypass_mode": BYPASS_FIREBASE,
        "timestamp": datetime.utcnow().isoformat()
    })

@bp.route("/verify", methods=["POST", "OPTIONS"])
def verify_firebase_id_token():
    """
    Verify Firebase ID token and create backend session
    This is called after Firebase authentication on the frontend
    """
    if request.method == "OPTIONS":
        return _cors_preflight_response("POST,OPTIONS")

    try:
        data = request.get_json()
        if not data or 'idToken' not in data:
            return jsonify({
                "success": False,
                "error": {"code": "MISSING_TOKEN", "message": "Firebase ID token required"}
            }), 400

        id_token = data['idToken']
        
        # Fast Firebase token verification with fallback
        if not verify_firebase_token:
            if IS_DEV and BYPASS_FIREBASE:
                # Development bypass
                decoded_token = {
                    'uid': 'dev_user_12345678',
                    'email': 'dev@example.com',
                    'email_verified': True,
                    'name': 'Development User'
                }
            else:
                return jsonify({
                    "success": False,
                    "error": {"code": "FIREBASE_ERROR", "message": "Firebase not configured properly"}
                }), 500
        else:
            decoded_token = verify_firebase_token(id_token)
            if not decoded_token:
                return jsonify({
                    "success": False,
                    "error": {"code": "INVALID_TOKEN", "message": "Invalid Firebase token"}
                }), 401

        # Get or create user in Firestore
        uid = decoded_token.get('uid') or decoded_token.get('user_id') or decoded_token.get('sub')
        if not uid:
            return jsonify({
                "success": False,
                "error": {"code": "INVALID_TOKEN", "message": "Verified token missing user identifier"}
            }), 401
        user_data = get_user_from_firestore(uid)
        
        if not user_data:
            # Create new user
            user_data = {
                'uid': uid,
                'email': decoded_token.get('email'),
                'name': decoded_token.get('name', ''),
                'role': 'user',  # Default role
                'email_verified': decoded_token.get('email_verified', False)
            }
            create_user_in_firestore(user_data)
        else:
            # Normalize legacy user docs that might not have 'uid'
            if isinstance(user_data, dict) and not user_data.get('uid'):
                user_data = {**user_data, 'uid': uid}

        # Create session token
        session_token = create_session_token(user_data)
        csrf_token = secrets.token_urlsafe(32)

        # Prepare response
        response_data = {
            "success": True,
            "user": {
                "id": user_data.get('uid', uid),
                "email": user_data.get('email'),
                "name": user_data.get('name', ''),
                "role": user_data.get('role', 'user'),
                "emailVerified": user_data.get('email_verified', False)
            },
            "sessionToken": session_token,
            "csrfToken": csrf_token
        }

        resp = make_response(jsonify(response_data))
        _set_auth_cookies(resp, session_token, csrf_token)

        return resp

    except Exception as e:
        print(f"Auth verification error: {e}")
        return jsonify({
            "success": False,
            "error": {"code": "SERVER_ERROR", "message": str(e)}
        }), 500


@bp.route("/dev-login", methods=["POST", "OPTIONS"])
def dev_login():
    if request.method == "OPTIONS":
        return _cors_preflight_response("POST,OPTIONS")

    if not IS_DEV:
        return jsonify({
            "success": False,
            "error": {"code": "NOT_AVAILABLE", "message": "Dev login is only available in development"}
        }), 404

    try:
        data = request.get_json() or {}

        user_data = {
            'uid': data.get('userId') or 'dev_user_12345678',
            'email': data.get('email') or 'dev@example.com',
            'name': data.get('name') or 'Development User',
            'role': data.get('role') or 'admin',
            'email_verified': True
        }

        # Create/update user in Firestore so downstream services can validate role/permissions
        try:
            create_user_in_firestore(user_data)
        except Exception as e:
            print(f"Warning: dev-login Firestore user upsert failed: {e}")

        session_token = create_session_token(user_data)
        csrf_token = secrets.token_urlsafe(32)

        response_data = {
            "success": True,
            "user": {
                "id": user_data.get('uid'),
                "email": user_data.get('email'),
                "name": user_data.get('name', ''),
                "role": user_data.get('role', 'user'),
                "emailVerified": True
            },
            "sessionToken": session_token,
            "csrfToken": csrf_token
        }

        resp = make_response(jsonify(response_data))
        _set_auth_cookies(resp, session_token, csrf_token)
        return resp
    except Exception as e:
        return jsonify({
            "success": False,
            "error": {"code": "SERVER_ERROR", "message": str(e)}
        }), 500

@bp.route("/refresh", methods=["POST", "OPTIONS"])
def refresh():
    """Refresh session token"""
    if request.method == "OPTIONS":
        return _cors_preflight_response("POST,OPTIONS")

    try:
        token = request.cookies.get("session_token")
        if not token:
            return jsonify({
                "success": False,
                "error": {"code": "NO_SESSION", "message": "No session token found"}
            }), 401

        # Verify current token
        try:
            payload = verify_session_token(token)
        except Exception as e:
            return jsonify({
                "success": False,
                "error": {"code": "INVALID_SESSION", "message": "Session expired"}
            }), 401

        # Get user data
        user_data = get_user_from_firestore(payload['user_id'])
        if not user_data:
            return jsonify({
                "success": False,
                "error": {"code": "USER_NOT_FOUND", "message": "User not found"}
            }), 401

        # Create new session token
        new_session_token = create_session_token(user_data)
        new_csrf_token = secrets.token_urlsafe(32)

        response_data = {
            "success": True,
            "user": {
                "id": user_data.get('uid'),
                "email": user_data.get('email'),
                "name": user_data.get('name', ''),
                "role": user_data.get('role', 'user'),
                "emailVerified": user_data.get('email_verified', False)
            },
            "sessionToken": new_session_token,
            "csrfToken": new_csrf_token
        }

        resp = make_response(jsonify(response_data))
        _set_auth_cookies(resp, new_session_token, new_csrf_token)

        return resp

    except Exception as e:
        print(f"Refresh error: {e}")
        return jsonify({
            "success": False,
            "error": {"code": "SERVER_ERROR", "message": "Session refresh failed"}
        }), 401

@bp.route("/logout", methods=["POST", "OPTIONS"])
def logout():
    """Logout user"""
    if request.method == "OPTIONS":
        return _cors_preflight_response("POST,OPTIONS")

    try:
        resp = make_response(jsonify({
            "success": True,
            "message": "Logged out successfully"
        }))
        
        # Clear cookies
        _clear_auth_cookies(resp)
        
        return resp

    except Exception as e:
        print(f"Logout error: {e}")
        return jsonify({
            "success": False,
            "error": {"code": "SERVER_ERROR", "message": str(e)}
        }), 500

@bp.route("/signup", methods=["POST", "OPTIONS"])
def signup():
    """
    Public signup endpoint - creates user with Firebase ID token
    This is called after Firebase user creation on the frontend
    """
    if request.method == "OPTIONS":
        return _cors_preflight_response("POST,OPTIONS")

    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "success": False,
                "error": {"code": "MISSING_DATA", "message": "Request data required"}
            }), 400

        # Required fields
        required_fields = ['idToken', 'role', 'name']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    "success": False,
                    "error": {"code": "MISSING_FIELD", "message": f"Missing required field: {field}"}
                }), 400

        id_token = data['idToken']
        role = data['role']
        name = data['name']
        department = data.get('department', '')
        student_id = data.get('studentId', '')

        # Validate role
        valid_roles = ['student', 'faculty', 'admin']
        if role not in valid_roles:
            return jsonify({
                "success": False,
                "error": {"code": "INVALID_ROLE", "message": f"Role must be one of: {', '.join(valid_roles)}"}
            }), 400

        # Verify Firebase token
        decoded_token = None
        if verify_firebase_token:
            decoded_token = verify_firebase_token(id_token)
        
        if not decoded_token:
            if IS_DEV and BYPASS_FIREBASE:
                # Last resort development fallback if verify_firebase_token failed and bypass is on
                decoded_token = {
                    'uid': 'dev_user_12345678',
                    'email': 'dev@example.com',
                    'email_verified': True,
                    'name': name
                }
            else:
                return jsonify({
                    "success": False,
                    "error": {"code": "INVALID_TOKEN", "message": "Invalid Firebase token"}
                }), 401

        # Get user ID
        uid = decoded_token.get('uid') or decoded_token.get('user_id') or decoded_token.get('sub')
        if not uid:
            return jsonify({
                "success": False,
                "error": {"code": "INVALID_TOKEN", "message": "Token missing user identifier"}
            }), 401

        # Check if user already exists
        existing_user = get_user_from_firestore(uid)
        if existing_user:
            return jsonify({
                "success": False,
                "error": {"code": "USER_EXISTS", "message": "User already registered"}
            }), 409

        # Create user data
        user_data = {
            'uid': uid,
            'email': decoded_token.get('email'),
            'name': name,
            'role': role,
            'department': department,
            'student_id': student_id if role == 'student' else None,
            'email_verified': decoded_token.get('email_verified', False),
            'created_at': datetime.utcnow(),
            'last_login': datetime.utcnow(),
            'is_active': True,
            'mfa_enabled': False,
            'failed_login_attempts': 0
        }

        # Create user in Firestore
        success = create_user_in_firestore(user_data)
        if not success:
            return jsonify({
                "success": False,
                "error": {"code": "USER_CREATION_FAILED", "message": "Failed to create user profile"}
            }), 500

        # Create session token
        session_token = create_session_token(user_data)
        csrf_token = secrets.token_urlsafe(32)

        # Prepare response
        response_data = {
            "success": True,
            "message": "User registered successfully",
            "user": {
                "id": uid,
                "email": user_data.get('email'),
                "name": name,
                "role": role,
                "department": department,
                "studentId": student_id,
                "emailVerified": user_data.get('email_verified', False)
            },
            "sessionToken": session_token,
            "csrfToken": csrf_token
        }

        resp = make_response(jsonify(response_data))
        _set_auth_cookies(resp, session_token, csrf_token)

        return resp

    except Exception as e:
        print(f"Signup error: {e}")
        return jsonify({
            "success": False,
            "error": {"code": "SERVER_ERROR", "message": str(e)}
        }), 500

@bp.route("/session/status", methods=["GET", "OPTIONS"])
@require_auth
def session_status():
    """Check session status"""
    if request.method == "OPTIONS":
        return _cors_preflight_response("GET,OPTIONS")

    try:
        user_data = get_user_from_firestore(request.user_id)
        
        return jsonify({
            "success": True,
            "authenticated": True,
            "user": {
                "id": request.user_id,
                "email": request.user_email,
                "name": user_data.get('name', '') if user_data else '',
                "role": request.user_role
            }
        })

    except Exception as e:
        print(f"Session status error: {e}")
        return jsonify({
            "success": False,
            "authenticated": False,
            "error": {"code": "SERVER_ERROR", "message": str(e)}
        }), 500