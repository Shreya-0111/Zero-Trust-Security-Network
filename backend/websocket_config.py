"""
Enhanced WebSocket Configuration for Zero Trust Security Framework
Eventlet-safe, production-ready, high concurrency WebSocket server
"""

import os
import jwt
import redis
import logging
import json
from functools import wraps
from datetime import datetime

from flask import request
from flask_socketio import (
    SocketIO, emit, join_room, leave_room, disconnect
)
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# --------------------------------------------------
# GLOBAL SocketIO instance (CRITICAL)
# --------------------------------------------------
socketio = None

# --------------------------------------------------
# Connection tracking
# --------------------------------------------------
active_connections = {}
redis_client = None


# --------------------------------------------------
# Decorators
# --------------------------------------------------
def authenticated_only(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        sid = request.sid
        if sid not in active_connections or not active_connections[sid].get("authenticated"):
            emit("authentication_required", {
                "message": "Authentication required",
                "timestamp": datetime.utcnow().isoformat()
            })
            return
        return f(*args, **kwargs)
    return wrapped


def admin_only(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        sid = request.sid
        if sid not in active_connections:
            emit("authentication_required", {"message": "Authentication required"})
            return
        if active_connections[sid].get("role") != "admin":
            emit("authorization_denied", {
                "message": "Admin privileges required",
                "timestamp": datetime.utcnow().isoformat()
            })
            return
        return f(*args, **kwargs)
    return wrapped


# --------------------------------------------------
# INIT
# --------------------------------------------------
def init_socketio(app):
    global redis_client, socketio

    # Skip heavy Redis setup in development
    is_development = os.getenv("FLASK_ENV") == "development"

    async_mode = "eventlet"
    if is_development:
        async_mode = "threading"
    else:
        try:
            import eventlet  # noqa: F401
        except Exception:
            async_mode = "threading"
    
    # Initialize SocketIO with the app
    socketio_kwargs = {
        "cors_allowed_origins": os.getenv(
            "WEBSOCKET_CORS_ALLOWED_ORIGINS",
            "http://localhost:3000"
        ).split(","),
        "async_mode": async_mode,
        "logger": is_development,
        "engineio_logger": is_development,
    }

    # Werkzeug dev server + threading mode can throw assertion errors on websocket upgrade.
    # Force polling transport in development to keep the app stable.
    if is_development and async_mode == "threading":
        socketio_kwargs["transports"] = ["polling"]

    socketio = SocketIO(
        app,
        **socketio_kwargs
    )

    # Redis ONLY in production
    if not is_development and os.getenv("ENABLE_REDIS_SCALING", "false").lower() == "true":
        try:
            redis_client = redis.Redis(
                host=os.getenv("REDIS_HOST", "localhost"),
                port=int(os.getenv("REDIS_PORT", 6379)),
                password=os.getenv("REDIS_PASSWORD"),
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2
            )
            redis_client.ping()
            logger.info("Redis enabled for WebSocket scaling")
        except Exception as e:
            logger.warning(f"Redis disabled: {e}")
            redis_client = None

    register_handlers()
    logger.info("WebSocket server initialized (eventlet mode)")
    return socketio


# --------------------------------------------------
# AUTH
# --------------------------------------------------
def verify_jwt_token(token):
    try:
        return jwt.decode(
            token,
            os.getenv("JWT_SECRET_KEY", "dev_jwt_secret"),
            algorithms=["HS256"]
        )
    except Exception:
        return None


# --------------------------------------------------
# HANDLERS
# --------------------------------------------------
def register_handlers():

    @socketio.on("connect")
    def connect(auth=None):
        sid = request.sid
        active_connections[sid] = {
            "connected_at": datetime.utcnow().isoformat(),
            "authenticated": False,
            "rooms": [],
            "user_id": None,
            "role": None,
            "last_activity": datetime.utcnow().isoformat()
        }
        emit("connection_established", {
            "sid": sid,
            "authentication_required": True,
            "timestamp": datetime.utcnow().isoformat()
        })
        logger.info(f"Client connected: {sid}")

    @socketio.on("authenticate")
    def authenticate(data):
        sid = request.sid
        payload = verify_jwt_token(data.get("token"))

        if not payload:
            emit("authentication_failed", {"message": "Invalid token"})
            return

        active_connections[sid].update({
            "authenticated": True,
            "user_id": payload.get("user_id"),
            "role": payload.get("role")
        })

        user_room = f"user_{payload['user_id']}"
        role_room = f"role_{payload['role']}"

        join_room(user_room)
        join_room(role_room)

        active_connections[sid]["rooms"].extend([user_room, role_room])

        emit("authentication_success", {
            "user_id": payload["user_id"],
            "role": payload["role"]
        })

    @socketio.on("disconnect")
    def disconnect_handler():
        sid = request.sid
        user = active_connections.pop(sid, None)
        logger.info(f"Client disconnected: {sid} ({user})")

    @authenticated_only
    @socketio.on("subscribe_risk_score")
    def subscribe_risk(data):
        session_id = data.get("session_id")
        if session_id:
            room = f"risk_score_{session_id}"
            join_room(room)
            active_connections[request.sid]["rooms"].append(room)
            emit("subscribed", {"room": room})


# --------------------------------------------------
# EMITTERS (unchanged logic)
# --------------------------------------------------
def emit_risk_score_update(session_id, risk_score, risk_level, details=None, user_id=None):
    socketio.emit("risk_score_update", {
        "session_id": session_id,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "details": details,
        "timestamp": datetime.utcnow().isoformat()
    }, room=f"risk_score_{session_id}")

def emit_admin_notification(notification_data):
    """
    Emit notification to all admin users
    (Backward compatibility function)
    """
    if not socketio:
        return

    enhanced_notification = {
        **notification_data,
        "timestamp": datetime.utcnow().isoformat()
    }

    socketio.emit(
        "admin_notification",
        enhanced_notification,
        room="admin_room"
    )
