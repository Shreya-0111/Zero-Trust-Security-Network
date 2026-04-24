import os
from flask import Flask, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

IS_DEVELOPMENT = os.getenv("FLASK_ENV", "development") == "development"


def create_app():
    print("🏗️  Creating Flask application", flush=True)

    app = Flask(__name__)

    # --------------------------------------------------
    # BASIC CONFIG
    # --------------------------------------------------
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev_secret_key")
    app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "dev_jwt_secret")
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB for photo uploads

    # --------------------------------------------------
    # CORS
    # --------------------------------------------------
    # Apply CORS to API routes so the frontend (3000) can call backend (5001)
    # even when handlers return errors.
    CORS(
        app,
        resources={r"/api/*": {"origins": ["http://localhost:3000", "http://127.0.0.1:3000"]}},
        supports_credentials=True,
        allow_headers=[
            "Content-Type",
            "Authorization",
            "X-CSRF-Token",
            "X-Requested-With",
        ],
        methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    )
    print("✅ CORS configured for /api/* (localhost:3000 allowed)", flush=True)

    # --------------------------------------------------
    # HEALTH CHECK (IMMEDIATE)
    # --------------------------------------------------
    @app.route("/health", methods=["GET"])
    def health():
        return {
            "status": "healthy",
            "timestamp": "ready"
        }, 200

    # --------------------------------------------------
    # INITIALIZE FIREBASE EARLY (SYNCHRONOUS FOR AUTH)
    # --------------------------------------------------
    try:
        print("🔄 Initializing Firebase...", flush=True)
        from app.firebase_config import initialize_firebase
        initialize_firebase()
        print("✅ Firebase initialized", flush=True)
    except Exception as e:
        print(f"⚠️ Firebase initialization failed: {e}", flush=True)

    # --------------------------------------------------
    # REGISTER AUTH ROUTES FIRST (CRITICAL)
    # --------------------------------------------------
    try:
        from app.routes.auth_routes import bp as auth_bp
        app.register_blueprint(auth_bp)
        print("✅ Auth routes registered", flush=True)
    except Exception as e:
        print(f"❌ Failed to register auth routes: {e}", flush=True)

    # --------------------------------------------------
    # REGISTER APPLICATION ROUTES
    # --------------------------------------------------
    blueprints = [
        ("notification_routes", "bp"),
        ("access_routes", "bp"),
        ("jit_access_routes", "bp"),
        ("admin_jit_routes", "bp"),
        ("user_routes", "bp"),
        ("admin_routes", "bp"),
        ("break_glass_routes", "break_glass_bp"),
        ("resource_routes", "resource_bp"),
        ("resource_segment_routes", "bp"),
        ("device_routes", "device_bp"),
        ("policy_routes", "bp"),
        ("monitoring_routes", "monitoring_bp"),
        ("reports_routes", "reports_bp"),
        ("security_routes", "security_bp"),
        ("system_routes", "system_bp"),
        ("visitor_routes", "visitor_bp"),
        ("training_routes", "training_bp"),
        ("threat_routes", "threat_bp"),
    ]

    for module_name, attr in blueprints:
        try:
            module = __import__(f"app.routes.{module_name}", fromlist=[attr])
            bp_obj = getattr(module, attr)
            if bp_obj is not None:
                app.register_blueprint(bp_obj)
        except Exception as e:
            print(f"⚠️ Failed to register {module_name}.{attr}: {e}", flush=True)

    # --------------------------------------------------
    # INITIALIZE SOCKET.IO (OPTIONAL)
    # --------------------------------------------------
    try:
        from websocket_config import init_socketio
        socketio = init_socketio(app)
        app.config["SOCKETIO"] = socketio
        print("✅ Socket.IO initialized", flush=True)
    except Exception as e:
        app.config["SOCKETIO"] = None
        print(f"⚠️ Socket.IO initialization failed: {e}", flush=True)

    print("🚀 Flask app ready", flush=True)
    return app