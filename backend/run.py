import os
import time
from app import create_app

# Performance optimization: disable heavy services in development
IS_DEVELOPMENT = os.getenv('FLASK_ENV', 'development') == 'development'

if IS_DEVELOPMENT:
    os.environ['ENABLE_PERFORMANCE_MONITORING'] = 'false'
    os.environ['ENABLE_DETAILED_LOGGING'] = 'false'
    # Don't override BYPASS_FIREBASE_NETWORK_ERRORS - let .env file control it

# Expose WSGI app for production servers like gunicorn
app = create_app()

def main():
    print("🚀 Starting Zero Trust Security Framework", flush=True)
    
    if IS_DEVELOPMENT:
        print("🔧 Development mode - optimizing for speed", flush=True)

    print("STEP 1: Creating application...", flush=True)
    startup_time = 0.0
    print(f"STEP 2: App created in {startup_time:.2f}s", flush=True)

    host = "0.0.0.0"
    port = int(os.getenv('PORT', 5001))
    debug = IS_DEVELOPMENT

    print(f"STEP 3: Starting server on {host}:{port}", flush=True)
    print(f"🔧 Debug mode: {'enabled' if debug else 'disabled'}", flush=True)

    # Use regular Flask server for faster startup
    socketio = getattr(app, "config", {}).get("SOCKETIO")
    if socketio is not None:
        socketio.run(
            app,
            host=host,
            port=port,
            debug=debug,
            allow_unsafe_werkzeug=debug,
            use_reloader=False
        )
    else:
        app.run(
            host=host,
            port=port,
            debug=debug,
            use_reloader=False,
            threaded=True
        )

if __name__ == "__main__":
    main()
