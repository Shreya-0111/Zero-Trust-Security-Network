
import sys
import os

# Add backend to sys.path
backend_path = '/Users/tanishpd/Downloads/Zero-Trust-Security-Framework-main/backend'
sys.path.append(backend_path)

try:
    print(f"Testing import app.routes.monitoring_routes (sys.path includes {backend_path})...")
    from app.routes.monitoring_routes import monitoring_bp
    print("Successfully imported monitoring_bp")
except Exception as e:
    print(f"FAILED to import monitoring_bp: {e}")
    import traceback
    traceback.print_exc()
