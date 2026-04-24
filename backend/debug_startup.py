import sys
import os
import traceback

# Add current directory to path
sys.path.append(os.getcwd())

print("Attempting to import create_app...")
try:
    from app import create_app
    print("Import successful.")
    
    print("Creating app...")
    app = create_app()
    print("App created successfully.")
    
except Exception as e:
    print(f"Startup failed: {e}")
    traceback.print_exc()