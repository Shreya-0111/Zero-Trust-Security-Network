import firebase_admin
from firebase_admin import credentials, auth, firestore
import os

# Firebase Admin SDK initialization
_firebase_initialized = False
_db = None

# Backward-compatible alias used by some modules
db = None

def initialize_firebase():
    """Initialize Firebase Admin SDK"""
    global _firebase_initialized, _db, db
    
    if _firebase_initialized:
        return _db
    
    try:
        # A more robust way to find the backend directory
        # Assumes firebase_config.py is in 'app/' and credentials are in 'backend/'
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) # This gets to the 'backend' directory
        cred_path = os.path.join(base_dir, 'firebase-credentials.json')
        
        if os.path.exists(cred_path):
            # Check if Firebase is already initialized
            try:
                firebase_admin.get_app()
                # Already initialized, just get the client
                _db = firestore.client()
                db = _db
                _firebase_initialized = True
                print("Firebase already initialized, using existing app")
            except ValueError:
                # Not initialized, so initialize it
                cred = credentials.Certificate(cred_path)
                firebase_admin.initialize_app(cred, {
                    'storageBucket': 'break-glass-41fa7.appspot.com'
                })
                _db = firestore.client()
                db = _db
                _firebase_initialized = True
                print("✅ Firebase app initialized successfully with service account.")
        else:
            print(f"⚠️ Warning: Firebase credentials file not found at {cred_path}. Backend cannot verify tokens.", flush=True)

    except Exception as e:
        print(f"🔥 Firebase initialization failed: {e}", flush=True)
        _db = None
        db = None
        return None
    
    return _db

def get_firestore_client():
    """Get Firestore client instance"""
    global _db, db
    if not _firebase_initialized:
        _db = initialize_firebase()
        db = _db
    return _db

def verify_firebase_token(id_token):
    """Verify Firebase ID token"""
    
    # Development mode bypass - check this FIRST
    is_development = os.getenv('FLASK_ENV') == 'development'
    bypass_network_errors = os.getenv('BYPASS_FIREBASE_NETWORK_ERRORS', 'false').lower() == 'true'
    
    if is_development and bypass_network_errors:
        print("🔧 Development mode: Using Firebase bypass")
        # Create a mock token for development
        return {
            'uid': 'dev_user_12345678',
            'email': 'dev@example.com',
            'email_verified': True,
            'name': 'Development User'
        }

    try:
        # Initialize Firebase if not already done
        if not _firebase_initialized:
            initialize_firebase()
        
        if not _firebase_initialized:
            raise Exception("Firebase not initialized")
        
        # Verify the token
        decoded_token = auth.verify_id_token(id_token)
        print(f"✅ Firebase token verified for user: {decoded_token.get('email')}")
        return decoded_token
        
    except Exception as e:
        print(f"❌ Firebase token verification failed: {str(e)}")
        
        # In development, we can be more lenient
        if is_development:
            print("🔧 Development mode: Firebase verification failed, but continuing...")
            # Return a mock token based on the error
            return {
                'uid': 'dev_user_fallback',
                'email': 'dev-fallback@example.com',
                'email_verified': True,
                'name': 'Development Fallback User'
            }
        
        # In production, fail hard
        return None
    
    try:
        # Make sure Firebase is initialized
        if not _firebase_initialized:
            initialize_firebase()
        
        if not _firebase_initialized:
            raise Exception("Firebase not initialized - credentials file missing")
        
        # Add timeout and retry logic for network issues
        import time
        max_retries = 3
        retry_delay = 1
        
        for attempt in range(max_retries):
            try:
                decoded_token = auth.verify_id_token(id_token)
                
                # In development mode, allow unverified emails
                if not is_development and not decoded_token.get('email_verified', False):
                    raise Exception("Email not verified. Please verify your email before logging in.")
                
                return decoded_token
                
            except Exception as network_error:
                error_str = str(network_error)
                if ("Failed to resolve" in error_str or 
                    "Max retries exceeded" in error_str or
                    "Connection" in error_str or
                    "timeout" in error_str.lower()):
                    
                    if attempt < max_retries - 1:
                        print(f"Network error on attempt {attempt + 1}, retrying in {retry_delay}s...")
                        time.sleep(retry_delay)
                        retry_delay *= 2  # Exponential backoff
                        continue
                    else:
                        print(f"Network error after {max_retries} attempts: {network_error}")
                        # In development, allow bypass for testing
                        if is_development:
                            print("⚠️ DEVELOPMENT MODE: Bypassing Firebase network error")
                            # Create a mock token for development
                            return {
                                'uid': 'dev_user_12345678',
                                'email': 'dev@example.com',
                                'email_verified': True,
                                'name': 'Development User'
                            }
                        raise network_error
                else:
                    # Non-network error, re-raise immediately
                    raise network_error
        
    except Exception as e:
        print(f"Error verifying token: {str(e)}")
        return None
