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
        cred_path = os.getenv('FIREBASE_CREDENTIALS_PATH', './firebase-credentials.json')
        storage_bucket = os.getenv('FIREBASE_STORAGE_BUCKET', 'zero-trust-security-framework.firebasestorage.app')
        
        # Strategy 1: Use service account JSON file if it exists and is valid
        if os.path.exists(cred_path):
            try:
                # Check if already initialized
                firebase_admin.get_app()
                _db = firestore.client()
                db = _db
                _firebase_initialized = True
                print("Firebase already initialized")
                return _db
            except ValueError:
                # Not initialized, try to load from file
                try:
                    cred = credentials.Certificate(cred_path)
                    firebase_admin.initialize_app(cred, {'storageBucket': storage_bucket})
                    _db = firestore.client()
                    db = _db
                    _firebase_initialized = True
                    print("Firebase initialized from JSON file")
                    return _db
                except Exception as file_err:
                    print(f"Failed to initialize from JSON file: {file_err}")
                    # Continue to Strategy 2
        
        # Strategy 2: Use individual environment variables (useful for .env users)
        fb_project_id = os.getenv('FIREBASE_PROJECT_ID')
        fb_private_key = os.getenv('FIREBASE_PRIVATE_KEY')
        fb_client_email = os.getenv('FIREBASE_CLIENT_EMAIL')
        
        if fb_project_id and fb_private_key and fb_client_email:
            try:
                # Handle formatted newlines in private key
                if "\\n" in fb_private_key:
                    fb_private_key = fb_private_key.replace("\\n", "\n")
                
                # Strip quotes if they exist
                if fb_private_key.startswith('"') and fb_private_key.endswith('"'):
                    fb_private_key = fb_private_key[1:-1]
                
                cred_dict = {
                    "type": "service_account",
                    "project_id": fb_project_id,
                    "private_key": fb_private_key,
                    "client_email": fb_client_email,
                    "token_uri": "https://oauth2.googleapis.com/token",
                }
                
                cred = credentials.Certificate(cred_dict)
                firebase_admin.initialize_app(cred, {'storageBucket': storage_bucket})
                _db = firestore.client()
                db = _db
                _firebase_initialized = True
                print("Firebase initialized from environment variables")
                return _db
            except Exception as env_err:
                print(f"Failed to initialize from environment variables: {env_err}")
                
        # Strategy 3: Mock initialization for development (last resort)
        if os.getenv('FLASK_ENV') == 'development' or os.getenv('BYPASS_FIREBASE_NETWORK_ERRORS') == 'true':
            print("⚠️ Firebase initialization failed or credentials missing. Using MOCK mode for development.")
            # We don't call initialize_app here to avoid further errors, 
            # but we mark as partially initialized so routes don't crash
            _firebase_initialized = True 
            db = None
            return None
            
        print("❌ Firebase initialized failed: No valid credentials found")
        _firebase_initialized = False
        return None
        
    except Exception as e:
        print(f"Critical error in initialize_firebase: {str(e)}")
        _firebase_initialized = False
        db = None
        return None

def get_firestore_client():
    """Get Firestore client instance"""
    global _db, db
    if not _firebase_initialized:
        _db = initialize_firebase()
        db = _db
    return _db

def verify_firebase_token(id_token):
    """Verify Firebase ID token with fallback for development"""
    is_development = os.getenv('FLASK_ENV') == 'development'
    bypass_network_errors = os.getenv('BYPASS_FIREBASE_NETWORK_ERRORS', 'false').lower() == 'true'
    
    # Initialize if not already done
    if not _firebase_initialized:
        initialize_firebase()

    # Try real verification if Firebase is initialized
    if _firebase_initialized and db is not None:
        try:
            # Verify the token
            decoded_token = auth.verify_id_token(id_token)
            print(f"✅ Firebase token verified for user: {decoded_token.get('email')}")
            return decoded_token
        except Exception as e:
            print(f"❌ Firebase token verification failed: {str(e)}")
            # Only use fallback if we are in dev mode AND bypass is enabled
            if is_development and bypass_network_errors:
                print("🔧 Development mode: Using fallback mock token due to verification failure")
                return {
                    'uid': 'dev_user_fallback',
                    'email': 'dev-fallback@example.com',
                    'email_verified': True,
                    'name': 'Development Fallback User'
                }
            return None

    # If we get here, Firebase is NOT initialized. 
    # Check if we should use the hardcoded bypass.
    if is_development and bypass_network_errors:
        print("🔧 Development mode: Using Firebase bypass (Firebase not initialized)")
        return {
            'uid': 'dev_user_12345678',
            'email': 'dev@example.com',
            'email_verified': True,
            'name': 'Development User'
        }

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
