"""
Authentication Service
Handles user authentication, token verification, session management, and MFA operations
"""

import jwt
import pyotp
import os
import io
import base64
import secrets
from datetime import datetime, timedelta
from firebase_admin import auth, firestore
from cryptography.fernet import Fernet
from app.firebase_config import get_firestore_client, verify_firebase_token


class AuthService:
    """Authentication service for user management and session handling"""
    
    def __init__(self):
        self.db = get_firestore_client()
        self.jwt_secret = os.getenv('JWT_SECRET_KEY', 'dev_jwt_secret')
        self.jwt_algorithm = os.getenv('JWT_ALGORITHM', 'HS256')
        self.jwt_expiration_minutes = int(os.getenv('JWT_EXPIRATION_MINUTES', 60))
        self.refresh_token_expiration_days = int(os.getenv('REFRESH_TOKEN_EXPIRATION_DAYS', 7))
        self.session_inactivity_minutes = int(os.getenv('SESSION_INACTIVITY_MINUTES', 30))
        self.max_login_attempts = int(os.getenv('MAX_LOGIN_ATTEMPTS', 5))
        self.lockout_duration_minutes = int(os.getenv('LOCKOUT_DURATION_MINUTES', 30))
        self.mfa_lockout_attempts = int(os.getenv('MFA_LOCKOUT_ATTEMPTS', 3))
        
        # Initialize encryption key for MFA secrets
        # In production, this should be stored securely (e.g., in environment variable)
        encryption_key = os.getenv('ENCRYPTION_KEY')
        
        if not encryption_key:
            # Generate a key for development (should be persistent in production)
            encryption_key_bytes = Fernet.generate_key()
            print(f"Warning: Using generated encryption key. Set ENCRYPTION_KEY in production.")
        else:
            # Validate and convert the encryption key
            try:
                # Convert string to bytes if needed
                if isinstance(encryption_key, str):
                    encryption_key_bytes = encryption_key.encode()
                else:
                    encryption_key_bytes = encryption_key
                
                # Validate the key by trying to create a Fernet instance
                Fernet(encryption_key_bytes)
            except (ValueError, TypeError) as e:
                # If key is invalid, generate a new one for development
                print(f"Warning: Invalid ENCRYPTION_KEY format. Generating new key. Error: {e}")
                print(f"To fix: Generate a valid key using: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'")
                encryption_key_bytes = Fernet.generate_key()
        
        self.cipher = Fernet(encryption_key_bytes)
    
    def verify_firebase_token(self, id_token):
        """
        Verify Firebase ID token and return user data
        
        Args:
            id_token (str): Firebase ID token
            
        Returns:
            dict: Decoded token data with user information
            
        Raises:
            Exception: If token verification fails
        """
        try:
            decoded_token = verify_firebase_token(id_token)
            if not decoded_token:
                raise Exception("Invalid token")
            return decoded_token
        except Exception as e:
            raise Exception(f"Token verification failed: {str(e)}")
    
    def create_session(self, user_id, user_data):
        """
        Create JWT session token and refresh token for authenticated user
        
        Args:
            user_id (str): User ID
            user_data (dict): User information to include in token
            
        Returns:
            dict: Session token, refresh token, and CSRF token
        """
        try:
            # Create access token with 60-minute expiration
            access_expiration = datetime.utcnow() + timedelta(minutes=self.jwt_expiration_minutes)
            
            access_payload = {
                'user_id': user_id,
                'email': user_data.get('email'),
                'role': user_data.get('role'),
                'exp': access_expiration,
                'iat': datetime.utcnow(),
                'type': 'access',
                'last_activity': datetime.utcnow().isoformat()
            }
            
            access_token = jwt.encode(access_payload, self.jwt_secret, algorithm=self.jwt_algorithm)
            
            # Create refresh token with 7-day expiration
            refresh_expiration = datetime.utcnow() + timedelta(days=self.refresh_token_expiration_days)
            refresh_token_id = secrets.token_urlsafe(32)
            
            refresh_payload = {
                'user_id': user_id,
                'token_id': refresh_token_id,
                'exp': refresh_expiration,
                'iat': datetime.utcnow(),
                'type': 'refresh'
            }
            
            refresh_token = jwt.encode(refresh_payload, self.jwt_secret, algorithm=self.jwt_algorithm)
            
            # Generate CSRF token
            csrf_token = secrets.token_urlsafe(32)
            
            # Store refresh token and CSRF token in Firestore
            self.db.collection('sessions').document(user_id).set({
                'refreshTokenId': refresh_token_id,
                'csrfToken': csrf_token,
                'createdAt': datetime.utcnow(),
                'expiresAt': refresh_expiration,
                'lastActivity': datetime.utcnow()
            })
            
            return {
                'accessToken': access_token,
                'refreshToken': refresh_token,
                'csrfToken': csrf_token
            }
        except Exception as e:
            raise Exception(f"Session creation failed: {str(e)}")
    
    def verify_session_token(self, token, check_inactivity=True):
        """
        Verify JWT session token and check for inactivity timeout
        
        Args:
            token (str): JWT session token
            check_inactivity (bool): Whether to check for inactivity timeout
            
        Returns:
            dict: Decoded token payload
            
        Raises:
            Exception: If token is invalid, expired, or inactive
        """
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            
            # Verify token type
            if payload.get('type') != 'access':
                raise Exception("Invalid token type")
            
            # Check inactivity timeout
            if check_inactivity:
                last_activity_str = payload.get('last_activity')
                if last_activity_str:
                    last_activity = datetime.fromisoformat(last_activity_str)
                    inactivity_duration = datetime.utcnow() - last_activity
                    
                    if inactivity_duration.total_seconds() > (self.session_inactivity_minutes * 60):
                        raise Exception("Session timeout due to inactivity")
            
            return payload
        except jwt.ExpiredSignatureError:
            raise Exception("Session expired")
        except jwt.InvalidTokenError:
            raise Exception("Invalid session token")
    
    def refresh_session_with_token(self, refresh_token):
        """
        Refresh session using refresh token with token rotation
        
        Args:
            refresh_token (str): JWT refresh token
            
        Returns:
            dict: New access token, refresh token, and CSRF token
        """
        try:
            # Verify refresh token
            payload = jwt.decode(refresh_token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            
            # Verify token type
            if payload.get('type') != 'refresh':
                raise Exception("Invalid token type")
            
            user_id = payload['user_id']
            token_id = payload['token_id']
            
            # Verify refresh token ID matches stored value
            session_doc = self.db.collection('sessions').document(user_id).get()
            if not session_doc.exists:
                raise Exception("Session not found")
            
            session_data = session_doc.to_dict()
            if session_data.get('refreshTokenId') != token_id:
                # Token has already been used (possible replay attack)
                # Invalidate all sessions for this user
                self.invalidate_all_sessions(user_id)
                raise Exception("Invalid refresh token - possible replay attack detected")
            
            # Get user data from Firestore
            user_doc = self.db.collection('users').document(user_id).get()
            if not user_doc.exists:
                raise Exception("User not found")
            
            user_data = user_doc.to_dict()
            
            # Check if user is active
            if not user_data.get('isActive', True):
                raise Exception("Account has been disabled")
            
            # Create new session tokens (refresh token rotation)
            new_tokens = self.create_session(user_id, user_data)
            
            return new_tokens
        except jwt.ExpiredSignatureError:
            raise Exception("Refresh token expired")
        except jwt.InvalidTokenError:
            raise Exception("Invalid refresh token")
        except Exception as e:
            raise Exception(f"Session refresh failed: {str(e)}")
    
    def refresh_session(self, id_token):
        """
        Refresh session token with new expiration using Firebase ID token
        
        Args:
            id_token (str): Firebase ID token
            
        Returns:
            dict: New session tokens
        """
        try:
            decoded_token = self.verify_firebase_token(id_token)
            user_id = decoded_token['uid']
            
            # Get user data from Firestore
            user_doc = self.db.collection('users').document(user_id).get()
            if not user_doc.exists:
                raise Exception("User not found")
            
            user_data = user_doc.to_dict()
            return self.create_session(user_id, user_data)
        except Exception as e:
            raise Exception(f"Session refresh failed: {str(e)}")
    
    def check_login_attempts(self, user_id, ip_address):
        """
        Check and track failed login attempts with account lockout
        
        Args:
            user_id (str): User ID
            ip_address (str): Client IP address
            
        Returns:
            dict: Status with locked status and remaining attempts
            
        Raises:
            Exception: If account is locked
        """
        try:
            user_ref = self.db.collection('users').document(user_id)
            user_doc = user_ref.get()
            
            if not user_doc.exists:
                return {'locked': False, 'attempts': 0}
            
            user_data = user_doc.to_dict()
            failed_attempts = user_data.get('failedLoginAttempts', 0)
            lockout_until = user_data.get('lockoutUntil')
            
            # Check if account is currently locked
            if lockout_until:
                lockout_time = lockout_until
                if isinstance(lockout_time, datetime) and lockout_time > datetime.utcnow():
                    remaining_minutes = int((lockout_time - datetime.utcnow()).total_seconds() / 60)
                    raise Exception(f"Account locked. Try again in {remaining_minutes} minutes")
                else:
                    # Lockout period expired, reset attempts
                    user_ref.update({
                        'failedLoginAttempts': 0,
                        'lockoutUntil': None
                    })
                    failed_attempts = 0
            
            return {
                'locked': False,
                'attempts': failed_attempts,
                'remaining': self.max_login_attempts - failed_attempts
            }
        except Exception as e:
            if "Account locked" in str(e):
                raise
            print(f"Error checking login attempts: {str(e)}")
            return {'locked': False, 'attempts': 0}
    
    def record_failed_login(self, user_id, ip_address):
        """
        Record failed login attempt and lock account if threshold exceeded
        
        Args:
            user_id (str): User ID
            ip_address (str): Client IP address
        """
        try:
            user_ref = self.db.collection('users').document(user_id)
            user_doc = user_ref.get()
            
            if not user_doc.exists:
                return
            
            user_data = user_doc.to_dict()
            failed_attempts = user_data.get('failedLoginAttempts', 0) + 1
            
            update_data = {
                'failedLoginAttempts': failed_attempts,
                'metadata.lastFailedLoginIp': ip_address,
                'metadata.lastFailedLoginAt': datetime.utcnow()
            }
            
            # Lock account if max attempts exceeded
            if failed_attempts >= self.max_login_attempts:
                lockout_until = datetime.utcnow() + timedelta(minutes=self.lockout_duration_minutes)
                update_data['lockoutUntil'] = lockout_until
                
                # TODO: Send security alert email (will be implemented in audit logger)
                print(f"Account {user_id} locked until {lockout_until}")
            
            user_ref.update(update_data)
        except Exception as e:
            print(f"Error recording failed login: {str(e)}")
    
    def record_successful_login(self, user_id, ip_address, device_info):
        """
        Record successful login and reset failed attempts
        
        Args:
            user_id (str): User ID
            ip_address (str): Client IP address
            device_info (dict): Device information
        """
        try:
            user_ref = self.db.collection('users').document(user_id)
            user_ref.update({
                'failedLoginAttempts': 0,
                'lockoutUntil': None,
                'lastLogin': datetime.utcnow(),
                'metadata.lastIpAddress': ip_address,
                'metadata.lastDeviceInfo': device_info
            })
        except Exception as e:
            print(f"Error recording successful login: {str(e)}")
    
    def setup_mfa(self, user_id):
        """
        Generate MFA secret and QR code for user
        
        Args:
            user_id (str): User ID
            
        Returns:
            dict: MFA secret and QR code data URL
        """
        try:
            # Generate TOTP secret
            secret = pyotp.random_base32()
            
            # Get user email for QR code
            user_doc = self.db.collection('users').document(user_id).get()
            if not user_doc.exists:
                raise Exception("User not found")
            
            user_data = user_doc.to_dict()
            user_email = user_data.get('email', 'user@example.com')
            
            # Generate QR code URI
            totp = pyotp.TOTP(secret)
            provisioning_uri = totp.provisioning_uri(
                name=user_email,
                issuer_name="Zero Trust Security"
            )
            
            # Encrypt secret before storing
            encrypted_secret = self.cipher.encrypt(secret.encode()).decode()
            
            # Store encrypted secret in Firestore
            self.db.collection('users').document(user_id).update({
                'mfaSecret': encrypted_secret,
                'mfaEnabled': False  # Will be enabled after first successful verification
            })
            
            return {
                'secret': secret,
                'qrCodeUri': provisioning_uri
            }
        except Exception as e:
            raise Exception(f"MFA setup failed: {str(e)}")
    
    def verify_mfa_code(self, user_id, code):
        """
        Verify TOTP MFA code
        
        Args:
            user_id (str): User ID
            code (str): 6-digit TOTP code
            
        Returns:
            bool: True if code is valid
            
        Raises:
            Exception: If verification fails or account is locked
        """
        try:
            user_ref = self.db.collection('users').document(user_id)
            user_doc = user_ref.get()
            
            if not user_doc.exists:
                raise Exception("User not found")
            
            user_data = user_doc.to_dict()
            encrypted_secret = user_data.get('mfaSecret')
            
            if not encrypted_secret:
                raise Exception("MFA not set up for this user")
            
            # Check MFA failed attempts
            mfa_failed_attempts = user_data.get('mfaFailedAttempts', 0)
            if mfa_failed_attempts >= self.mfa_lockout_attempts:
                # Lock account and send alert
                lockout_until = datetime.utcnow() + timedelta(minutes=self.lockout_duration_minutes)
                user_ref.update({
                    'lockoutUntil': lockout_until,
                    'mfaFailedAttempts': 0
                })
                raise Exception("Account locked due to failed MFA attempts")
            
            # Decrypt secret
            secret = self.cipher.decrypt(encrypted_secret.encode()).decode()
            
            # Verify TOTP code
            totp = pyotp.TOTP(secret)
            is_valid = totp.verify(code, valid_window=1)  # Allow 1 time step tolerance
            
            if is_valid:
                # Reset failed attempts and enable MFA if first successful verification
                user_ref.update({
                    'mfaFailedAttempts': 0,
                    'mfaEnabled': True
                })
                return True
            else:
                # Increment failed attempts
                user_ref.update({
                    'mfaFailedAttempts': mfa_failed_attempts + 1
                })
                return False
        except Exception as e:
            if "Account locked" in str(e):
                raise
            raise Exception(f"MFA verification failed: {str(e)}")
    
    def verify_csrf_token(self, user_id, csrf_token):
        """
        Verify CSRF token for state-changing operations
        
        Args:
            user_id (str): User ID
            csrf_token (str): CSRF token from request
            
        Returns:
            bool: True if token is valid
            
        Raises:
            Exception: If token is invalid
        """
        try:
            session_doc = self.db.collection('sessions').document(user_id).get()
            if not session_doc.exists:
                raise Exception("Session not found")
            
            session_data = session_doc.to_dict()
            stored_csrf_token = session_data.get('csrfToken')
            
            if not stored_csrf_token or stored_csrf_token != csrf_token:
                raise Exception("Invalid CSRF token")
            
            return True
        except Exception as e:
            raise Exception(f"CSRF verification failed: {str(e)}")
    
    def update_last_activity(self, user_id):
        """
        Update last activity timestamp for session
        
        Args:
            user_id (str): User ID
        """
        try:
            session_ref = self.db.collection('sessions').document(user_id)
            session_ref.update({
                'lastActivity': datetime.utcnow()
            })
        except Exception as e:
            print(f"Error updating last activity: {str(e)}")
    
    def invalidate_session(self, user_id):
        """
        Invalidate user session
        
        Args:
            user_id (str): User ID
        """
        try:
            self.db.collection('sessions').document(user_id).delete()
        except Exception as e:
            print(f"Error invalidating session: {str(e)}")
    
    def invalidate_all_sessions(self, user_id):
        """
        Invalidate all sessions for a user (security measure)
        
        Args:
            user_id (str): User ID
        """
        try:
            # Delete session document
            self.db.collection('sessions').document(user_id).delete()
            
            # Could also maintain a blacklist of tokens if needed
            print(f"All sessions invalidated for user {user_id}")
        except Exception as e:
            print(f"Error invalidating all sessions: {str(e)}")
    
    def create_access_token_with_activity(self, user_id, user_data):
        """
        Create new access token with updated activity timestamp
        
        Args:
            user_id (str): User ID
            user_data (dict): User information
            
        Returns:
            str: New access token
        """
        try:
            access_expiration = datetime.utcnow() + timedelta(minutes=self.jwt_expiration_minutes)
            
            access_payload = {
                'user_id': user_id,
                'email': user_data.get('email'),
                'role': user_data.get('role'),
                'exp': access_expiration,
                'iat': datetime.utcnow(),
                'type': 'access',
                'last_activity': datetime.utcnow().isoformat()
            }
            
            access_token = jwt.encode(access_payload, self.jwt_secret, algorithm=self.jwt_algorithm)
            
            # Update last activity in session
            self.update_last_activity(user_id)
            
            return access_token
        except Exception as e:
            raise Exception(f"Access token creation failed: {str(e)}")
    
    def send_security_alert(self, user_id, event_type, details):
        """
        Send security alert email to user
        
        Args:
            user_id (str): User ID
            event_type (str): Type of security event
            details (dict): Event details
        """
        # TODO: Implement email sending (will be done with audit logger)
        print(f"Security alert for user {user_id}: {event_type}")
        print(f"Details: {details}")


# Singleton instance
auth_service = AuthService()
