"""
Simple Auth Service for Testing
Minimal authentication service for device fingerprinting testing
"""

import jwt
import os
from datetime import datetime, timedelta
from firebase_admin import firestore


class AuthService:
    """Simple authentication service for testing"""
    
    def __init__(self):
        self.db = firestore.client()
        self.jwt_secret = os.getenv('JWT_SECRET_KEY', 'dev_jwt_secret')
        self.jwt_algorithm = 'HS256'
    
    def verify_session_token(self, token, check_inactivity=True):
        """Verify JWT session token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            raise Exception("Token has expired")
        except jwt.InvalidTokenError:
            raise Exception("Invalid token")
    
    def update_last_activity(self, user_id):
        """Update user's last activity timestamp"""
        try:
            user_ref = self.db.collection('users').document(user_id)
            user_ref.set({
                'lastActivity': datetime.utcnow()
            }, merge=True)
        except Exception as e:
            print(f"Error updating last activity: {e}")


# Singleton instance
auth_service = AuthService()