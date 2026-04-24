"""
Firebase Admin SDK Integration Service
Handles Firebase Admin operations with enhanced security and custom claims management
"""

import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import firebase_admin
from firebase_admin import credentials, auth, firestore, storage
from firebase_admin.exceptions import FirebaseError
from app.models.enhanced_user import EnhancedUser, UserRole, SecurityClearanceLevel
from app.services.audit_logger import AuditLogger
from app.utils.error_handler import handle_service_error

logger = logging.getLogger(__name__)

class FirebaseAdminService:
    """Firebase Admin SDK service for backend operations"""
    
    def __init__(self):
        self.audit_logger = AuditLogger()
        self._initialize_firebase()
        self.db = firestore.client()
        self.storage_bucket = storage.bucket()
    
    def _initialize_firebase(self):
        """Initialize Firebase Admin SDK"""
        try:
            if not firebase_admin._apps:
                # Get credentials path from environment
                cred_path = os.getenv('FIREBASE_CREDENTIALS_PATH', './firebase-credentials.json')
                
                if os.path.exists(cred_path):
                    cred = credentials.Certificate(cred_path)
                    firebase_admin.initialize_app(cred, {
                        'storageBucket': 'zero-trust-security-framework.appspot.com'
                    })
                    logger.info("Firebase Admin SDK initialized successfully")
                else:
                    logger.error(f"Firebase credentials file not found: {cred_path}")
                    raise FileNotFoundError(f"Firebase credentials not found: {cred_path}")
            
        except Exception as e:
            logger.error(f"Failed to initialize Firebase Admin SDK: {str(e)}")
            raise
    
    @handle_service_error
    def create_user_with_custom_claims(self, user_data: Dict) -> Dict:
        """
        Create a new user with custom claims and enhanced profile
        
        Args:
            user_data: User creation data
            
        Returns:
            Created user information
        """
        try:
            # Create Firebase Auth user
            user_record = auth.create_user(
                email=user_data['email'],
                password=user_data.get('password'),
                display_name=user_data.get('displayName', ''),
                disabled=False
            )
            
            # Set custom claims
            custom_claims = {
                'role': user_data.get('role', 'student'),
                'securityClearance': user_data.get('securityClearance', 1),
                'trustScore': 100,
                'department': user_data.get('department', ''),
                'isActive': True,
                'createdAt': datetime.utcnow().isoformat(),
                'deviceCount': 0,
                'riskScore': 0
            }
            
            auth.set_custom_user_claims(user_record.uid, custom_claims)
            
            # Create enhanced user profile
            enhanced_user = EnhancedUser(
                uid=user_record.uid,
                email=user_data['email'],
                display_name=user_data.get('displayName', ''),
                role=UserRole(user_data.get('role', 'student')),
                department=user_data.get('department', ''),
                security_clearance=SecurityClearanceLevel(user_data.get('securityClearance', 1))
            )
            
            # Store in Firestore
            self.db.collection('users').document(user_record.uid).set(enhanced_user.to_dict())
            
            # Log user creation
            self.audit_logger.log_event(
                event_type="user_creation",
                user_id=user_record.uid,
                action="create_user_with_claims",
                resource="user_profile",
                result="success",
                details={
                    "email": user_data['email'],
                    "role": user_data.get('role'),
                    "security_clearance": user_data.get('securityClearance'),
                    "department": user_data.get('department')
                },
                severity="medium"
            )
            
            logger.info(f"Created user with custom claims: {user_record.uid}")
            
            return {
                "success": True,
                "uid": user_record.uid,
                "email": user_record.email,
                "customClaims": custom_claims
            }
            
        except FirebaseError as e:
            logger.error(f"Firebase error creating user: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error creating user with custom claims: {str(e)}")
            raise
    
    @handle_service_error
    def update_user_custom_claims(self, uid: str, claims_update: Dict) -> bool:
        """
        Update user's custom claims
        
        Args:
            uid: User ID
            claims_update: Claims to update
            
        Returns:
            Success status
        """
        try:
            # Get current user record
            user_record = auth.get_user(uid)
            current_claims = user_record.custom_claims or {}
            
            # Merge with updates
            updated_claims = {**current_claims, **claims_update}
            
            # Set updated claims
            auth.set_custom_user_claims(uid, updated_claims)
            
            # Update Firestore profile if relevant fields changed
            firestore_updates = {}
            if 'role' in claims_update:
                firestore_updates['role'] = claims_update['role']
            if 'securityClearance' in claims_update:
                firestore_updates['securityClearance'] = claims_update['securityClearance']
            if 'trustScore' in claims_update:
                firestore_updates['riskProfile.trustScore'] = claims_update['trustScore']
            if 'riskScore' in claims_update:
                firestore_updates['riskProfile.currentScore'] = claims_update['riskScore']
            
            if firestore_updates:
                firestore_updates['lastActivity'] = datetime.utcnow()
                self.db.collection('users').document(uid).update(firestore_updates)
            
            # Log claims update
            self.audit_logger.log_event(
                event_type="user_claims_update",
                user_id=uid,
                action="update_custom_claims",
                resource="user_claims",
                result="success",
                details={"updated_claims": claims_update},
                severity="medium"
            )
            
            logger.info(f"Updated custom claims for user {uid}: {claims_update}")
            return True
            
        except FirebaseError as e:
            logger.error(f"Firebase error updating claims: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error updating custom claims: {str(e)}")
            raise
    
    @handle_service_error
    def verify_and_decode_token(self, id_token: str) -> Dict:
        """
        Verify Firebase ID token and return decoded claims
        
        Args:
            id_token: Firebase ID token
            
        Returns:
            Decoded token with custom claims
        """
        try:
            # Verify the token
            decoded_token = auth.verify_id_token(id_token)
            
            # Get user record to include custom claims
            user_record = auth.get_user(decoded_token['uid'])
            
            # Merge standard claims with custom claims
            full_claims = {
                **decoded_token,
                **(user_record.custom_claims or {})
            }
            
            return full_claims
            
        except FirebaseError as e:
            logger.error(f"Firebase error verifying token: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error verifying token: {str(e)}")
            raise
    
    @handle_service_error
    def get_user_with_claims(self, uid: str) -> Dict:
        """
        Get user record with custom claims
        
        Args:
            uid: User ID
            
        Returns:
            User record with custom claims
        """
        try:
            user_record = auth.get_user(uid)
            
            return {
                "uid": user_record.uid,
                "email": user_record.email,
                "displayName": user_record.display_name,
                "disabled": user_record.disabled,
                "emailVerified": user_record.email_verified,
                "customClaims": user_record.custom_claims or {},
                "creationTimestamp": user_record.user_metadata.creation_timestamp,
                "lastSignInTimestamp": user_record.user_metadata.last_sign_in_timestamp
            }
            
        except FirebaseError as e:
            logger.error(f"Firebase error getting user: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error getting user with claims: {str(e)}")
            raise
    
    @handle_service_error
    def disable_user_account(self, uid: str, reason: str = "security_violation") -> bool:
        """
        Disable user account and revoke tokens
        
        Args:
            uid: User ID
            reason: Reason for disabling
            
        Returns:
            Success status
        """
        try:
            # Disable user in Firebase Auth
            auth.update_user(uid, disabled=True)
            
            # Revoke all refresh tokens
            auth.revoke_refresh_tokens(uid)
            
            # Update Firestore profile
            self.db.collection('users').document(uid).update({
                'isActive': False,
                'disabledAt': datetime.utcnow(),
                'disabledReason': reason,
                'lastActivity': datetime.utcnow()
            })
            
            # Update custom claims
            self.update_user_custom_claims(uid, {'isActive': False})
            
            # Log account disable
            self.audit_logger.log_event(
                event_type="account_disabled",
                user_id=uid,
                action="disable_account",
                resource="user_account",
                result="success",
                details={"reason": reason},
                severity="high"
            )
            
            logger.info(f"Disabled user account: {uid}, reason: {reason}")
            return True
            
        except FirebaseError as e:
            logger.error(f"Firebase error disabling user: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error disabling user account: {str(e)}")
            raise
    
    @handle_service_error
    def enable_user_account(self, uid: str) -> bool:
        """
        Enable user account
        
        Args:
            uid: User ID
            
        Returns:
            Success status
        """
        try:
            # Enable user in Firebase Auth
            auth.update_user(uid, disabled=False)
            
            # Update Firestore profile
            self.db.collection('users').document(uid).update({
                'isActive': True,
                'enabledAt': datetime.utcnow(),
                'lastActivity': datetime.utcnow()
            })
            
            # Update custom claims
            self.update_user_custom_claims(uid, {'isActive': True})
            
            # Log account enable
            self.audit_logger.log_event(
                event_type="account_enabled",
                user_id=uid,
                action="enable_account",
                resource="user_account",
                result="success",
                details={},
                severity="medium"
            )
            
            logger.info(f"Enabled user account: {uid}")
            return True
            
        except FirebaseError as e:
            logger.error(f"Firebase error enabling user: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error enabling user account: {str(e)}")
            raise
    
    @handle_service_error
    def bulk_update_user_claims(self, user_updates: List[Dict]) -> Dict:
        """
        Bulk update custom claims for multiple users
        
        Args:
            user_updates: List of user updates with uid and claims
            
        Returns:
            Update results
        """
        try:
            success_count = 0
            error_count = 0
            errors = []
            
            for update in user_updates:
                try:
                    uid = update['uid']
                    claims = update['claims']
                    
                    self.update_user_custom_claims(uid, claims)
                    success_count += 1
                    
                except Exception as e:
                    error_count += 1
                    errors.append({
                        'uid': update.get('uid'),
                        'error': str(e)
                    })
                    logger.error(f"Error updating claims for user {update.get('uid')}: {str(e)}")
            
            # Log bulk update
            self.audit_logger.log_event(
                event_type="bulk_claims_update",
                user_id="system",
                action="bulk_update_claims",
                resource="user_claims",
                result="partial" if error_count > 0 else "success",
                details={
                    "total_users": len(user_updates),
                    "success_count": success_count,
                    "error_count": error_count
                },
                severity="medium"
            )
            
            return {
                "success": True,
                "totalUsers": len(user_updates),
                "successCount": success_count,
                "errorCount": error_count,
                "errors": errors
            }
            
        except Exception as e:
            logger.error(f"Error in bulk update user claims: {str(e)}")
            raise
    
    @handle_service_error
    def cleanup_expired_tokens(self, days_old: int = 30) -> int:
        """
        Revoke refresh tokens for inactive users
        
        Args:
            days_old: Revoke tokens older than this many days
            
        Returns:
            Number of users processed
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days_old)
            
            # Query inactive users
            query = self.db.collection('users').where(
                'lastActivity', '<', cutoff_date
            ).where(
                'isActive', '==', True
            ).limit(100)  # Process in batches
            
            users = query.get()
            processed_count = 0
            
            for user_doc in users:
                try:
                    uid = user_doc.id
                    
                    # Revoke refresh tokens
                    auth.revoke_refresh_tokens(uid)
                    processed_count += 1
                    
                    logger.info(f"Revoked tokens for inactive user: {uid}")
                    
                except Exception as e:
                    logger.error(f"Error revoking tokens for user {uid}: {str(e)}")
            
            if processed_count > 0:
                # Log cleanup operation
                self.audit_logger.log_event(
                    event_type="token_cleanup",
                    user_id="system",
                    action="cleanup_expired_tokens",
                    resource="user_tokens",
                    result="success",
                    details={"processed_count": processed_count},
                    severity="low"
                )
            
            return processed_count
            
        except Exception as e:
            logger.error(f"Error cleaning up expired tokens: {str(e)}")
            raise
    
    @handle_service_error
    def get_users_by_custom_claim(self, claim_key: str, claim_value: Any) -> List[Dict]:
        """
        Get users by custom claim value (requires iterating through users)
        
        Args:
            claim_key: Custom claim key
            claim_value: Custom claim value
            
        Returns:
            List of matching users
        """
        try:
            # Note: Firebase doesn't support querying by custom claims directly
            # We need to use Firestore for efficient querying
            
            field_mapping = {
                'role': 'role',
                'securityClearance': 'securityClearance',
                'trustScore': 'riskProfile.trustScore',
                'riskScore': 'riskProfile.currentScore',
                'isActive': 'isActive'
            }
            
            firestore_field = field_mapping.get(claim_key)
            if not firestore_field:
                logger.warning(f"No Firestore mapping for claim: {claim_key}")
                return []
            
            # Query Firestore
            query = self.db.collection('users').where(firestore_field, '==', claim_value)
            users = query.get()
            
            user_list = []
            for user_doc in users:
                user_data = user_doc.to_dict()
                
                # Get Firebase Auth record for complete info
                try:
                    auth_record = auth.get_user(user_doc.id)
                    user_info = {
                        "uid": auth_record.uid,
                        "email": auth_record.email,
                        "displayName": auth_record.display_name,
                        "disabled": auth_record.disabled,
                        "customClaims": auth_record.custom_claims or {},
                        "firestoreData": user_data
                    }
                    user_list.append(user_info)
                    
                except Exception as e:
                    logger.error(f"Error getting auth record for user {user_doc.id}: {str(e)}")
            
            return user_list
            
        except Exception as e:
            logger.error(f"Error getting users by custom claim: {str(e)}")
            raise
    
    @handle_service_error
    def archive_user_data(self, uid: str) -> str:
        """
        Archive user data to Cloud Storage before deletion
        
        Args:
            uid: User ID
            
        Returns:
            Archive file path
        """
        try:
            # Get user data from Firestore
            user_doc = self.db.collection('users').document(uid).get()
            if not user_doc.exists:
                raise ValueError(f"User not found: {uid}")
            
            user_data = user_doc.to_dict()
            
            # Get Firebase Auth record
            try:
                auth_record = auth.get_user(uid)
                auth_data = {
                    "uid": auth_record.uid,
                    "email": auth_record.email,
                    "displayName": auth_record.display_name,
                    "disabled": auth_record.disabled,
                    "emailVerified": auth_record.email_verified,
                    "customClaims": auth_record.custom_claims,
                    "creationTimestamp": auth_record.user_metadata.creation_timestamp,
                    "lastSignInTimestamp": auth_record.user_metadata.last_sign_in_timestamp
                }
            except:
                auth_data = None
            
            # Create archive data
            archive_data = {
                "archivedAt": datetime.utcnow().isoformat(),
                "uid": uid,
                "firestoreData": user_data,
                "authData": auth_data
            }
            
            # Upload to Cloud Storage
            archive_filename = f"user_archives/{uid}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            blob = self.storage_bucket.blob(archive_filename)
            
            import json
            blob.upload_from_string(
                json.dumps(archive_data, default=str, indent=2),
                content_type='application/json'
            )
            
            logger.info(f"Archived user data: {uid} to {archive_filename}")
            return archive_filename
            
        except Exception as e:
            logger.error(f"Error archiving user data: {str(e)}")
            raise