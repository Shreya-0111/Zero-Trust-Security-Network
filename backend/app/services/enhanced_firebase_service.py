"""
Enhanced Firebase Service
Implements Firebase Authentication with custom claims, enhanced user management,
and comprehensive security features for the Zero Trust framework
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import firebase_admin
from firebase_admin import auth, firestore, storage
from firebase_admin.exceptions import FirebaseError
from app.utils.error_handler import handle_service_error
from app.services.audit_logger import AuditLogger

logger = logging.getLogger(__name__)

class EnhancedFirebaseService:
    """Enhanced Firebase service with custom claims and security features"""
    
    def __init__(self):
        self._db = None
        self._storage_client = None
        self.audit_logger = AuditLogger()
        
        # Role hierarchy for access control
        self.role_hierarchy = {
            'student': 1,
            'faculty': 2,
            'security_officer': 3,
            'admin': 4
        }
        
        # Security clearance levels
        self.security_clearance_levels = {
            'public': 1,
            'internal': 2,
            'confidential': 3,
            'secret': 4,
            'top_secret': 5
        }

    def get_db(self):
        if self._db is None:
            self._db = firestore.client()
        return self._db

    def get_storage_client(self):
        if self._storage_client is None:
            self._storage_client = storage.bucket()
        return self._storage_client
    
    @handle_service_error
    def create_user_with_enhanced_profile(self, user_data: Dict) -> Dict:
        """
        Create a new user with enhanced profile including risk assessment
        
        Args:
            user_data: User information including role, clearance, etc.
            
        Returns:
            Created user information
        """
        try:
            # Create Firebase Auth user
            user_record = auth.create_user(
                email=user_data['email'],
                password=user_data.get('password'),
                display_name=user_data.get('displayName'),
                disabled=False
            )
            
            # Set custom claims
            custom_claims = {
                'role': user_data.get('role', 'student'),
                'securityClearance': user_data.get('securityClearance', 1),
                'trustScore': 100,  # Start with full trust
                'department': user_data.get('department', ''),
                'isActive': True,
                'createdAt': datetime.utcnow().isoformat()
            }
            
            auth.set_custom_user_claims(user_record.uid, custom_claims)
            
            # Create enhanced user profile in Firestore
            user_profile = {
                'uid': user_record.uid,
                'email': user_data['email'],
                'displayName': user_data.get('displayName', ''),
                'role': user_data.get('role', 'student'),
                'department': user_data.get('department', ''),
                'securityClearance': user_data.get('securityClearance', 1),
                'isActive': True,
                'createdAt': datetime.utcnow(),
                'lastActivity': datetime.utcnow(),
                'riskProfile': {
                    'currentScore': 0,  # Start with low risk
                    'baselineEstablished': False,
                    'lastAssessment': datetime.utcnow(),
                    'riskFactors': [],
                    'behavioralBaseline': {
                        'keystrokeDynamics': {},
                        'mouseMovements': {},
                        'accessPatterns': {},
                        'locationHistory': []
                    }
                },
                'preferences': {
                    'notifications': True,
                    'securityAlerts': True,
                    'dataRetention': 'standard'
                },
                'mfaEnabled': False,
                'deviceCount': 0,
                'lastPasswordChange': datetime.utcnow(),
                'accountLocked': False,
                'failedLoginAttempts': 0
            }
            
            # Store user profile
            self.get_db().collection('users').document(user_record.uid).set(user_profile)
            
            # Log user creation
            self.audit_logger.log_event(
                event_type="user_creation",
                user_id=user_record.uid,
                action="create_user",
                resource="user_profile",
                result="success",
                details={
                    "role": user_data.get('role'),
                    "security_clearance": user_data.get('securityClearance'),
                    "department": user_data.get('department')
                },
                severity="medium"
            )
            
            logger.info(f"Enhanced user profile created: {user_record.uid}")
            
            return {
                "success": True,
                "uid": user_record.uid,
                "email": user_record.email,
                "role": user_data.get('role', 'student'),
                "securityClearance": user_data.get('securityClearance', 1)
            }
            
        except FirebaseError as e:
            logger.error(f"Firebase error creating user: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error creating enhanced user profile: {str(e)}")
            raise
    
    @handle_service_error
    def update_user_custom_claims(self, uid: str, claims_update: Dict) -> bool:
        """
        Update user's custom claims in Firebase Auth
        
        Args:
            uid: User ID
            claims_update: Claims to update
            
        Returns:
            Success status
        """
        try:
            # Get current claims
            user_record = auth.get_user(uid)
            current_claims = user_record.custom_claims or {}
            
            # Merge with updates
            updated_claims = {**current_claims, **claims_update}
            
            # Set updated claims
            auth.set_custom_user_claims(uid, updated_claims)
            
            # Update Firestore profile
            user_ref = self.get_db().collection('users').document(uid)
            user_ref.update({
                'lastUpdated': datetime.utcnow(),
                **{k: v for k, v in claims_update.items() if k in ['role', 'securityClearance', 'trustScore']}
            })
            
            # Log claims update
            self.audit_logger.log_event(
                event_type="user_claims_update",
                user_id=uid,
                action="update_claims",
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
            logger.error(f"Error updating user claims: {str(e)}")
            raise
    
    @handle_service_error
    def update_user_risk_profile(self, uid: str, risk_data: Dict) -> bool:
        """
        Update user's risk profile with new assessment data
        
        Args:
            uid: User ID
            risk_data: Risk assessment data
            
        Returns:
            Success status
        """
        try:
            user_ref = self.get_db().collection('users').document(uid)
            user_doc = user_ref.get()
            
            if not user_doc.exists:
                logger.warning(f"User not found for risk profile update: {uid}")
                return False
            
            current_profile = user_doc.to_dict()
            current_risk = current_profile.get('riskProfile', {})
            
            # Update risk profile
            updated_risk_profile = {
                'currentScore': risk_data.get('score', current_risk.get('currentScore', 0)),
                'lastAssessment': datetime.utcnow(),
                'riskFactors': risk_data.get('factors', current_risk.get('riskFactors', [])),
                'baselineEstablished': risk_data.get('baselineEstablished', current_risk.get('baselineEstablished', False)),
                'behavioralBaseline': {
                    **current_risk.get('behavioralBaseline', {}),
                    **risk_data.get('behavioralBaseline', {})
                }
            }
            
            # Update Firestore
            user_ref.update({
                'riskProfile': updated_risk_profile,
                'lastActivity': datetime.utcnow()
            })
            
            # Update custom claims if risk score changed significantly
            new_score = risk_data.get('score')
            if new_score is not None:
                trust_score = max(0, min(100, 100 - new_score))  # Inverse relationship
                self.update_user_custom_claims(uid, {'trustScore': trust_score})
            
            logger.info(f"Updated risk profile for user {uid}: score={new_score}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating user risk profile: {str(e)}")
            raise
    
    @handle_service_error
    def get_users_by_role(self, role: str, include_inactive: bool = False) -> List[Dict]:
        """
        Get all users with a specific role
        
        Args:
            role: User role to filter by
            include_inactive: Whether to include inactive users
            
        Returns:
            List of user profiles
        """
        try:
            query = self.get_db().collection('users').where('role', '==', role)
            
            if not include_inactive:
                query = query.where('isActive', '==', True)
            
            users = query.get()
            
            user_list = []
            for user_doc in users:
                user_data = user_doc.to_dict()
                # Remove sensitive data
                safe_user_data = {
                    'uid': user_data.get('uid'),
                    'email': user_data.get('email'),
                    'displayName': user_data.get('displayName'),
                    'role': user_data.get('role'),
                    'department': user_data.get('department'),
                    'securityClearance': user_data.get('securityClearance'),
                    'isActive': user_data.get('isActive'),
                    'lastActivity': user_data.get('lastActivity'),
                    'riskScore': user_data.get('riskProfile', {}).get('currentScore', 0)
                }
                user_list.append(safe_user_data)
            
            return user_list
            
        except Exception as e:
            logger.error(f"Error getting users by role: {str(e)}")
            raise
    
    @handle_service_error
    def get_high_risk_users(self, risk_threshold: int = 70) -> List[Dict]:
        """
        Get users with high risk scores
        
        Args:
            risk_threshold: Minimum risk score to include
            
        Returns:
            List of high-risk user profiles
        """
        try:
            # Query users with high risk scores
            query = self.get_db().collection('users').where(
                'riskProfile.currentScore', '>=', risk_threshold
            ).where(
                'isActive', '==', True
            ).order_by('riskProfile.currentScore', direction=firestore.Query.DESCENDING)
            
            users = query.get()
            
            high_risk_users = []
            for user_doc in users:
                user_data = user_doc.to_dict()
                risk_profile = user_data.get('riskProfile', {})
                
                high_risk_user = {
                    'uid': user_data.get('uid'),
                    'email': user_data.get('email'),
                    'displayName': user_data.get('displayName'),
                    'role': user_data.get('role'),
                    'riskScore': risk_profile.get('currentScore', 0),
                    'riskFactors': risk_profile.get('riskFactors', []),
                    'lastAssessment': risk_profile.get('lastAssessment'),
                    'lastActivity': user_data.get('lastActivity')
                }
                high_risk_users.append(high_risk_user)
            
            return high_risk_users
            
        except Exception as e:
            logger.error(f"Error getting high-risk users: {str(e)}")
            raise
    
    @handle_service_error
    def archive_audit_logs_to_storage(self, days_old: int = 90) -> int:
        """
        Archive old audit logs to Cloud Storage
        
        Args:
            days_old: Archive logs older than this many days
            
        Returns:
            Number of logs archived
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days_old)
            
            # Query old audit logs
            query = self.get_db().collection('auditLogs').where(
                'timestamp', '<', cutoff_date
            ).limit(1000)  # Process in batches
            
            logs = query.get()
            archived_count = 0
            
            if not logs:
                return 0
            
            # Prepare archive data
            archive_data = []
            log_ids_to_delete = []
            
            for log_doc in logs:
                log_data = log_doc.to_dict()
                archive_data.append(log_data)
                log_ids_to_delete.append(log_doc.id)
            
            # Upload to Cloud Storage
            archive_filename = f"audit_logs_archive_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            blob = self.get_storage_client().blob(f"audit_archives/{archive_filename}")
            
            import json
            blob.upload_from_string(
                json.dumps(archive_data, default=str, indent=2),
                content_type='application/json'
            )
            
            # Delete from Firestore after successful upload
            batch = self.get_db().batch()
            for log_id in log_ids_to_delete:
                log_ref = self.get_db().collection('auditLogs').document(log_id)
                batch.delete(log_ref)
            
            batch.commit()
            archived_count = len(log_ids_to_delete)
            
            logger.info(f"Archived {archived_count} audit logs to {archive_filename}")
            return archived_count
            
        except Exception as e:
            logger.error(f"Error archiving audit logs: {str(e)}")
            raise
    
    @handle_service_error
    def store_ml_model(self, model_name: str, model_data: bytes, metadata: Dict) -> str:
        """
        Store ML model in Cloud Storage
        
        Args:
            model_name: Name of the model
            model_data: Serialized model data
            metadata: Model metadata
            
        Returns:
            Storage path of the model
        """
        try:
            # Upload model to Cloud Storage
            model_path = f"ml_models/{model_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pkl"
            blob = self.get_storage_client().blob(model_path)
            
            blob.upload_from_string(model_data, content_type='application/octet-stream')
            
            # Store metadata in Firestore
            model_metadata = {
                'name': model_name,
                'storagePath': model_path,
                'uploadedAt': datetime.utcnow(),
                'metadata': metadata,
                'isActive': True
            }
            
            self.get_db().collection('mlModels').add(model_metadata)
            
            logger.info(f"Stored ML model: {model_name} at {model_path}")
            return model_path
            
        except Exception as e:
            logger.error(f"Error storing ML model: {str(e)}")
            raise
    
    @handle_service_error
    def get_user_behavioral_baseline(self, uid: str) -> Optional[Dict]:
        """
        Get user's behavioral baseline data
        
        Args:
            uid: User ID
            
        Returns:
            Behavioral baseline data or None
        """
        try:
            user_ref = self.get_db().collection('users').document(uid)
            user_doc = user_ref.get()
            
            if not user_doc.exists:
                return None
            
            user_data = user_doc.to_dict()
            risk_profile = user_data.get('riskProfile', {})
            
            return risk_profile.get('behavioralBaseline', {})
            
        except Exception as e:
            logger.error(f"Error getting behavioral baseline: {str(e)}")
            raise
    
    @handle_service_error
    def update_user_behavioral_baseline(self, uid: str, baseline_data: Dict) -> bool:
        """
        Update user's behavioral baseline
        
        Args:
            uid: User ID
            baseline_data: New baseline data
            
        Returns:
            Success status
        """
        try:
            user_ref = self.get_db().collection('users').document(uid)
            
            # Update the behavioral baseline
            user_ref.update({
                'riskProfile.behavioralBaseline': baseline_data,
                'riskProfile.baselineEstablished': True,
                'riskProfile.lastAssessment': datetime.utcnow(),
                'lastActivity': datetime.utcnow()
            })
            
            logger.info(f"Updated behavioral baseline for user {uid}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating behavioral baseline: {str(e)}")
            raise
    
    @handle_service_error
    def cleanup_inactive_users(self, days_inactive: int = 365) -> int:
        """
        Mark users as inactive if they haven't been active for specified days
        
        Args:
            days_inactive: Days of inactivity threshold
            
        Returns:
            Number of users marked as inactive
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days_inactive)
            
            # Query inactive users
            query = self.get_db().collection('users').where(
                'lastActivity', '<', cutoff_date
            ).where(
                'isActive', '==', True
            )
            
            users = query.get()
            cleanup_count = 0
            
            batch = self.get_db().batch()
            for user_doc in users:
                user_ref = user_doc.reference
                batch.update(user_ref, {
                    'isActive': False,
                    'deactivatedAt': datetime.utcnow(),
                    'deactivationReason': 'inactivity'
                })
                cleanup_count += 1
            
            if cleanup_count > 0:
                batch.commit()
                logger.info(f"Marked {cleanup_count} users as inactive due to inactivity")
            
            return cleanup_count
            
        except Exception as e:
            logger.error(f"Error cleaning up inactive users: {str(e)}")
            raise
    
    @handle_service_error
    async def send_notification(self, user_id: str, notification_data: Dict) -> bool:
        """
        Send notification to a user (placeholder implementation)
        
        Args:
            user_id: User ID to send notification to
            notification_data: Notification data
            
        Returns:
            Success status
        """
        try:
            # For now, just log the notification
            # In a full implementation, this would send push notifications, emails, etc.
            logger.info(f"Notification for user {user_id}: {notification_data.get('title', 'No title')}")
            
            # Store notification in Firestore for the user to see in the UI
            notification = {
                'userId': user_id,
                'type': notification_data.get('type', 'info'),
                'title': notification_data.get('title', 'Notification'),
                'message': notification_data.get('message', ''),
                'data': notification_data,
                'isRead': False,
                'createdAt': datetime.utcnow(),
                'expiresAt': datetime.utcnow() + timedelta(days=30)
            }
            
            self.get_db().collection('notifications').add(notification)
            return True
            
        except Exception as e:
            logger.error(f"Error sending notification: {str(e)}")
            return False
    
    @handle_service_error
    async def broadcast_to_admins(self, notification_data: Dict) -> bool:
        """
        Broadcast notification to all admin users
        
        Args:
            notification_data: Notification data
            
        Returns:
            Success status
        """
        try:
            # Get all admin users
            admin_users = self.get_users_by_role('admin', include_inactive=False)
            
            # Send notification to each admin
            for admin_user in admin_users:
                await self.send_notification(admin_user['uid'], notification_data)
            
            logger.info(f"Broadcasted notification to {len(admin_users)} admin users")
            return True
            
        except Exception as e:
            logger.error(f"Error broadcasting to admins: {str(e)}")
            return False

# Global instance
enhanced_firebase_service = EnhancedFirebaseService()