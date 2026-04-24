"""
Visitor Service

Handles visitor registration, session lifecycle management, route compliance monitoring,
and credential generation for the Enhanced Zero Trust Security Framework.
"""

import os
import uuid
import secrets
import string
import base64
import qrcode
import jwt
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any, Tuple
from io import BytesIO
from PIL import Image
import logging

from flask import has_request_context, request

from google.cloud import firestore
from google.cloud import storage
from werkzeug.security import generate_password_hash
from cryptography.fernet import Fernet

from ..models.visitor import Visitor, VisitorRegistrationRequest, VisitorCredentials, AssignedRoute, AccessLogEntry
from ..services.firebase_admin_service import FirebaseAdminService
from ..services.enhanced_firebase_service import EnhancedFirebaseService
from ..utils.error_handler import ValidationError, NotFoundError, AuthorizationError

logger = logging.getLogger(__name__)


class VisitorService:
    """
    Visitor Service
    
    Manages visitor registration, session lifecycle, route compliance monitoring,
    and real-time notifications for hosts and administrators.
    """
    
    def __init__(self):
        from app.firebase_config import get_firestore_client
        self.db = get_firestore_client()
        # Use Firebase Admin SDK storage instead of Google Cloud Storage client
        from firebase_admin import storage
        self.storage_bucket = storage.bucket()
        self.firebase_service = FirebaseAdminService()
        self.enhanced_firebase = EnhancedFirebaseService()
        
        # Initialize encryption for credentials
        self.encryption_key = os.getenv('VISITOR_ENCRYPTION_KEY', Fernet.generate_key())
        if isinstance(self.encryption_key, str):
            self.encryption_key = self.encryption_key.encode()
        self.cipher_suite = Fernet(self.encryption_key)
        
        # JWT secret for access tokens
        self.jwt_secret = os.getenv('JWT_SECRET', 'your-secret-key')

    
    async def register_visitor(
        self,
        registration_data: VisitorRegistrationRequest,
        photo_file: Any,
        host_user_id: str
    ) -> Visitor:
        """
        Register a new visitor with photo upload and credential generation
        
        Args:
            registration_data: Visitor registration information
            photo_file: Uploaded photo file
            host_user_id: ID of the host (faculty/admin) registering the visitor
            
        Returns:
            Visitor: Created visitor object with credentials
            
        Raises:
            ValidationError: If registration data is invalid
            AuthorizationError: If host doesn't have permission to register visitors
        """
        try:
            # Validate host permissions
            await self._validate_host_permissions(host_user_id)
            
            # Generate unique visitor ID
            visitor_id = str(uuid.uuid4())
            
            # Upload visitor photo
            photo_url = await self._upload_visitor_photo(visitor_id, photo_file)
            
            # Generate visitor credentials
            credentials = await self._generate_visitor_credentials(visitor_id, registration_data.name)
            
            # Calculate expected exit time
            entry_time = datetime.utcnow()
            expected_exit_time = entry_time + timedelta(hours=registration_data.expected_duration)
            
            # Create visitor object
            visitor = Visitor(
                visitor_id=visitor_id,
                name=registration_data.name,
                email=registration_data.email,
                phone=registration_data.phone,
                photo=photo_url,
                host_id=registration_data.host_id,
                host_name=registration_data.host_name,
                host_department=registration_data.host_department,
                visit_purpose=registration_data.visit_purpose,
                entry_time=entry_time,
                expected_exit_time=expected_exit_time,
                max_duration=registration_data.expected_duration,
                assigned_route=registration_data.assigned_route,
                credentials=credentials,
                status="active"
            )
            
            # Store visitor in Firestore
            await self._store_visitor(visitor)
            
            # Send notification to host
            await self._notify_host_registration(visitor)
            
            # Log visitor registration
            await self._log_visitor_event(visitor_id, "visitor_registered", {
                "host_id": host_user_id,
                "duration": registration_data.expected_duration,
                "purpose": registration_data.visit_purpose
            })
            
            logger.info(f"Visitor {visitor_id} registered successfully by host {host_user_id}")
            return visitor
            
        except Exception as e:
            logger.error(f"Error registering visitor: {str(e)}")
            raise ValidationError(f"Failed to register visitor: {str(e)}")
    
    async def get_visitor(self, visitor_id: str, requesting_user_id: str) -> Visitor:
        """
        Get visitor information with access control
        
        Args:
            visitor_id: Visitor ID to retrieve
            requesting_user_id: ID of user requesting visitor information
            
        Returns:
            Visitor: Visitor object
            
        Raises:
            NotFoundError: If visitor doesn't exist
            AuthorizationError: If user doesn't have access to visitor information
        """
        try:
            # Get visitor from Firestore
            visitor_ref = self.db.collection('visitors').document(visitor_id)
            visitor_doc = visitor_ref.get()
            
            if not visitor_doc.exists:
                raise NotFoundError(f"Visitor {visitor_id} not found")
            
            visitor_data = visitor_doc.to_dict()
            visitor = Visitor(**visitor_data)
            
            # Check access permissions
            await self._validate_visitor_access(visitor, requesting_user_id)
            
            return visitor
            
        except Exception as e:
            if isinstance(e, (NotFoundError, AuthorizationError)):
                raise
            logger.error(f"Error retrieving visitor {visitor_id}: {str(e)}")
            raise ValidationError(f"Failed to retrieve visitor: {str(e)}")
    
    async def get_host_visitors(self, host_id: str, status_filter: Optional[str] = None) -> List[Visitor]:
        """
        Get all visitors for a specific host
        
        Args:
            host_id: Host user ID
            status_filter: Optional status filter ('active', 'completed', 'expired', 'terminated')
            
        Returns:
            List[Visitor]: List of visitors for the host
        """
        try:
            query = self.db.collection('visitors').where('host_id', '==', host_id)
            
            if status_filter:
                query = query.where('status', '==', status_filter)
            
            # Order by entry time (most recent first)
            query = query.order_by('entry_time', direction=firestore.Query.DESCENDING)
            
            visitors = []
            docs = query.stream()
            
            for doc in docs:
                visitor_data = doc.to_dict()
                visitor = Visitor(**visitor_data)
                visitors.append(visitor)
            
            return visitors
            
        except Exception as e:
            logger.error(f"Error retrieving visitors for host {host_id}: {str(e)}")
            raise ValidationError(f"Failed to retrieve visitors: {str(e)}")
    
    async def track_visitor_access(
        self,
        visitor_id: str,
        resource_segment: str,
        action: str,
        requesting_user_id: str,
        risk_score: Optional[float] = None
    ) -> bool:
        """
        Track visitor access to resources and check route compliance
        
        Args:
            visitor_id: Visitor ID
            resource_segment: Resource segment being accessed
            action: Action being performed
            requesting_user_id: User ID making the access request
            risk_score: Optional risk score for the access
            
        Returns:
            bool: Whether access is approved
        """
        try:
            # Get visitor
            visitor = await self.get_visitor(visitor_id, requesting_user_id)
            
            # Check if session is active
            if not visitor.is_session_active():
                await self._log_visitor_event(visitor_id, "access_denied_expired", {
                    "resource_segment": resource_segment,
                    "action": action,
                    "reason": "session_expired"
                })
                return False
            
            # Check route compliance
            approved = resource_segment in visitor.assigned_route.allowed_segments
            
            # Add access log entry
            visitor.add_access_log_entry(resource_segment, action, approved, risk_score)
            
            # Update visitor in Firestore
            await self._update_visitor(visitor)
            
            # Check for route violations
            if not approved:
                await self._handle_route_violation(visitor, resource_segment, action)
            
            # Log access attempt
            await self._log_visitor_event(visitor_id, "resource_access", {
                "resource_segment": resource_segment,
                "action": action,
                "approved": approved,
                "risk_score": risk_score,
                "compliance_score": visitor.route_compliance.compliance_score
            })
            
            return approved
            
        except Exception as e:
            logger.error(f"Error tracking visitor access: {str(e)}")
            return False
    
    async def extend_visitor_session(
        self,
        visitor_id: str,
        additional_hours: int,
        reason: str,
        requesting_host_id: str,
        approving_admin_id: str
    ) -> Visitor:
        """
        Extend visitor session with host request and admin approval
        
        Args:
            visitor_id: Visitor ID
            additional_hours: Additional hours to grant (1-4)
            reason: Reason for extension
            requesting_host_id: Host requesting the extension
            approving_admin_id: Admin approving the extension
            
        Returns:
            Visitor: Updated visitor object
            
        Raises:
            ValidationError: If extension parameters are invalid
            AuthorizationError: If requesting user doesn't have permission
        """
        try:
            # Get visitor
            visitor = await self.get_visitor(visitor_id, requesting_host_id)
            
            # Validate that requesting user is the host
            if visitor.host_id != requesting_host_id:
                raise AuthorizationError("Only the assigned host can request session extensions")
            
            # Validate admin permissions
            await self._validate_admin_permissions(approving_admin_id)
            
            # Extend session
            visitor.extend_session(additional_hours, requesting_host_id, approving_admin_id, reason)
            
            # Update visitor in Firestore
            await self._update_visitor(visitor)
            
            # Notify host and visitor
            await self._notify_session_extension(visitor, additional_hours, reason)
            
            # Log extension
            await self._log_visitor_event(visitor_id, "session_extended", {
                "additional_hours": additional_hours,
                "reason": reason,
                "requested_by": requesting_host_id,
                "approved_by": approving_admin_id,
                "new_exit_time": visitor.expected_exit_time.isoformat()
            })
            
            logger.info(f"Visitor {visitor_id} session extended by {additional_hours} hours")
            return visitor
            
        except Exception as e:
            if isinstance(e, (ValidationError, AuthorizationError)):
                raise
            logger.error(f"Error extending visitor session: {str(e)}")
            raise ValidationError(f"Failed to extend session: {str(e)}")
    
    async def terminate_visitor_session(
        self,
        visitor_id: str,
        reason: str,
        terminating_user_id: str
    ) -> Visitor:
        """
        Terminate visitor session manually
        
        Args:
            visitor_id: Visitor ID
            reason: Reason for termination
            terminating_user_id: User ID terminating the session
            
        Returns:
            Visitor: Updated visitor object
        """
        try:
            # Get visitor
            visitor = await self.get_visitor(visitor_id, terminating_user_id)
            
            # Validate permissions (host or admin can terminate)
            await self._validate_termination_permissions(visitor, terminating_user_id)
            
            # Terminate session
            visitor.terminate_session(reason)
            
            # Update visitor in Firestore
            await self._update_visitor(visitor)
            
            # Notify host and administrators
            await self._notify_session_termination(visitor, reason, terminating_user_id)
            
            # Log termination
            await self._log_visitor_event(visitor_id, "session_terminated", {
                "reason": reason,
                "terminated_by": terminating_user_id,
                "termination_time": visitor.actual_exit_time.isoformat()
            })
            
            logger.info(f"Visitor {visitor_id} session terminated by {terminating_user_id}")
            return visitor
            
        except Exception as e:
            if isinstance(e, (ValidationError, AuthorizationError)):
                raise
            logger.error(f"Error terminating visitor session: {str(e)}")
            raise ValidationError(f"Failed to terminate session: {str(e)}")
    
    async def check_expired_sessions(self) -> List[str]:
        """
        Check for expired visitor sessions and auto-terminate them
        
        Returns:
            List[str]: List of visitor IDs that were auto-terminated
        """
        try:
            now = datetime.utcnow()
            
            # Query for active visitors with expired sessions
            query = (self.db.collection('visitors')
                    .where('status', '==', 'active')
                    .where('expected_exit_time', '<=', now))
            
            expired_visitors = []
            docs = query.stream()
            
            for doc in docs:
                visitor_data = doc.to_dict()
                visitor = Visitor(**visitor_data)
                
                # Auto-terminate expired session
                visitor.terminate_session("Automatic expiration")
                await self._update_visitor(visitor)
                
                # Notify host
                await self._notify_session_expiration(visitor)
                
                # Log expiration
                await self._log_visitor_event(visitor.visitor_id, "session_expired", {
                    "expected_exit_time": visitor.expected_exit_time.isoformat(),
                    "actual_termination_time": visitor.actual_exit_time.isoformat()
                })
                
                expired_visitors.append(visitor.visitor_id)
            
            if expired_visitors:
                logger.info(f"Auto-terminated {len(expired_visitors)} expired visitor sessions")
            
            return expired_visitors
            
        except Exception as e:
            logger.error(f"Error checking expired sessions: {str(e)}")
            return []
    
    async def get_visitor_compliance_report(self, visitor_id: str, requesting_user_id: str) -> Dict[str, Any]:
        """
        Generate compliance report for a visitor
        
        Args:
            visitor_id: Visitor ID
            requesting_user_id: User requesting the report
            
        Returns:
            Dict[str, Any]: Compliance report data
        """
        try:
            visitor = await self.get_visitor(visitor_id, requesting_user_id)
            
            # Calculate compliance metrics
            total_accesses = len(visitor.access_log)
            approved_accesses = sum(1 for entry in visitor.access_log if entry.approved)
            denied_accesses = total_accesses - approved_accesses
            
            # Route deviation analysis
            deviations = visitor.route_compliance.deviations
            high_severity_deviations = [d for d in deviations if d.get('severity') == 'high']
            
            # Time analysis
            session_duration = (visitor.actual_exit_time or datetime.utcnow()) - visitor.entry_time
            
            report = {
                "visitor_id": visitor_id,
                "visitor_name": visitor.name,
                "host_name": visitor.host_name,
                "session_summary": {
                    "entry_time": visitor.entry_time.isoformat(),
                    "expected_exit_time": visitor.expected_exit_time.isoformat(),
                    "actual_exit_time": visitor.actual_exit_time.isoformat() if visitor.actual_exit_time else None,
                    "session_duration": str(session_duration),
                    "status": visitor.status
                },
                "access_summary": {
                    "total_accesses": total_accesses,
                    "approved_accesses": approved_accesses,
                    "denied_accesses": denied_accesses,
                    "approval_rate": (approved_accesses / total_accesses * 100) if total_accesses > 0 else 100
                },
                "compliance_metrics": {
                    "overall_score": visitor.route_compliance.compliance_score,
                    "total_deviations": len(deviations),
                    "high_severity_deviations": len(high_severity_deviations),
                    "last_compliance_check": visitor.route_compliance.last_compliance_check.isoformat()
                },
                "route_assignment": {
                    "allowed_segments": visitor.assigned_route.allowed_segments,
                    "restricted_areas": visitor.assigned_route.restricted_areas,
                    "route_description": visitor.assigned_route.route_description
                },
                "extensions": [
                    {
                        "additional_hours": ext.additional_hours,
                        "reason": ext.reason,
                        "approved_by": ext.approved_by,
                        "timestamp": ext.timestamp.isoformat()
                    }
                    for ext in visitor.session_extensions
                ],
                "alerts": visitor.alerts,
                "generated_at": datetime.utcnow().isoformat()
            }
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating compliance report: {str(e)}")
            raise ValidationError(f"Failed to generate report: {str(e)}")
    
    # Private helper methods
    
    async def _validate_host_permissions(self, user_id: str):
        """Validate that user has permission to register visitors"""
        user_doc = self.db.collection('users').document(user_id).get()
        if not user_doc.exists:
            if os.getenv("FLASK_ENV", "development") == "development" and has_request_context():
                role = getattr(request, "user_role", None)
                if role in ['faculty', 'admin']:
                    return
            raise AuthorizationError("User not found")
        
        user_data = user_doc.to_dict()
        if user_data.get('role') not in ['faculty', 'admin']:
            raise AuthorizationError("Only faculty and administrators can register visitors")
    
    async def _validate_admin_permissions(self, user_id: str):
        """Validate that user has admin permissions"""
        user_doc = self.db.collection('users').document(user_id).get()
        if not user_doc.exists:
            raise AuthorizationError("User not found")
        
        user_data = user_doc.to_dict()
        if user_data.get('role') != 'admin':
            raise AuthorizationError("Admin permissions required")
    
    async def _validate_visitor_access(self, visitor: Visitor, user_id: str):
        """Validate that user has access to visitor information"""
        user_doc = self.db.collection('users').document(user_id).get()
        if not user_doc.exists:
            raise AuthorizationError("User not found")
        
        user_data = user_doc.to_dict()
        user_role = user_data.get('role')
        
        # Admin can access all visitors, host can access their own visitors
        if user_role == 'admin' or visitor.host_id == user_id:
            return
        
        raise AuthorizationError("Access denied to visitor information")
    
    async def _validate_termination_permissions(self, visitor: Visitor, user_id: str):
        """Validate that user can terminate visitor session"""
        user_doc = self.db.collection('users').document(user_id).get()
        if not user_doc.exists:
            raise AuthorizationError("User not found")
        
        user_data = user_doc.to_dict()
        user_role = user_data.get('role')
        
        # Admin or host can terminate
        if user_role == 'admin' or visitor.host_id == user_id:
            return
        
        raise AuthorizationError("Permission denied to terminate visitor session")
    
    async def _upload_visitor_photo(self, visitor_id: str, photo_file: Any) -> str:
        """Upload visitor photo to Cloud Storage"""
        try:
            print(f"📸 Starting photo upload for visitor {visitor_id}")
            print(f"📸 Photo file info: {getattr(photo_file, 'filename', 'unknown')}, size: {getattr(photo_file, 'content_length', 'unknown')}")
            
            # In development mode, always use placeholder
            if os.getenv('FLASK_ENV') == 'development':
                placeholder_url = f"https://via.placeholder.com/200x200/4f46e5/ffffff?text=Visitor+Photo"
                print(f"🔧 Development mode: Using placeholder URL: {placeholder_url}")
                return placeholder_url
            
            # Use Firebase Admin SDK storage bucket directly
            bucket = self.storage_bucket
            
            # Generate unique filename
            filename = f"visitor-photos/{visitor_id}/{uuid.uuid4()}.jpg"
            blob = bucket.blob(filename)
            
            print(f"📸 Uploading to: {filename}")
            
            # Reset file pointer to beginning
            if hasattr(photo_file, 'seek'):
                photo_file.seek(0)
            
            # Upload file
            blob.upload_from_file(photo_file, content_type='image/jpeg')
            
            # Make blob publicly readable
            blob.make_public()
            
            photo_url = blob.public_url
            print(f"📸 Photo uploaded successfully: {photo_url}")
            
            return photo_url
            
        except Exception as e:
            logger.error(f"Error uploading visitor photo: {str(e)}")
            print(f"❌ Photo upload failed: {str(e)}")
            
            # Always return a placeholder URL in case of failure
            placeholder_url = f"https://via.placeholder.com/200x200/ff0000/ffffff?text=Photo+Upload+Failed"
            print(f"🔧 Using placeholder URL: {placeholder_url}")
            return placeholder_url
    
    async def _generate_visitor_credentials(self, visitor_id: str, visitor_name: str) -> VisitorCredentials:
        """Generate visitor access credentials"""
        try:
            # Generate temporary password
            temp_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
            encrypted_password = self.cipher_suite.encrypt(temp_password.encode()).decode()
            
            # Generate JWT access token
            token_payload = {
                'visitor_id': visitor_id,
                'name': visitor_name,
                'type': 'visitor',
                'exp': datetime.utcnow() + timedelta(hours=8),  # Max session duration
                'iat': datetime.utcnow()
            }
            access_token = jwt.encode(token_payload, self.jwt_secret, algorithm='HS256')
            
            # Generate QR code
            qr_data = {
                'visitor_id': visitor_id,
                'name': visitor_name,
                'access_token': access_token,
                'temp_password': temp_password
            }
            
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(str(qr_data))
            qr.make(fit=True)
            
            qr_image = qr.make_image(fill_color="black", back_color="white")
            
            # Convert QR code to base64
            buffer = BytesIO()
            qr_image.save(buffer, format='PNG')
            qr_code_b64 = base64.b64encode(buffer.getvalue()).decode()
            
            return VisitorCredentials(
                temporary_password=encrypted_password,
                qr_code=qr_code_b64,
                access_token=access_token
            )
            
        except Exception as e:
            logger.error(f"Error generating visitor credentials: {str(e)}")
            raise ValidationError(f"Failed to generate credentials: {str(e)}")
    
    async def _store_visitor(self, visitor: Visitor):
        """Store visitor in Firestore"""
        try:
            visitor_ref = self.db.collection('visitors').document(visitor.visitor_id)
            visitor_ref.set(visitor.dict())
            
        except Exception as e:
            logger.error(f"Error storing visitor: {str(e)}")
            raise ValidationError(f"Failed to store visitor: {str(e)}")
    
    async def _update_visitor(self, visitor: Visitor):
        """Update visitor in Firestore"""
        try:
            visitor.updated_at = datetime.utcnow()
            visitor_ref = self.db.collection('visitors').document(visitor.visitor_id)
            visitor_ref.update(visitor.dict())
            
        except Exception as e:
            logger.error(f"Error updating visitor: {str(e)}")
            raise ValidationError(f"Failed to update visitor: {str(e)}")
    
    async def _handle_route_violation(self, visitor: Visitor, resource_segment: str, action: str):
        """Handle route compliance violation"""
        try:
            # Create alert
            alert_id = str(uuid.uuid4())
            alert_data = {
                'alert_id': alert_id,
                'type': 'route_violation',
                'visitor_id': visitor.visitor_id,
                'visitor_name': visitor.name,
                'host_id': visitor.host_id,
                'resource_segment': resource_segment,
                'action': action,
                'timestamp': datetime.utcnow(),
                'severity': 'high' if resource_segment in visitor.assigned_route.restricted_areas else 'medium',
                'status': 'active'
            }
            
            # Store alert
            self.db.collection('alerts').document(alert_id).set(alert_data)
            
            # Add alert to visitor
            visitor.alerts.append(alert_id)
            
            # Notify host and administrators within 2 minutes
            await self._notify_route_violation(visitor, resource_segment, action, alert_data['severity'])
            
        except Exception as e:
            logger.error(f"Error handling route violation: {str(e)}")
    
    async def _notify_host_registration(self, visitor: Visitor):
        """Send notification to host about visitor registration"""
        try:
            notification_data = {
                'type': 'visitor_registered',
                'title': 'Visitor Registered Successfully',
                'message': f'Visitor {visitor.name} has been registered and is now active.',
                'visitor_id': visitor.visitor_id,
                'visitor_name': visitor.name,
                'expected_exit_time': visitor.expected_exit_time.isoformat(),
                'timestamp': datetime.utcnow()
            }
            
            await self.enhanced_firebase.send_notification(visitor.host_id, notification_data)
            
        except Exception as e:
            logger.error(f"Error sending host registration notification: {str(e)}")
    
    async def _notify_route_violation(self, visitor: Visitor, resource_segment: str, action: str, severity: str):
        """Send route violation notification"""
        try:
            notification_data = {
                'type': 'route_violation',
                'title': f'{severity.title()} Route Violation',
                'message': f'Visitor {visitor.name} attempted unauthorized access to {resource_segment}',
                'visitor_id': visitor.visitor_id,
                'visitor_name': visitor.name,
                'resource_segment': resource_segment,
                'action': action,
                'severity': severity,
                'timestamp': datetime.utcnow()
            }
            
            # Notify host
            await self.enhanced_firebase.send_notification(visitor.host_id, notification_data)
            
            # Notify administrators for high severity violations
            if severity == 'high':
                await self.enhanced_firebase.broadcast_to_admins(notification_data)
            
        except Exception as e:
            logger.error(f"Error sending route violation notification: {str(e)}")
    
    async def _notify_session_extension(self, visitor: Visitor, additional_hours: int, reason: str):
        """Send session extension notification"""
        try:
            notification_data = {
                'type': 'session_extended',
                'title': 'Visitor Session Extended',
                'message': f'Visitor {visitor.name} session extended by {additional_hours} hours',
                'visitor_id': visitor.visitor_id,
                'visitor_name': visitor.name,
                'additional_hours': additional_hours,
                'reason': reason,
                'new_exit_time': visitor.expected_exit_time.isoformat(),
                'timestamp': datetime.utcnow()
            }
            
            await self.enhanced_firebase.send_notification(visitor.host_id, notification_data)
            
        except Exception as e:
            logger.error(f"Error sending session extension notification: {str(e)}")
    
    async def _notify_session_termination(self, visitor: Visitor, reason: str, terminated_by: str):
        """Send session termination notification"""
        try:
            notification_data = {
                'type': 'session_terminated',
                'title': 'Visitor Session Terminated',
                'message': f'Visitor {visitor.name} session has been terminated: {reason}',
                'visitor_id': visitor.visitor_id,
                'visitor_name': visitor.name,
                'reason': reason,
                'terminated_by': terminated_by,
                'termination_time': visitor.actual_exit_time.isoformat(),
                'timestamp': datetime.utcnow()
            }
            
            await self.enhanced_firebase.send_notification(visitor.host_id, notification_data)
            
        except Exception as e:
            logger.error(f"Error sending session termination notification: {str(e)}")
    
    async def _notify_session_expiration(self, visitor: Visitor):
        """Send session expiration notification"""
        try:
            notification_data = {
                'type': 'session_expired',
                'title': 'Visitor Session Expired',
                'message': f'Visitor {visitor.name} session has automatically expired',
                'visitor_id': visitor.visitor_id,
                'visitor_name': visitor.name,
                'expected_exit_time': visitor.expected_exit_time.isoformat(),
                'timestamp': datetime.utcnow()
            }
            
            await self.enhanced_firebase.send_notification(visitor.host_id, notification_data)
            
        except Exception as e:
            logger.error(f"Error sending session expiration notification: {str(e)}")
    
    async def _notify_session_expiration_warning(self, visitor_data: Dict[str, Any]):
        """Send session expiration warning notification"""
        try:
            notification_data = {
                'type': 'session_expiring_soon',
                'title': 'Visitor Session Expiring Soon',
                'message': f'Visitor {visitor_data["name"]} session will expire in 30 minutes',
                'visitor_id': visitor_data['visitor_id'],
                'visitor_name': visitor_data['name'],
                'expected_exit_time': visitor_data['expected_exit_time'],
                'timestamp': datetime.utcnow()
            }
            
            await self.enhanced_firebase.send_notification(visitor_data['host_id'], notification_data)
            
        except Exception as e:
            logger.error(f"Error sending session expiration warning: {str(e)}")
    
    async def _log_visitor_event(self, visitor_id: str, event_type: str, event_data: Dict[str, Any]):
        """Log visitor event for audit purposes"""
        try:
            log_entry = {
                'event_id': str(uuid.uuid4()),
                'visitor_id': visitor_id,
                'event_type': event_type,
                'event_data': event_data,
                'timestamp': datetime.utcnow(),
                'source': 'visitor_service'
            }
            
            self.db.collection('audit_logs').add(log_entry)
            
        except Exception as e:
            logger.error(f"Error logging visitor event: {str(e)}")


# Global visitor service instance
visitor_service = VisitorService()