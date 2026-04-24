"""
Unit tests for Visitor Management Service
Tests visitor registration, session management, and route compliance
"""

import pytest
import uuid
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime, timedelta

from app.services.visitor_service import VisitorService
from app.models.visitor import Visitor, VisitorRegistrationRequest, AssignedRoute
from app.utils.error_handler import ValidationError, NotFoundError, PermissionError


class TestVisitorService:
    """Unit tests for VisitorService"""
    
    @pytest.fixture
    def service(self):
        """Create VisitorService instance for testing"""
        with patch('app.services.visitor_service.firestore.Client'), \
             patch('app.services.visitor_service.storage.Client'), \
             patch('app.services.visitor_service.FirebaseAdminService'), \
             patch('app.services.visitor_service.EnhancedFirebaseService'):
            
            service = VisitorService()
            service.db = Mock()
            service.storage_client = Mock()
            service.firebase_service = Mock()
            service.enhanced_firebase = Mock()
            return service
    
    @pytest.fixture
    def sample_registration_data(self):
        """Sample visitor registration data"""
        return VisitorRegistrationRequest(
            name="John Doe",
            email="john.doe@example.com",
            phone="+1234567890",
            host_id="host_123",
            host_name="Dr. Smith",
            host_department="Computer Science",
            visit_purpose="Research collaboration meeting",
            expected_duration=4,  # 4 hours
            assigned_route=AssignedRoute(
                allowed_segments=["academic_resources", "library_services"],
                restricted_areas=["admin_systems", "research_labs"],
                route_description="Visitor access to academic areas and library only"
            )
        )
    
    @pytest.fixture
    def sample_visitor(self):
        """Sample visitor object"""
        return Visitor(
            visitor_id="visitor_123",
            name="John Doe",
            email="john.doe@example.com",
            phone="+1234567890",
            photo="https://storage.example.com/photo.jpg",
            host_id="host_123",
            host_name="Dr. Smith",
            host_department="Computer Science",
            visit_purpose="Research collaboration meeting",
            entry_time=datetime.utcnow(),
            expected_exit_time=datetime.utcnow() + timedelta(hours=4),
            max_duration=4,
            assigned_route=AssignedRoute(
                allowed_segments=["academic_resources", "library_services"],
                restricted_areas=["admin_systems", "research_labs"],
                route_description="Visitor access to academic areas and library only"
            ),
            status="active"
        )
    
    @pytest.mark.asyncio
    async def test_register_visitor_success(self, service, sample_registration_data):
        """Test successful visitor registration"""
        host_user_id = "host_123"
        photo_file = Mock()
        
        # Mock validation and dependencies
        service._validate_host_permissions = AsyncMock()
        service._upload_visitor_photo = AsyncMock(return_value="https://storage.example.com/photo.jpg")
        service._generate_visitor_credentials = AsyncMock(return_value=Mock())
        service._store_visitor = AsyncMock()
        service._notify_host_registration = AsyncMock()
        service._log_visitor_event = AsyncMock()
        
        with patch('uuid.uuid4', return_value=Mock(hex='visitor_123')):
            result = await service.register_visitor(sample_registration_data, photo_file, host_user_id)
            
            assert isinstance(result, Visitor)
            assert result.name == "John Doe"
            assert result.host_id == sample_registration_data.host_id
            assert result.status == "active"
            
            # Verify all required methods were called
            service._validate_host_permissions.assert_called_once_with(host_user_id)
            service._upload_visitor_photo.assert_called_once()
            service._generate_visitor_credentials.assert_called_once()
            service._store_visitor.assert_called_once()
            service._notify_host_registration.assert_called_once()
            service._log_visitor_event.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_register_visitor_invalid_host(self, service, sample_registration_data):
        """Test visitor registration with invalid host permissions"""
        host_user_id = "invalid_host"
        photo_file = Mock()
        
        # Mock permission validation failure
        service._validate_host_permissions = AsyncMock(side_effect=PermissionError("Invalid host"))
        
        with pytest.raises(ValidationError):
            await service.register_visitor(sample_registration_data, photo_file, host_user_id)
    
    @pytest.mark.asyncio
    async def test_get_visitor_success(self, service, sample_visitor):
        """Test successful visitor retrieval"""
        visitor_id = "visitor_123"
        requesting_user_id = "host_123"
        
        # Mock Firestore document
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = sample_visitor.dict()
        
        mock_doc_ref = Mock()
        mock_doc_ref.get.return_value = mock_doc
        service.db.collection.return_value.document.return_value = mock_doc_ref
        
        service._validate_visitor_access = AsyncMock()
        
        result = await service.get_visitor(visitor_id, requesting_user_id)
        
        assert isinstance(result, Visitor)
        assert result.visitor_id == visitor_id
        service._validate_visitor_access.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_visitor_not_found(self, service):
        """Test visitor retrieval when visitor doesn't exist"""
        visitor_id = "nonexistent_visitor"
        requesting_user_id = "host_123"
        
        # Mock non-existent document
        mock_doc = Mock()
        mock_doc.exists = False
        
        mock_doc_ref = Mock()
        mock_doc_ref.get.return_value = mock_doc
        service.db.collection.return_value.document.return_value = mock_doc_ref
        
        with pytest.raises(NotFoundError):
            await service.get_visitor(visitor_id, requesting_user_id)
    
    @pytest.mark.asyncio
    async def test_get_host_visitors(self, service, sample_visitor):
        """Test retrieving visitors for a specific host"""
        host_id = "host_123"
        
        # Mock Firestore query
        mock_docs = [Mock()]
        mock_docs[0].to_dict.return_value = sample_visitor.dict()
        
        mock_query = Mock()
        mock_query.stream.return_value = mock_docs
        
        # Chain query methods
        service.db.collection.return_value.where.return_value.order_by.return_value = mock_query
        
        result = await service.get_host_visitors(host_id)
        
        assert len(result) == 1
        assert isinstance(result[0], Visitor)
        assert result[0].host_id == host_id
    
    @pytest.mark.asyncio
    async def test_track_visitor_access_approved(self, service, sample_visitor):
        """Test visitor access tracking for approved resource"""
        visitor_id = "visitor_123"
        resource_segment = "academic_resources"  # In allowed segments
        action = "read"
        requesting_user_id = "host_123"
        
        service.get_visitor = AsyncMock(return_value=sample_visitor)
        service._update_visitor = AsyncMock()
        service._log_visitor_event = AsyncMock()
        
        # Mock session active check
        sample_visitor.is_session_active = Mock(return_value=True)
        sample_visitor.add_access_log_entry = Mock()
        
        result = await service.track_visitor_access(
            visitor_id, resource_segment, action, requesting_user_id
        )
        
        assert result is True
        sample_visitor.add_access_log_entry.assert_called_once_with(
            resource_segment, action, True, None
        )
        service._update_visitor.assert_called_once()
        service._log_visitor_event.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_track_visitor_access_denied(self, service, sample_visitor):
        """Test visitor access tracking for denied resource"""
        visitor_id = "visitor_123"
        resource_segment = "admin_systems"  # In restricted areas
        action = "read"
        requesting_user_id = "host_123"
        
        service.get_visitor = AsyncMock(return_value=sample_visitor)
        service._update_visitor = AsyncMock()
        service._handle_route_violation = AsyncMock()
        service._log_visitor_event = AsyncMock()
        
        sample_visitor.is_session_active = Mock(return_value=True)
        sample_visitor.add_access_log_entry = Mock()
        
        result = await service.track_visitor_access(
            visitor_id, resource_segment, action, requesting_user_id
        )
        
        assert result is False
        sample_visitor.add_access_log_entry.assert_called_once_with(
            resource_segment, action, False, None
        )
        service._handle_route_violation.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_track_visitor_access_expired_session(self, service, sample_visitor):
        """Test visitor access tracking when session is expired"""
        visitor_id = "visitor_123"
        resource_segment = "academic_resources"
        action = "read"
        requesting_user_id = "host_123"
        
        service.get_visitor = AsyncMock(return_value=sample_visitor)
        service._log_visitor_event = AsyncMock()
        
        # Mock expired session
        sample_visitor.is_session_active = Mock(return_value=False)
        
        result = await service.track_visitor_access(
            visitor_id, resource_segment, action, requesting_user_id
        )
        
        assert result is False
        service._log_visitor_event.assert_called_once_with(
            visitor_id, "access_denied_expired", {
                "resource_segment": resource_segment,
                "action": action,
                "reason": "session_expired"
            }
        )
    
    @pytest.mark.asyncio
    async def test_extend_visitor_session_success(self, service, sample_visitor):
        """Test successful visitor session extension"""
        visitor_id = "visitor_123"
        additional_hours = 2
        reason = "Meeting running longer than expected"
        requesting_host_id = "host_123"
        approving_admin_id = "admin_456"
        
        service.get_visitor = AsyncMock(return_value=sample_visitor)
        service._validate_admin_permissions = AsyncMock()
        service._update_visitor = AsyncMock()
        service._notify_session_extension = AsyncMock()
        service._log_visitor_event = AsyncMock()
        
        sample_visitor.extend_session = Mock()
        
        result = await service.extend_visitor_session(
            visitor_id, additional_hours, reason, requesting_host_id, approving_admin_id
        )
        
        assert isinstance(result, Visitor)
        sample_visitor.extend_session.assert_called_once_with(
            additional_hours, requesting_host_id, approving_admin_id, reason
        )
        service._validate_admin_permissions.assert_called_once_with(approving_admin_id)
        service._update_visitor.assert_called_once()
        service._notify_session_extension.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_extend_visitor_session_wrong_host(self, service, sample_visitor):
        """Test session extension by wrong host"""
        visitor_id = "visitor_123"
        additional_hours = 2
        reason = "Meeting running longer"
        requesting_host_id = "wrong_host_456"  # Different from visitor's host
        approving_admin_id = "admin_456"
        
        service.get_visitor = AsyncMock(return_value=sample_visitor)
        
        with pytest.raises(PermissionError, match="Only the assigned host can request"):
            await service.extend_visitor_session(
                visitor_id, additional_hours, reason, requesting_host_id, approving_admin_id
            )
    
    @pytest.mark.asyncio
    async def test_terminate_visitor_session(self, service, sample_visitor):
        """Test visitor session termination"""
        visitor_id = "visitor_123"
        reason = "Early departure"
        terminating_user_id = "host_123"
        
        service.get_visitor = AsyncMock(return_value=sample_visitor)
        service._validate_termination_permissions = AsyncMock()
        service._update_visitor = AsyncMock()
        service._notify_session_termination = AsyncMock()
        service._log_visitor_event = AsyncMock()
        
        sample_visitor.terminate_session = Mock()
        
        result = await service.terminate_visitor_session(visitor_id, reason, terminating_user_id)
        
        assert isinstance(result, Visitor)
        sample_visitor.terminate_session.assert_called_once_with(reason)
        service._validate_termination_permissions.assert_called_once()
        service._update_visitor.assert_called_once()
        service._notify_session_termination.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_check_expired_sessions(self, service):
        """Test automatic expiration of visitor sessions"""
        # Mock expired visitor data
        expired_visitor_data = {
            "visitor_id": "visitor_123",
            "name": "John Doe",
            "host_id": "host_123",
            "status": "active",
            "expected_exit_time": datetime.utcnow() - timedelta(hours=1)  # Expired
        }
        
        mock_docs = [Mock()]
        mock_docs[0].to_dict.return_value = expired_visitor_data
        
        mock_query = Mock()
        mock_query.stream.return_value = mock_docs
        
        # Chain query methods
        service.db.collection.return_value.where.return_value.where.return_value = mock_query
        
        service._update_visitor = AsyncMock()
        service._notify_session_expiration = AsyncMock()
        service._log_visitor_event = AsyncMock()
        
        with patch('app.models.visitor.Visitor') as mock_visitor_class:
            mock_visitor = Mock()
            mock_visitor.visitor_id = "visitor_123"
            mock_visitor.terminate_session = Mock()
            mock_visitor_class.return_value = mock_visitor
            
            result = await service.check_expired_sessions()
            
            assert len(result) == 1
            assert result[0] == "visitor_123"
            mock_visitor.terminate_session.assert_called_once_with("Automatic expiration")
            service._update_visitor.assert_called_once()
            service._notify_session_expiration.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_visitor_compliance_report(self, service, sample_visitor):
        """Test visitor compliance report generation"""
        visitor_id = "visitor_123"
        requesting_user_id = "host_123"
        
        # Add some access log entries
        sample_visitor.access_log = [
            Mock(approved=True, timestamp=datetime.utcnow()),
            Mock(approved=True, timestamp=datetime.utcnow()),
            Mock(approved=False, timestamp=datetime.utcnow())
        ]
        
        sample_visitor.route_compliance.deviations = [
            {"severity": "high", "timestamp": datetime.utcnow()}
        ]
        
        service.get_visitor = AsyncMock(return_value=sample_visitor)
        
        result = await service.get_visitor_compliance_report(visitor_id, requesting_user_id)
        
        assert "visitor_id" in result
        assert "session_summary" in result
        assert "access_summary" in result
        assert "compliance_metrics" in result
        
        # Check access summary calculations
        assert result["access_summary"]["total_accesses"] == 3
        assert result["access_summary"]["approved_accesses"] == 2
        assert result["access_summary"]["denied_accesses"] == 1
        assert abs(result["access_summary"]["approval_rate"] - 66.67) < 0.1
        
        # Check compliance metrics
        assert result["compliance_metrics"]["total_deviations"] == 1
        assert result["compliance_metrics"]["high_severity_deviations"] == 1
    
    @pytest.mark.asyncio
    async def test_validate_host_permissions_success(self, service):
        """Test successful host permission validation"""
        user_id = "host_123"
        
        # Mock user document
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {"role": "faculty"}
        
        mock_doc_ref = Mock()
        mock_doc_ref.get.return_value = mock_doc
        service.db.collection.return_value.document.return_value = mock_doc_ref
        
        # Should not raise exception
        await service._validate_host_permissions(user_id)
    
    @pytest.mark.asyncio
    async def test_validate_host_permissions_invalid_role(self, service):
        """Test host permission validation with invalid role"""
        user_id = "student_123"
        
        # Mock user document with student role
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {"role": "student"}
        
        mock_doc_ref = Mock()
        mock_doc_ref.get.return_value = mock_doc
        service.db.collection.return_value.document.return_value = mock_doc_ref
        
        with pytest.raises(PermissionError, match="Only faculty and administrators"):
            await service._validate_host_permissions(user_id)
    
    @pytest.mark.asyncio
    async def test_validate_admin_permissions(self, service):
        """Test admin permission validation"""
        admin_id = "admin_123"
        
        # Mock admin document
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {"role": "admin"}
        
        mock_doc_ref = Mock()
        mock_doc_ref.get.return_value = mock_doc
        service.db.collection.return_value.document.return_value = mock_doc_ref
        
        # Should not raise exception
        await service._validate_admin_permissions(admin_id)
        
        # Test invalid role
        mock_doc.to_dict.return_value = {"role": "faculty"}
        
        with pytest.raises(PermissionError, match="Admin permissions required"):
            await service._validate_admin_permissions(admin_id)
    
    @pytest.mark.asyncio
    async def test_upload_visitor_photo(self, service):
        """Test visitor photo upload to Cloud Storage"""
        visitor_id = "visitor_123"
        photo_file = Mock()
        
        # Mock storage operations
        mock_blob = Mock()
        mock_blob.public_url = "https://storage.example.com/photo.jpg"
        
        mock_bucket = Mock()
        mock_bucket.blob.return_value = mock_blob
        
        service.storage_client.bucket.return_value = mock_bucket
        
        result = await service._upload_visitor_photo(visitor_id, photo_file)
        
        assert result == "https://storage.example.com/photo.jpg"
        mock_blob.upload_from_file.assert_called_once_with(photo_file, content_type='image/jpeg')
        mock_blob.make_public.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_generate_visitor_credentials(self, service):
        """Test visitor credential generation"""
        visitor_id = "visitor_123"
        visitor_name = "John Doe"
        
        with patch('secrets.choice') as mock_choice, \
             patch('jwt.encode') as mock_jwt, \
             patch('qrcode.QRCode') as mock_qr:
            
            # Mock password generation
            mock_choice.side_effect = list("testpassword")
            
            # Mock JWT encoding
            mock_jwt.return_value = "mock_jwt_token"
            
            # Mock QR code generation
            mock_qr_instance = Mock()
            mock_qr_image = Mock()
            mock_qr_instance.make_image.return_value = mock_qr_image
            mock_qr.return_value = mock_qr_instance
            
            with patch('base64.b64encode') as mock_b64:
                mock_b64.return_value = b"mock_qr_code"
                
                result = await service._generate_visitor_credentials(visitor_id, visitor_name)
                
                assert hasattr(result, 'temporary_password')
                assert hasattr(result, 'qr_code')
                assert hasattr(result, 'access_token')
                assert result.access_token == "mock_jwt_token"
    
    @pytest.mark.asyncio
    async def test_handle_route_violation(self, service, sample_visitor):
        """Test route violation handling"""
        resource_segment = "admin_systems"
        action = "read"
        
        service._notify_route_violation = AsyncMock()
        
        # Mock Firestore operations for alert creation
        mock_doc_ref = Mock()
        service.db.collection.return_value.document.return_value = mock_doc_ref
        
        await service._handle_route_violation(sample_visitor, resource_segment, action)
        
        # Verify alert was created
        mock_doc_ref.set.assert_called_once()
        
        # Verify notification was sent
        service._notify_route_violation.assert_called_once()
        
        # Verify alert was added to visitor
        assert len(sample_visitor.alerts) > 0
    
    @pytest.mark.asyncio
    async def test_error_handling(self, service):
        """Test error handling in various scenarios"""
        # Test with invalid visitor data
        with pytest.raises(ValidationError):
            await service.register_visitor(None, None, "host_123")
        
        # Test photo upload failure
        service.storage_client.bucket.side_effect = Exception("Storage error")
        
        with pytest.raises(ValidationError, match="Failed to upload photo"):
            await service._upload_visitor_photo("visitor_123", Mock())
    
    def test_visitor_model_methods(self, sample_visitor):
        """Test visitor model helper methods"""
        # Test session active check
        assert sample_visitor.is_session_active() is True
        
        # Test expired session
        sample_visitor.expected_exit_time = datetime.utcnow() - timedelta(hours=1)
        assert sample_visitor.is_session_active() is False
        
        # Test session extension
        original_exit_time = sample_visitor.expected_exit_time
        sample_visitor.extend_session(2, "host_123", "admin_456", "Meeting extended")
        
        assert sample_visitor.expected_exit_time > original_exit_time
        assert len(sample_visitor.session_extensions) == 1
        
        # Test session termination
        sample_visitor.terminate_session("Early departure")
        assert sample_visitor.status == "terminated"
        assert sample_visitor.actual_exit_time is not None