"""
Unit tests for Break-Glass Emergency Access Service
Tests dual approval workflow, activity logging, and emergency session management
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime, timedelta

from app.services.break_glass_service import (
    BreakGlassService, 
    EmergencyAccessRequest, 
    EmergencyRequestStatus,
    EmergencyType,
    UrgencyLevel
)


class TestBreakGlassService:
    """Unit tests for BreakGlassService"""
    
    @pytest.fixture
    def service(self):
        """Create BreakGlassService instance for testing"""
        mock_db = MagicMock()
        service = BreakGlassService(mock_db)
        return service
    
    @pytest.fixture
    def sample_emergency_request_data(self):
        """Sample emergency request data"""
        return {
            'requesterId': 'user_123',
            'emergencyType': 'system_outage',
            'urgencyLevel': 'critical',
            'justification': 'Critical system outage affecting production services. Need immediate access to restore database connectivity and resolve authentication issues that are preventing user access to essential systems.',
            'requiredResources': ['admin_systems', 'database_servers'],
            'estimatedDuration': 1.5
        }
    
    @pytest.fixture
    def sample_emergency_request(self):
        """Sample emergency access request object"""
        return EmergencyAccessRequest(
            requester_id='user_123',
            emergency_type='system_outage',
            urgency_level='critical',
            justification='Critical system outage affecting production services. Need immediate access to restore database connectivity and resolve authentication issues that are preventing user access to essential systems.',
            required_resources=['admin_systems', 'database_servers'],
            estimated_duration=1.5
        )
    
    def test_emergency_access_request_creation(self):
        """Test emergency access request model creation"""
        request = EmergencyAccessRequest(
            requester_id='user_123',
            emergency_type='security_incident',
            urgency_level='high',
            justification='Security incident detected requiring immediate investigation and containment measures.',
            required_resources=['security_systems'],
            estimated_duration=2.0
        )
        
        assert request.requester_id == 'user_123'
        assert request.emergency_type == 'security_incident'
        assert request.urgency_level == 'high'
        assert request.status == EmergencyRequestStatus.PENDING
        assert len(request.required_resources) == 1
        assert request.estimated_duration == 2.0
        assert isinstance(request.requested_at, datetime)
        assert request.post_incident_review['reviewRequired'] is True
    
    def test_emergency_request_serialization(self, sample_emergency_request):
        """Test emergency request to/from dict conversion"""
        # Test to_dict
        request_dict = sample_emergency_request.to_dict()
        
        assert request_dict['requesterId'] == 'user_123'
        assert request_dict['emergencyType'] == 'system_outage'
        assert request_dict['urgencyLevel'] == 'critical'
        assert request_dict['status'] == 'pending'
        assert len(request_dict['requiredResources']) == 2
        
        # Test from_dict
        restored_request = EmergencyAccessRequest.from_dict(request_dict)
        
        assert restored_request.requester_id == sample_emergency_request.requester_id
        assert restored_request.emergency_type == sample_emergency_request.emergency_type
        assert restored_request.status == sample_emergency_request.status
    
    @pytest.mark.asyncio
    async def test_submit_emergency_request_success(self, service, sample_emergency_request_data):
        """Test successful emergency request submission"""
        # Mock validation
        service._validate_emergency_request = Mock(return_value={'valid': True})
        
        # Mock available administrators
        service._get_available_administrators = AsyncMock(return_value=[
            {'userId': 'admin_1', 'name': 'Admin One'},
            {'userId': 'admin_2', 'name': 'Admin Two'},
            {'userId': 'admin_3', 'name': 'Admin Three'}
        ])
        
        # Mock other dependencies
        service._notify_administrators = AsyncMock(return_value=3)
        service._log_emergency_request = AsyncMock()
        service._schedule_approval_timeout = AsyncMock()
        
        # Mock Firestore operations
        mock_doc_ref = Mock()
        service.db.collection.return_value.document.return_value = mock_doc_ref
        
        result = await service.submit_emergency_request(sample_emergency_request_data)
        
        assert result['success'] is True
        assert 'requestId' in result
        assert result['approvalRequired'] is True
        assert result['timeoutMinutes'] == service.APPROVAL_TIMEOUT_MINUTES
        assert result['notificationsSent'] == 3
        
        # Verify Firestore was called
        mock_doc_ref.set.assert_called_once()
        
        # Verify notifications were sent
        service._notify_administrators.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_submit_emergency_request_validation_failure(self, service, sample_emergency_request_data):
        """Test emergency request submission with validation failure"""
        # Mock validation failure
        service._validate_emergency_request = Mock(return_value={
            'valid': False,
            'error': 'Justification too short'
        })
        
        result = await service.submit_emergency_request(sample_emergency_request_data)
        
        assert result['success'] is False
        assert 'Justification too short' in result['error']
    
    @pytest.mark.asyncio
    async def test_submit_emergency_request_insufficient_admins(self, service, sample_emergency_request_data):
        """Test emergency request submission with insufficient administrators"""
        # Mock validation
        service._validate_emergency_request = Mock(return_value={'valid': True})
        
        # Mock available administrators
        service._get_available_administrators = AsyncMock(return_value=[
            {'userId': 'admin_1', 'name': 'Admin One', 'email': 'admin1@example.com'}
        ])
        
        # Mock notification
        service._notify_administrators = AsyncMock()
        
        # Mock DB operations
        mock_break_glass_ref = Mock()
        mock_audit_log_ref = Mock()
        
        def collection_side_effect(collection_name):
            if collection_name == 'breakGlassRequests':
                return mock_break_glass_ref
            elif collection_name == 'auditLogs':
                return mock_audit_log_ref
            return Mock()

        service.db.collection.side_effect = collection_side_effect
        
        # Execute
        result = await service.submit_emergency_request(sample_emergency_request_data)
        
        # Verify
        assert result['success'] is True
        assert "Insufficient administrators available" in result['warning']
        mock_break_glass_ref.document.return_value.set.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_process_approval_first_approval(self, service, sample_emergency_request):
        """Test processing first approval for emergency request"""
        request_id = sample_emergency_request.request_id
        approver_id = 'admin_1'
        decision = 'approved'
        comments = 'Approved - critical system outage confirmed'
        
        # Mock Firestore document
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = sample_emergency_request.to_dict()
        
        mock_doc_ref = Mock()
        mock_doc_ref.get.return_value = mock_doc
        service.db.collection.return_value.document.return_value = mock_doc_ref
        
        service._log_approval_decision = AsyncMock()
        
        result = await service.process_approval(request_id, approver_id, decision, comments)
        
        assert result['success'] is True
        assert result['status'] == 'pending'
        assert result['approvalsReceived'] == 1
        assert result['approvalsRequired'] == 2
        assert 'more approval(s) needed' in result['message']
        
        # Verify approval was recorded
        mock_doc_ref.update.assert_called_once()
        service._log_approval_decision.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_process_approval_second_approval_activates(self, service, sample_emergency_request):
        """Test processing second approval activates emergency access"""
        request_id = sample_emergency_request.request_id
        approver_id = 'admin_2'
        decision = 'approved'
        
        # Add first approval
        sample_emergency_request.approvals = [{
            'approverId': 'admin_1',
            'decision': 'approved',
            'timestamp': datetime.utcnow(),
            'comments': 'First approval'
        }]
        
        # Mock Firestore document
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = sample_emergency_request.to_dict()
        
        mock_doc_ref = Mock()
        mock_doc_ref.get.return_value = mock_doc
        service.db.collection.return_value.document.return_value = mock_doc_ref
        
        # Mock activation
        service._activate_emergency_access = AsyncMock(return_value={
            'success': True,
            'sessionId': 'session_123',
            'expiresAt': (datetime.utcnow() + timedelta(hours=2)).isoformat()
        })
        
        result = await service.process_approval(request_id, approver_id, decision)
        
        assert result['success'] is True
        assert result['status'] == 'activated'
        assert 'sessionId' in result
        assert 'expiresAt' in result
        
        # Verify activation was called
        service._activate_emergency_access.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_process_approval_denial(self, service, sample_emergency_request):
        """Test processing denial for emergency request"""
        request_id = sample_emergency_request.request_id
        approver_id = 'admin_1'
        decision = 'denied'
        comments = 'Insufficient justification'
        
        # Mock Firestore document
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = sample_emergency_request.to_dict()
        
        mock_doc_ref = Mock()
        mock_doc_ref.get.return_value = mock_doc
        service.db.collection.return_value.document.return_value = mock_doc_ref
        
        service._notify_requester_denial = AsyncMock()
        service._log_approval_decision = AsyncMock()
        
        result = await service.process_approval(request_id, approver_id, decision, comments)
        
        assert result['success'] is True
        assert result['status'] == 'denied'
        assert 'denied' in result['message']
        
        # Verify denial notifications
        service._notify_requester_denial.assert_called_once()
        service._log_approval_decision.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_process_approval_duplicate_approver(self, service, sample_emergency_request):
        """Test processing approval from same approver twice"""
        request_id = sample_emergency_request.request_id
        approver_id = 'admin_1'
        
        # Add existing approval from same admin
        sample_emergency_request.approvals = [{
            'approverId': 'admin_1',
            'decision': 'approved',
            'timestamp': datetime.utcnow(),
            'comments': 'Already approved'
        }]
        
        # Mock Firestore document
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = sample_emergency_request.to_dict()
        
        mock_doc_ref = Mock()
        mock_doc_ref.get.return_value = mock_doc
        service.db.collection.return_value.document.return_value = mock_doc_ref
        
        result = await service.process_approval(request_id, approver_id, 'approved')
        
        assert result['success'] is False
        assert 'already provided a decision' in result['error']
    
    @pytest.mark.asyncio
    async def test_get_pending_emergency_requests(self, service):
        """Test retrieving pending emergency requests for admin"""
        admin_id = 'admin_1'
        
        # Mock pending request data
        pending_request_data = {
            'requestId': 'req_123',
            'requesterId': 'user_123',
            'emergencyType': 'system_outage',
            'urgencyLevel': 'critical',
            'justification': 'Critical system outage',
            'requiredResources': ['admin_systems'],
            'requestedAt': datetime.utcnow() - timedelta(minutes=5),
            'status': 'pending',
            'approvals': []
        }
        
        # Mock Firestore query
        mock_docs = [Mock()]
        mock_docs[0].to_dict.return_value = pending_request_data
        
        mock_query = Mock()
        mock_query.stream.return_value = mock_docs
        service.db.collection.return_value.where.return_value = mock_query
        
        # Mock user and resource info
        service._get_user_info = AsyncMock(return_value={
            'name': 'Test User',
            'role': 'faculty',
            'email': 'user@example.com'
        })
        service._get_resource_segment_info = AsyncMock(return_value={
            'name': 'Admin Systems',
            'securityLevel': 5
        })
        
        result = await service.get_pending_emergency_requests(admin_id)
        
        assert len(result) == 1
        assert result[0]['requestId'] == 'req_123'
        assert 'requesterName' in result[0]
        assert 'resourceDetails' in result[0]
        assert 'timeRemainingMinutes' in result[0]
    
    @pytest.mark.asyncio
    async def test_monitor_emergency_session_active(self, service):
        """Test monitoring active emergency session"""
        session_id = 'session_123'
        
        # Mock active session data
        session_data = {
            'sessionId': session_id,
            'userId': 'user_123',
            'status': 'active',
            'expiresAt': (datetime.utcnow() + timedelta(hours=1)).isoformat(),
            'elevatedPrivileges': ['admin_access'],
            'activityLog': [
                {'timestamp': datetime.utcnow(), 'action': 'login'},
                {'timestamp': datetime.utcnow(), 'action': 'database_query'}
            ]
        }
        
        # Mock Firestore document
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = session_data
        
        mock_doc_ref = Mock()
        mock_doc_ref.get.return_value = mock_doc
        service.db.collection.return_value.document.return_value = mock_doc_ref
        
        result = await service.monitor_emergency_session(session_id)
        
        assert result['success'] is True
        assert result['sessionId'] == session_id
        assert result['status'] == 'active'
        assert result['userId'] == 'user_123'
        assert len(result['recentActivity']) == 2
        assert result['timeRemainingSeconds'] > 0
        assert result['activityCount'] == 2
    
    @pytest.mark.asyncio
    async def test_monitor_emergency_session_expired(self, service):
        """Test monitoring expired emergency session"""
        session_id = 'session_123'
        
        # Mock expired session data
        session_data = {
            'sessionId': session_id,
            'status': 'active',
            'expiresAt': (datetime.utcnow() - timedelta(hours=1)).isoformat(),  # Expired
            'activityLog': []
        }
        
        # Mock Firestore document
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = session_data
        
        mock_doc_ref = Mock()
        mock_doc_ref.get.return_value = mock_doc
        service.db.collection.return_value.document.return_value = mock_doc_ref
        
        service._expire_emergency_session = AsyncMock()
        
        result = await service.monitor_emergency_session(session_id)
        
        assert result['success'] is False
        assert 'expired' in result['error']
        
        # Verify session was expired
        service._expire_emergency_session.assert_called_once_with(session_id)
    
    @pytest.mark.asyncio
    async def test_log_emergency_activity(self, service):
        """Test logging emergency session activity"""
        session_id = 'session_123'
        activity_data = {
            'userId': 'user_123',
            'action': 'database_restore',
            'resource': 'production_db',
            'command': 'RESTORE DATABASE',
            'dataAccessed': ['user_table', 'config_table'],
            'ipAddress': '192.168.1.100',
            'riskScore': 25,
            'result': 'success'
        }
        
        # Mock session document
        mock_doc = Mock()
        mock_doc.exists = True
        
        mock_doc_ref = Mock()
        mock_doc_ref.get.return_value = mock_doc
        service.db.collection.return_value.document.return_value = mock_doc_ref
        
        # Mock enhanced firebase service
        with patch('app.services.break_glass_service.enhanced_firebase_service') as mock_firebase:
            mock_firebase.array_union.return_value = Mock()
            
            # Mock audit log creation
            with patch('app.services.break_glass_service.create_audit_log', new_callable=AsyncMock) as mock_audit:
                result = await service.log_emergency_activity(session_id, activity_data)
                
                assert result is True
                
                # Verify session was updated
                mock_doc_ref.update.assert_called_once()
                
                # Verify audit log was created
                mock_audit.assert_called_once()
    
    def test_validate_emergency_request_success(self, service, sample_emergency_request_data):
        """Test successful emergency request validation"""
        result = service._validate_emergency_request(sample_emergency_request_data)
        
        assert result['valid'] is True
    
    def test_validate_emergency_request_missing_fields(self, service):
        """Test emergency request validation with missing fields"""
        incomplete_data = {
            'requesterId': 'user_123',
            'emergencyType': 'system_outage'
            # Missing other required fields
        }
        
        result = service._validate_emergency_request(incomplete_data)
        
        assert result['valid'] is False
        assert 'Missing required field' in result['error']
    
    def test_validate_emergency_request_invalid_type(self, service, sample_emergency_request_data):
        """Test emergency request validation with invalid emergency type"""
        sample_emergency_request_data['emergencyType'] = 'invalid_type'
        
        result = service._validate_emergency_request(sample_emergency_request_data)
        
        assert result['valid'] is False
        assert 'Invalid emergency type' in result['error']
    
    def test_validate_emergency_request_short_justification(self, service, sample_emergency_request_data):
        """Test emergency request validation with short justification"""
        sample_emergency_request_data['justification'] = 'Too short'  # Less than 100 characters
        
        result = service._validate_emergency_request(sample_emergency_request_data)
        
        assert result['valid'] is False
        assert 'at least 100 characters' in result['error']
    
    def test_validate_emergency_request_invalid_duration(self, service, sample_emergency_request_data):
        """Test emergency request validation with invalid duration"""
        sample_emergency_request_data['estimatedDuration'] = 3.0  # Exceeds 2 hour limit
        
        result = service._validate_emergency_request(sample_emergency_request_data)
        
        assert result['valid'] is False
        assert 'between 0.5 and 2 hours' in result['error']
    
    def test_validate_emergency_request_no_resources(self, service, sample_emergency_request_data):
        """Test emergency request validation with no required resources"""
        sample_emergency_request_data['requiredResources'] = []
        
        result = service._validate_emergency_request(sample_emergency_request_data)
        
        assert result['valid'] is False
        assert 'At least one required resource' in result['error']
    
    @pytest.mark.asyncio
    async def test_get_available_administrators(self, service):
        """Test getting available administrators"""
        # Mock admin users
        mock_docs = []
        for i in range(3):
            mock_doc = Mock()
            mock_doc.to_dict.return_value = {
                'userId': f'admin_{i}',
                'name': f'Admin {i}',
                'email': f'admin{i}@example.com',
                'role': 'admin',
                'isActive': True,
                'lastLogin': datetime.utcnow()
            }
            mock_docs.append(mock_doc)
        
        mock_query = Mock()
        mock_query.stream.return_value = mock_docs
        service.db.collection.return_value.where.return_value.where.return_value = mock_query
        
        result = await service._get_available_administrators()
        
        assert len(result) == 3
        assert all('userId' in admin for admin in result)
        assert all('name' in admin for admin in result)
        assert all(admin['available'] is True for admin in result)
    
    @pytest.mark.asyncio
    async def test_notify_administrators(self, service, sample_emergency_request):
        """Test administrator notification"""
        administrators = [
            {'userId': 'admin_1', 'name': 'Admin One', 'email': 'admin1@example.com'},
            {'userId': 'admin_2', 'name': 'Admin Two', 'email': 'admin2@example.com'}
        ]
        
        result = await service._notify_administrators(sample_emergency_request, administrators)
        
        assert result == 2  # Both admins notified
        assert len(sample_emergency_request.notification_log) == 2
        
        # Verify notification log entries
        for notification in sample_emergency_request.notification_log:
            assert notification['notificationType'] == 'emergency_request'
            assert notification['delivered'] is True
    
    @pytest.mark.asyncio
    async def test_activate_emergency_access(self, service, sample_emergency_request):
        """Test emergency access activation"""
        # Mock Firestore operations
        mock_session_ref = Mock()
        mock_request_ref = Mock()
        
        service.db.collection.return_value.document.side_effect = [mock_session_ref, mock_request_ref]
        
        service._log_emergency_activation = AsyncMock()
        service._schedule_session_expiration = AsyncMock()
        
        result = await service._activate_emergency_access(sample_emergency_request)
        
        assert result['success'] is True
        assert 'sessionId' in result
        assert 'expiresAt' in result
        
        # Verify session was created
        mock_session_ref.set.assert_called_once()
        
        # Verify request was updated
        mock_request_ref.update.assert_called_once()
        
        # Verify logging and scheduling
        service._log_emergency_activation.assert_called_once()
        service._schedule_session_expiration.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_expire_emergency_session(self, service):
        """Test emergency session expiration"""
        session_id = 'session_123'
        
        # Mock Firestore operations
        mock_session_ref = Mock()
        service.db.collection.return_value.document.return_value = mock_session_ref
        
        service._generate_post_incident_report = AsyncMock()
        
        result = await service._expire_emergency_session(session_id)
        
        assert result is True
        
        # Verify session was updated
        mock_session_ref.update.assert_called_once()
        update_call = mock_session_ref.update.call_args[0][0]
        assert update_call['status'] == 'expired'
        
        # Verify post-incident report generation
        service._generate_post_incident_report.assert_called_once_with(session_id)
    
    def test_emergency_type_enum(self):
        """Test emergency type enumeration"""
        assert EmergencyType.SYSTEM_OUTAGE.value == "system_outage"
        assert EmergencyType.SECURITY_INCIDENT.value == "security_incident"
        assert EmergencyType.DATA_RECOVERY.value == "data_recovery"
        assert EmergencyType.CRITICAL_MAINTENANCE.value == "critical_maintenance"
    
    def test_urgency_level_enum(self):
        """Test urgency level enumeration"""
        assert UrgencyLevel.CRITICAL.value == "critical"
        assert UrgencyLevel.HIGH.value == "high"
        assert UrgencyLevel.MEDIUM.value == "medium"
    
    def test_emergency_request_status_enum(self):
        """Test emergency request status enumeration"""
        assert EmergencyRequestStatus.PENDING.value == "pending"
        assert EmergencyRequestStatus.APPROVED.value == "approved"
        assert EmergencyRequestStatus.DENIED.value == "denied"
        assert EmergencyRequestStatus.ACTIVE.value == "active"
        assert EmergencyRequestStatus.EXPIRED.value == "expired"
        assert EmergencyRequestStatus.COMPLETED.value == "completed"
    
    @pytest.mark.asyncio
    async def test_error_handling(self, service):
        """Test error handling in various scenarios"""
        # Test with invalid request data
        result = await service.submit_emergency_request(None)
        assert result['success'] is False
        assert 'error' in result
        
        # Test approval processing with non-existent request
        mock_doc = Mock()
        mock_doc.exists = False
        
        mock_doc_ref = Mock()
        mock_doc_ref.get.return_value = mock_doc
        service.db.collection.return_value.document.return_value = mock_doc_ref
        
        result = await service.process_approval('nonexistent', 'admin_1', 'approved')
        assert result['success'] is False
        assert 'not found' in result['error']
    
    def test_constants(self, service):
        """Test service constants"""
        assert service.APPROVAL_TIMEOUT_MINUTES == 30
        assert service.MAX_SESSION_DURATION_HOURS == 2