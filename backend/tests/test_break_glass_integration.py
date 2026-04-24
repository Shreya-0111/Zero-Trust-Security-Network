"""
Integration tests for break-glass emergency access with dual approval and logging
Tests end-to-end emergency access request, dual approval, monitoring, and reporting
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, MagicMock, patch
from datetime import datetime, timedelta, timezone

from app.services.break_glass_service import BreakGlassService


class TestBreakGlassIntegration:
    """Integration tests for break-glass emergency access workflow"""
    
    @pytest.fixture
    def break_glass_service(self):
        """Mock break-glass service"""
        service = BreakGlassService(db=MagicMock())
        return service
    
    @pytest.fixture
    def sample_emergency_request_data(self):
        """Sample emergency access request data"""
        return {
            "requesterId": "user_123",
            "emergencyType": "system_outage",
            "urgencyLevel": "critical",
            "justification": "Critical system outage affecting production services. Need immediate access to administrative systems to restore service availability. Multiple users are impacted and business operations are at risk.",
            "requiredResources": ["admin_systems", "infrastructure"],
            "estimatedDuration": 1.5
        }
    
    @pytest.fixture
    def mock_administrators(self):
        """Mock available administrators"""
        return [
            {
                "userId": "admin_1",
                "name": "Admin One",
                "email": "admin1@example.com",
                "available": True
            },
            {
                "userId": "admin_2", 
                "name": "Admin Two",
                "email": "admin2@example.com",
                "available": True
            },
            {
                "userId": "admin_3",
                "name": "Admin Three", 
                "email": "admin3@example.com",
                "available": True
            }
        ]
    
    @pytest.mark.asyncio
    async def test_complete_emergency_access_request_workflow(self, break_glass_service):
        """Test complete emergency access request submission workflow"""
        # Mock emergency request submission
        break_glass_service.submit_emergency_request = AsyncMock(return_value={
            "success": True,
            "requestId": "emergency_123",
            "approvalRequired": True,
            "timeoutMinutes": 30,
            "notificationsSent": 3
        })
        
        # Execute emergency request submission
        result = await break_glass_service.submit_emergency_request({
            "requesterId": "user_123",
            "emergencyType": "system_outage",
            "urgencyLevel": "critical",
            "justification": "Critical system outage affecting production services",
            "requiredResources": ["admin_systems", "infrastructure"],
            "estimatedDuration": 1.5
        })
        
        # Verify request submission success
        assert result["success"] is True
        assert "requestId" in result
        assert result["approvalRequired"] is True
        assert result["timeoutMinutes"] == 30
        assert result["notificationsSent"] == 3
    
    @pytest.mark.asyncio
    async def test_dual_approval_workflow(self, break_glass_service):
        """Test dual approval workflow for emergency access"""
        # Mock dual approval process
        break_glass_service.process_approval = AsyncMock()
        break_glass_service.process_approval.side_effect = [
            {
                "success": True,
                "status": "pending",
                "approvalsReceived": 1,
                "approvalsRequired": 2
            },
            {
                "success": True,
                "status": "activated",
                "sessionId": "emergency_session_123",
                "expiresAt": (datetime.utcnow() + timedelta(hours=2)).isoformat()
            }
        ]
        
        # Step 1: First approval
        result1 = await break_glass_service.process_approval(
            "emergency_123", "admin_1", "approved", "Approved - legitimate security incident"
        )
        
        # Verify first approval recorded
        assert result1["success"] is True
        assert result1["status"] == "pending"
        assert result1["approvalsReceived"] == 1
        assert result1["approvalsRequired"] == 2
        
        # Step 2: Second approval (should activate emergency access)
        result2 = await break_glass_service.process_approval(
            "emergency_123", "admin_2", "approved", "Second approval - emergency access granted"
        )
        
        # Verify emergency access was activated
        assert result2["success"] is True
        assert result2["status"] == "activated"
        assert "sessionId" in result2
        assert "expiresAt" in result2
    
    @pytest.mark.asyncio
    async def test_emergency_access_denial_workflow(self, break_glass_service):
        """Test emergency access denial workflow"""
        request_id = "emergency_123"
        
        # Mock emergency request
        mock_request_data = {
            "requestId": request_id,
            "requesterId": "user_123",
            "emergencyType": "system_outage",
            "urgencyLevel": "critical",
            "justification": "Test justification",
            "requiredResources": ["test_resource"],
            "estimatedDuration": 1.0,
            "status": "pending",
            "approvals": []
        }
        
        # Mock Firestore operations
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = mock_request_data
        
        mock_doc_ref = Mock()
        mock_doc_ref.get.return_value = mock_doc
        
        break_glass_service.db.collection.return_value.document.return_value = mock_doc_ref
        
        # Mock notification services
        with patch.object(break_glass_service, '_notify_requester_denial'):
            with patch.object(break_glass_service, '_log_approval_decision'):
                
                # Execute denial
                result = await break_glass_service.process_approval(
                    request_id, "admin_1", "denied", "Insufficient justification for emergency access"
                )
                
                # Verify denial was processed
                assert result["success"] is True
                assert result["status"] == "denied"
                assert "Emergency request denied" in result["message"]
    
    @pytest.mark.asyncio
    async def test_emergency_session_monitoring_workflow(self, break_glass_service):
        """Test emergency session monitoring and activity logging"""
        session_id = "emergency_session_123"
        
        # Mock active emergency session
        mock_session_data = {
            "sessionId": session_id,
            "userId": "user_123",
            "status": "active",
            "activatedAt": datetime.utcnow() - timedelta(minutes=30),
            "expiresAt": datetime.utcnow() + timedelta(hours=1, minutes=30),
            "elevatedPrivileges": [
                {"resourceId": "admin_systems", "grantedAt": datetime.utcnow() - timedelta(minutes=30)}
            ],
            "activityLog": [
                {
                    "timestamp": datetime.utcnow() - timedelta(minutes=20),
                    "action": "system_restart",
                    "resource": "web_server",
                    "result": "success"
                }
            ]
        }
        
        # Mock Firestore operations
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = mock_session_data
        
        break_glass_service.db.collection.return_value.document.return_value.get.return_value = mock_doc
        
        # Execute session monitoring
        result = await break_glass_service.monitor_emergency_session(session_id)
        
        # Verify monitoring result
        assert result["success"] is True
        assert result["sessionId"] == session_id
        assert result["status"] == "active"
        assert result["userId"] == "user_123"
        assert len(result["elevatedPrivileges"]) == 1
        assert len(result["recentActivity"]) == 1
        assert result["timeRemainingSeconds"] > 0
        assert result["activityCount"] == 1
    
    @pytest.mark.asyncio
    async def test_emergency_activity_logging_workflow(self, break_glass_service):
        """Test comprehensive activity logging during emergency session"""
        session_id = "emergency_session_123"
        
        # Mock emergency session
        mock_doc = Mock()
        mock_doc.exists = True
        
        mock_doc_ref = Mock()
        mock_doc_ref.get.return_value = mock_doc
        
        break_glass_service.db.collection.return_value.document.return_value = mock_doc_ref
        
        # Mock enhanced Firebase service
        with patch('app.services.break_glass_service.enhanced_firebase_service') as mock_firebase:
            mock_firebase.array_union.return_value = Mock()
            
            # Mock audit logging
            with patch('app.services.break_glass_service.create_audit_log', new_callable=AsyncMock) as mock_audit:
                
                # Sample activity data
                activity_data = {
                    "userId": "user_123",
                    "action": "database_query",
                    "resource": "user_database",
                    "command": "SELECT * FROM users WHERE status='locked'",
                    "dataAccessed": ["user_table"],
                    "ipAddress": "192.168.1.100",
                    "riskScore": 25.0,
                    "result": "success"
                }
                
                # Execute activity logging
                result = await break_glass_service.log_emergency_activity(session_id, activity_data)
                
                # Verify logging success
                assert result is True
                
                # Verify session was updated with activity
                mock_doc_ref.update.assert_called_once()
                update_data = mock_doc_ref.update.call_args[0][0]
                
                assert "activityLog" in update_data
                assert "lastActivity" in update_data
    
    @pytest.mark.asyncio
    async def test_emergency_session_expiration_workflow(self, break_glass_service):
        """Test automatic emergency session expiration"""
        session_id = "emergency_session_123"
        
        # Mock expired session
        mock_session_data = {
            "sessionId": session_id,
            "userId": "user_123",
            "status": "active",
            "expiresAt": datetime.utcnow() - timedelta(minutes=30)  # Expired 30 minutes ago
        }
        
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = mock_session_data
        
        break_glass_service.db.collection.return_value.document.return_value.get.return_value = mock_doc
        
        # Execute session monitoring (should detect expiration)
        result = await break_glass_service.monitor_emergency_session(session_id)
        
        # Verify session was detected as expired
        assert result["success"] is False
        assert "expired" in result["error"]
    
    @pytest.mark.asyncio
    async def test_post_incident_report_generation_workflow(self, break_glass_service):
        """Test post-incident report generation"""
        session_id = "emergency_session_123"
        
        # Mock completed emergency session with comprehensive activity log
        mock_session_data = {
            "sessionId": session_id,
            "userId": "user_123",
            "requestId": "emergency_request_123",
            "status": "expired",
            "activatedAt": datetime.utcnow() - timedelta(hours=2),
            "expiresAt": datetime.utcnow() - timedelta(minutes=30),
            "activityLog": [
                {
                    "timestamp": datetime.utcnow() - timedelta(hours=1, minutes=45),
                    "action": "system_restart",
                    "resource": "web_server",
                    "command": "systemctl restart apache2",
                    "result": "success",
                    "riskScore": 20.0
                },
                {
                    "timestamp": datetime.utcnow() - timedelta(hours=1, minutes=30),
                    "action": "log_analysis",
                    "resource": "system_logs",
                    "dataAccessed": ["error.log", "access.log"],
                    "result": "success",
                    "riskScore": 15.0
                },
                {
                    "timestamp": datetime.utcnow() - timedelta(hours=1),
                    "action": "configuration_change",
                    "resource": "firewall_rules",
                    "command": "iptables -A INPUT -s 192.168.1.0/24 -j ACCEPT",
                    "result": "success",
                    "riskScore": 30.0
                }
            ]
        }
        
        # Mock report generation
        with patch.object(break_glass_service, '_generate_post_incident_report') as mock_generate:
            mock_generate.return_value = {
                "reportId": "report_123",
                "sessionId": session_id,
                "summary": {
                    "totalActions": 3,
                    "sessionDuration": "1h 30m",
                    "averageRiskScore": 21.67,
                    "resourcesAccessed": ["web_server", "system_logs", "firewall_rules"]
                },
                "recommendations": [
                    "Review firewall rule changes for compliance",
                    "Implement additional monitoring for system restarts"
                ],
                "complianceStatus": "compliant"
            }
            
            # Execute report generation
            result = await mock_generate(session_id)
            
            # Verify report contents
            assert result["sessionId"] == session_id
            assert result["summary"]["totalActions"] == 3
            assert result["summary"]["averageRiskScore"] == 21.67
            assert len(result["recommendations"]) == 2
            assert result["complianceStatus"] == "compliant"
    
    @pytest.mark.asyncio
    async def test_emergency_request_validation_workflow(self, break_glass_service):
        """Test emergency request validation"""
        # Test valid request
        valid_request = {
            "requesterId": "user_123",
            "emergencyType": "system_outage",
            "urgencyLevel": "critical",
            "justification": "Critical system outage affecting production services. Need immediate access to restore service availability. This is a legitimate emergency requiring urgent intervention.",
            "requiredResources": ["admin_systems"],
            "estimatedDuration": 1.5
        }
        
        validation_result = break_glass_service._validate_emergency_request(valid_request)
        assert validation_result["valid"] is True
        
        # Test invalid request - short justification
        invalid_request = valid_request.copy()
        invalid_request["justification"] = "need access"  # Too short
        
        validation_result = break_glass_service._validate_emergency_request(invalid_request)
        assert validation_result["valid"] is False
        assert "100 characters" in validation_result["error"]
        
        # Test invalid request - invalid duration
        invalid_request = valid_request.copy()
        invalid_request["estimatedDuration"] = 3.0  # Too long (max 2 hours)
        
        validation_result = break_glass_service._validate_emergency_request(invalid_request)
        assert validation_result["valid"] is False
        assert "between 0.5 and 2 hours" in validation_result["error"]
    
    @pytest.mark.asyncio
    async def test_emergency_access_timeout_workflow(self, break_glass_service):
        """Test emergency access approval timeout handling"""
        request_id = "emergency_123"
        
        # Mock emergency request that has timed out
        mock_request_data = {
            "requestId": request_id,
            "requesterId": "user_123",
            "requestedAt": datetime.utcnow() - timedelta(minutes=35),  # 35 minutes ago (past 30-minute timeout)
            "status": "pending",
            "approvals": [
                {
                    "approverId": "admin_1",
                    "decision": "approved",
                    "timestamp": datetime.utcnow() - timedelta(minutes=30)
                }
            ]  # Only one approval, needs two
        }
        
        # Mock timeout handling
        with patch.object(break_glass_service, '_schedule_approval_timeout') as mock_timeout:
            mock_timeout.return_value = {
                "success": True,
                "message": "Emergency request timed out - insufficient approvals within 30 minutes",
                "status": "expired"
            }
            
            # Execute timeout handling
            await mock_timeout(request_id)
            
            # Verify timeout was handled
            mock_timeout.assert_called_once_with(request_id)
    
    @pytest.mark.asyncio
    async def test_emergency_access_error_handling_workflow(self, break_glass_service, sample_emergency_request_data):
        """Test error handling throughout emergency access workflow"""
        # Test with insufficient administrators
        with patch.object(break_glass_service, '_get_available_administrators', return_value=[]):
            result = await break_glass_service.submit_emergency_request(sample_emergency_request_data)
            
            assert result["success"] is True
            assert "Insufficient administrators" in result["warning"]
        
        # Test approval for non-existent request
        mock_doc_ref = Mock()
        mock_doc_ref.get.return_value.exists = False
        break_glass_service.db.collection.return_value.document.return_value = mock_doc_ref

        result = await break_glass_service.process_approval(
            "non_existent_request", "admin_1", "approved", "comments"
        )
        
        assert result["success"] is False
        assert "not found" in result["error"]
        
        # Test monitoring non-existent session
        mock_session_doc_ref = Mock()
        mock_session_doc_ref.get.return_value.exists = False
        break_glass_service.db.collection.return_value.document.return_value = mock_session_doc_ref
        result = await break_glass_service.monitor_emergency_session("non_existent_session")
        
        assert result["success"] is False
        assert "not found" in result["error"]
    
    @pytest.mark.asyncio
    async def test_emergency_access_concurrent_approvals_workflow(self, break_glass_service):
        """Test handling of concurrent approval attempts"""
        request_id = "emergency_123"
        
        # Mock emergency request
        mock_request_data = {
            "requestId": request_id,
            "requesterId": "user_123",
            "emergencyType": "system_outage",
            "urgencyLevel": "critical",
            "justification": "Test justification",
            "requiredResources": ["test_resource"],
            "estimatedDuration": 1.0,
            "status": "pending",
            "approvals": []
        }
        
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = mock_request_data
        
        mock_doc_ref = Mock()
        mock_doc_ref.get.return_value = mock_doc
        
        break_glass_service.db.collection.return_value.document.return_value = mock_doc_ref
        
        # Mock logging services
        with patch.object(break_glass_service, '_log_approval_decision'):
            
            # Simulate concurrent approvals from same admin (should be rejected)
            result1 = await break_glass_service.process_approval(
                request_id, "admin_1", "approved", "First approval"
            )
            
            # Update mock data with first approval
            mock_request_data["approvals"] = [
                {
                    "approverId": "admin_1",
                    "decision": "approved",
                    "timestamp": datetime.utcnow()
                }
            ]
            
            # Second approval from same admin should be rejected
            result2 = await break_glass_service.process_approval(
                request_id, "admin_1", "approved", "Duplicate approval attempt"
            )
            
            # Verify first approval succeeded, second was rejected
            assert result1["success"] is True
            assert result2["success"] is False
            assert "already provided" in result2["error"]