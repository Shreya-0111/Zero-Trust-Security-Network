"""
Integration tests for JIT access request, approval, monitoring, and expiration
Tests end-to-end JIT access lifecycle with ML-enhanced policy evaluation
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock
from datetime import datetime, timedelta


class TestJITAccessIntegration:
    """Integration tests for JIT access workflow"""
    
    @pytest.fixture
    def jit_service(self):
        """Mock JIT access service"""
        service = Mock()
        return service
    
    @pytest.fixture
    def sample_request_data(self):
        """Sample JIT access request data"""
        return {
            "userId": "user_123",
            "resourceSegmentId": "research_labs",
            "justification": "Need access to research lab equipment for urgent data analysis project. The experiment is time-sensitive and requires immediate access to specialized hardware.",
            "durationHours": 4,
            "urgency": "high",
            "deviceInfo": {
                "fingerprint": "device_fingerprint_hash",
                "trustScore": 85
            },
            "ipAddress": "192.168.1.100",
            "timestamp": datetime.utcnow()
        }
    
    @pytest.fixture
    def mock_user(self):
        """Mock user data"""
        return Mock(
            user_id="user_123",
            role="faculty",
            department="Computer Science",
            security_clearance=3,
            is_active=True
        )
    
    @pytest.fixture
    def mock_resource_segment(self):
        """Mock resource segment data"""
        segment = Mock()
        segment.segment_id = "research_labs"
        segment.name = "Research Labs"
        segment.security_level = 3
        segment.is_active = True
        segment.requires_jit = True
        segment.requires_dual_approval = False
        segment.can_user_access.return_value = (True, "Access granted")
        return segment
    
    @pytest.mark.asyncio
    async def test_complete_jit_access_request_workflow(self, jit_service):
        """Test complete JIT access request and approval workflow"""
        # Mock JIT request evaluation
        jit_service.evaluate_jit_request = AsyncMock(return_value={
            "decision": "granted",
            "confidenceScore": 88.0,
            "requiresApproval": False,
            "expiresAt": (datetime.utcnow() + timedelta(hours=4)).isoformat(),
            "riskAssessment": {"riskScore": 25.0},
            "mlEvaluation": {"mlConfidence": 88.0}
        })
        
        # Execute JIT request evaluation
        result = await jit_service.evaluate_jit_request({
            "userId": "user_123",
            "resourceSegmentId": "research_labs",
            "justification": "Need access for urgent data analysis",
            "durationHours": 4
        })
        
        # Verify evaluation result
        assert result["decision"] == "granted"
        assert result["confidenceScore"] >= 85
        assert result["requiresApproval"] is False
        assert "expiresAt" in result
    
    @pytest.mark.asyncio
    async def test_jit_access_dual_approval_workflow(self, jit_service):
        """Test JIT access requiring dual approval for high-security segments"""
        # Mock dual approval requirement
        jit_service.evaluate_jit_request = AsyncMock(return_value={
            "decision": "pending_approval",
            "requiresApproval": True,
            "mfaRequired": True,
            "message": "Dual approval required for Administrative Systems (Security Level 5)"
        })
        
        # Execute JIT request evaluation
        result = await jit_service.evaluate_jit_request({
            "resourceSegmentId": "admin_systems"
        })
        
        # Verify dual approval is required
        assert result["decision"] == "pending_approval"
        assert result["requiresApproval"] is True
        assert result["mfaRequired"] is True
        assert "Dual approval required" in result["message"]
    
    @pytest.mark.asyncio
    async def test_jit_access_denial_workflow(self, jit_service):
        """Test JIT access denial for high-risk requests"""
        # Mock high-risk denial
        jit_service.evaluate_jit_request = AsyncMock(return_value={
            "decision": "denied",
            "requiresApproval": False,
            "message": "Access denied due to: Unrecognized device, Unusual access time"
        })
        
        # Execute JIT request evaluation
        result = await jit_service.evaluate_jit_request({
            "userId": "user_123",
            "resourceSegmentId": "research_labs"
        })
        
        # Verify denial
        assert result["decision"] == "denied"
        assert result["requiresApproval"] is False
        assert "Access denied due to:" in result["message"]
    
    @pytest.mark.asyncio
    async def test_jit_access_monitoring_workflow(self, jit_service):
        """Test JIT access monitoring during active session"""
        # Mock monitoring
        jit_service.monitor_jit_session = Mock(return_value={
            "success": True,
            "grantId": "grant_123",
            "status": "active",
            "timeRemaining": 10800,  # 3 hours in seconds
            "activityCount": 1,
            "complianceScore": 95.0,
            "anomaliesDetected": 0
        })
        
        # Execute monitoring
        result = jit_service.monitor_jit_session("grant_123")
        
        # Verify monitoring result
        assert result["success"] is True
        assert result["status"] == "active"
        assert result["timeRemaining"] == 10800
        assert result["complianceScore"] == 95.0
    
    @pytest.mark.asyncio
    async def test_jit_access_automatic_expiration_workflow(self, jit_service):
        """Test automatic JIT access expiration"""
        # Mock auto-expiration
        jit_service.auto_expire_grants = Mock(return_value={
            "expired_count": 2,
            "expired_grants": ["grant_1", "grant_2"]
        })
        
        # Execute auto-expiration
        result = jit_service.auto_expire_grants()
        
        # Verify expiration results
        assert result["expired_count"] == 2
        assert "grant_1" in result["expired_grants"]
        assert "grant_2" in result["expired_grants"]
    
    @pytest.mark.asyncio
    async def test_jit_access_ml_model_integration_workflow(self, jit_service, sample_request_data):
        """Test ML model integration in JIT access evaluation"""
        # Mock ML model predictions
        mock_features = [0.8, 0.7, 0.9, 0.6, 0.5, 0.8, 0.9, 0.6, 0.6, 1.0, 0.0, 0.17, 0.6, 0.5, 0.2]
        
        with patch.object(jit_service, '_extract_ml_features', return_value=mock_features):
            # Mock scaler
            jit_service.scaler.transform = Mock(return_value=[mock_features])
            
            # Mock ML model predictions
            jit_service.ml_models['confidence'].predict_proba = Mock(return_value=[[0.15, 0.85]])
            jit_service.ml_models['anomaly'].decision_function = Mock(return_value=[0.2])
            jit_service.ml_models['anomaly'].predict = Mock(return_value=[1])  # Not anomaly
            
            # Mock feature importance
            jit_service.ml_models['confidence'].feature_importances_ = [0.1] * 15
            
            # Execute ML evaluation
            result = await jit_service._apply_ml_evaluation(
                sample_request_data, {"riskScore": 30.0}, Mock(), Mock()
            )
            
            # Verify ML evaluation results
            assert result["mlConfidence"] == 85.0
            assert result["anomalyScore"] == 0.2
            assert result["isAnomaly"] is False
            assert "featureImportance" in result
    
    @pytest.mark.asyncio
    async def test_jit_access_peer_analysis_workflow(self, jit_service, mock_user):
        """Test peer analysis component of JIT access evaluation"""
        # Mock peer data
        mock_peer_docs = []
        for i in range(3):
            mock_doc = Mock()
            mock_doc.to_dict.return_value = {
                "userId": f"peer_{i}",
                "role": "faculty",
                "department": "Computer Science"
            }
            mock_peer_docs.append(mock_doc)
        
        # Mock Firestore query for peers
        mock_query = Mock()
        mock_query.limit.return_value.stream.return_value = mock_peer_docs
        
        jit_service.db.collection.return_value.where.return_value.where.return_value = mock_query
        
        # Mock peer JIT history
        with patch.object(jit_service, '_get_user_jit_history') as mock_history:
            mock_history.return_value = [
                {
                    "resourceSegmentId": "research_labs",
                    "status": "granted",
                    "timestamp": datetime.utcnow() - timedelta(days=5)
                }
            ]
            
            with patch.object(jit_service, '_analyze_peer_patterns') as mock_analyze:
                mock_analyze.return_value = 75.0  # Good peer match
                
                # Execute peer analysis
                result = await jit_service._evaluate_peer_analysis(
                    mock_user, Mock(segment_id="research_labs"), {"resourceSegmentId": "research_labs"}
                )
                
                # Verify peer analysis result
                assert result == 75.0
    
    @pytest.mark.asyncio
    async def test_jit_access_temporal_modeling_workflow(self, jit_service):
        """Test temporal access modeling in JIT evaluation"""
        user_id = "user_123"
        
        # Mock user's historical access patterns
        historical_requests = [
            {"timestamp": datetime.utcnow().replace(hour=9)},   # 9 AM
            {"timestamp": datetime.utcnow().replace(hour=14)},  # 2 PM
            {"timestamp": datetime.utcnow().replace(hour=16)},  # 4 PM
        ]
        
        with patch.object(jit_service, '_get_user_jit_history', return_value=historical_requests):
            with patch.object(jit_service, '_calculate_temporal_similarity') as mock_similarity:
                mock_similarity.side_effect = [80.0, 90.0]  # Hour and day similarity
                
                # Test request during typical hours
                request_data = {
                    "timestamp": datetime.utcnow().replace(hour=10, minute=0)  # 10 AM
                }
                
                result = await jit_service._evaluate_temporal_patterns(user_id, request_data)
                
                # Should have high score for typical time
                assert result == 85.0  # (80 + 90) / 2
    
    @pytest.mark.asyncio
    async def test_jit_access_justification_quality_workflow(self, jit_service):
        """Test justification quality evaluation"""
        # Test high-quality justification
        good_justification = """
        I need access to the research lab equipment for a critical data analysis project 
        that is required for tomorrow's client presentation. The specialized hardware 
        in the lab is necessary to process the large dataset within the deadline.
        This access is urgent and necessary for project completion.
        """
        
        score = jit_service._evaluate_justification_quality(good_justification)
        assert score >= 80  # Should get high score
        
        # Test poor justification
        poor_justification = "need access"
        
        score = jit_service._evaluate_justification_quality(poor_justification)
        assert score <= 30  # Should get low score
        
        # Test empty justification
        empty_justification = ""
        
        score = jit_service._evaluate_justification_quality(empty_justification)
        assert score == 0  # Should get zero score
    
    @pytest.mark.asyncio
    async def test_jit_access_error_handling_workflow(self, jit_service, sample_request_data):
        """Test error handling throughout JIT access workflow"""
        # Test with non-existent user
        with patch('app.services.jit_access_service.get_user_by_id', return_value=None):
            result = await jit_service.evaluate_jit_request(sample_request_data)
            
            assert result["decision"] == "denied"
            assert "User not found" in result["message"]
        
        # Test with inactive resource segment
        inactive_segment = Mock()
        inactive_segment.is_active = False
        
        with patch('app.services.jit_access_service.get_user_by_id', return_value=Mock()):
            with patch('app.services.jit_access_service.get_resource_segment_by_id', return_value=inactive_segment):
                result = await jit_service.evaluate_jit_request(sample_request_data)
                
                assert result["decision"] == "denied"
                assert "not active" in result["message"]
    
    @pytest.mark.asyncio
    async def test_jit_access_concurrent_requests_workflow(self, jit_service, mock_user, mock_resource_segment):
        """Test handling of concurrent JIT access requests"""
        # Create multiple concurrent requests
        request_data_1 = {
            "userId": "user_123",
            "resourceSegmentId": "research_labs",
            "justification": "First request for lab access",
            "durationHours": 2
        }
        
        request_data_2 = {
            "userId": "user_123", 
            "resourceSegmentId": "library_services",
            "justification": "Second request for library access",
            "durationHours": 3
        }
        
        with patch('app.services.jit_access_service.get_user_by_id', return_value=mock_user):
            with patch('app.services.jit_access_service.get_resource_segment_by_id', return_value=mock_resource_segment):
                
                # Mock risk assessments
                jit_service._calculate_risk_score = AsyncMock(return_value={
                    "riskScore": 20.0,
                    "riskFactors": []
                })
                
                jit_service._apply_ml_evaluation = AsyncMock(return_value={
                    "mlConfidence": 90.0,
                    "isAnomaly": False
                })
                
                # Execute concurrent requests
                results = await asyncio.gather(
                    jit_service.evaluate_jit_request(request_data_1),
                    jit_service.evaluate_jit_request(request_data_2)
                )
                
                # Both should be processed successfully
                assert all(result["decision"] == "granted" for result in results)
                assert len(results) == 2