"""
Unit tests for JIT Access Service
Tests JIT access policy evaluation, ML integration, and request processing
"""

import pytest
import numpy as np
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime, timedelta

from app.services.jit_access_service import JITAccessService, JITAccessRequest, JITAccessStatus
from app.models.resource_segment import ResourceSegment
from app.models.user import User


class TestJITAccessService:
    """Unit tests for JITAccessService"""
    
    @pytest.fixture
    def service(self):
        """Create JITAccessService instance for testing"""
        mock_db = Mock()
        service = JITAccessService(mock_db)
        
        # Mock ML models to avoid loading issues
        service.ml_models = {
            'confidence': Mock(),
            'anomaly': Mock()
        }
        service.scaler = Mock()
        
        return service
    
    @pytest.fixture
    def sample_user(self):
        """Sample user for testing"""
        return Mock(
            user_id="user_123",
            role="faculty",
            department="Computer Science",
            email="user@example.com",
            name="Test User"
        )
    
    @pytest.fixture
    def sample_resource_segment(self):
        """Sample resource segment for testing"""
        segment = Mock()
        segment.segment_id = "segment_123"
        segment.name = "Research Labs"
        segment.security_level = 3
        segment.is_active = True
        segment.requires_dual_approval = False
        segment.can_user_access = Mock(return_value=(True, "Access granted"))
        return segment
    
    @pytest.fixture
    def sample_request_data(self):
        """Sample JIT access request data"""
        return {
            'userId': 'user_123',
            'resourceSegmentId': 'segment_123',
            'justification': 'I need access to the research lab to conduct experiments for my ongoing project on machine learning algorithms. This access is required to complete the data collection phase of my research.',
            'durationHours': 4,
            'urgency': 'medium',
            'deviceInfo': {
                'fingerprint': 'device_fingerprint_hash',
                'trustScore': 85
            },
            'ipAddress': '192.168.1.100',
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def test_jit_access_request_creation(self):
        """Test JIT access request model creation"""
        request = JITAccessRequest(
            user_id="user_123",
            resource_segment_id="segment_123",
            justification="Need access for research",
            duration_hours=2,
            urgency="high"
        )
        
        assert request.user_id == "user_123"
        assert request.resource_segment_id == "segment_123"
        assert request.duration_hours == 2
        assert request.urgency == "high"
        assert request.status == JITAccessStatus.PENDING
        assert isinstance(request.requested_at, datetime)
    
    def test_jit_access_request_serialization(self):
        """Test JIT access request to/from dict conversion"""
        request = JITAccessRequest(
            user_id="user_123",
            resource_segment_id="segment_123",
            justification="Need access for research",
            duration_hours=2
        )
        
        # Test to_dict
        request_dict = request.to_dict()
        assert request_dict['userId'] == "user_123"
        assert request_dict['resourceSegmentId'] == "segment_123"
        assert request_dict['status'] == "pending"
        
        # Test from_dict
        restored_request = JITAccessRequest.from_dict(request_dict)
        assert restored_request.user_id == request.user_id
        assert restored_request.resource_segment_id == request.resource_segment_id
        assert restored_request.status == request.status
    
    @pytest.mark.asyncio
    async def test_evaluate_jit_request_success(self, service, sample_request_data, sample_user, sample_resource_segment):
        """Test successful JIT access request evaluation"""
        # Mock dependencies
        with patch('app.services.jit_access_service.get_user_by_id', return_value=sample_user), \
             patch('app.services.jit_access_service.get_resource_segment_by_id', return_value=sample_resource_segment):
            
            # Mock internal methods
            service._calculate_risk_score = AsyncMock(return_value={
                'riskScore': 75.0,
                'deviceFingerprint': 85.0,
                'behavioralPatterns': 70.0,
                'peerAnalysis': 80.0,
                'temporalModeling': 75.0,
                'historicalPatterns': 65.0,
                'justificationQuality': 80.0,
                'riskFactors': []
            })
            
            service._apply_ml_evaluation = AsyncMock(return_value={
                'mlConfidence': 82.0,
                'anomalyScore': 0.1,
                'isAnomaly': False,
                'featureImportance': {}
            })
            
            service._generate_approval_recommendations = Mock(return_value=[
                "Low risk profile - recommend approval"
            ])
            
            result = await service.evaluate_jit_request(sample_request_data)
            
            assert result['decision'] == 'pending_approval'  # Below auto-approve threshold
            assert result['confidenceScore'] > 0
            assert 'riskAssessment' in result
            assert 'mlEvaluation' in result
            assert 'approvalRecommendations' in result
    
    @pytest.mark.asyncio
    async def test_evaluate_jit_request_user_not_found(self, service, sample_request_data):
        """Test JIT request evaluation when user doesn't exist"""
        with patch('app.services.jit_access_service.get_user_by_id', return_value=None):
            result = await service.evaluate_jit_request(sample_request_data)
            
            assert result['decision'] == 'denied'
            assert 'User not found' in result['message']
            assert result['confidenceScore'] == 0
    
    @pytest.mark.asyncio
    async def test_evaluate_jit_request_resource_not_found(self, service, sample_request_data, sample_user):
        """Test JIT request evaluation when resource segment doesn't exist"""
        with patch('app.services.jit_access_service.get_user_by_id', return_value=sample_user), \
             patch('app.services.jit_access_service.get_resource_segment_by_id', return_value=None):
            
            result = await service.evaluate_jit_request(sample_request_data)
            
            assert result['decision'] == 'denied'
            assert 'Resource segment not found' in result['message']
    
    @pytest.mark.asyncio
    async def test_evaluate_jit_request_no_permission(self, service, sample_request_data, sample_user, sample_resource_segment):
        """Test JIT request evaluation when user lacks permission"""
        sample_resource_segment.can_user_access = Mock(return_value=(False, "Insufficient clearance"))
        
        with patch('app.services.jit_access_service.get_user_by_id', return_value=sample_user), \
             patch('app.services.jit_access_service.get_resource_segment_by_id', return_value=sample_resource_segment):
            
            result = await service.evaluate_jit_request(sample_request_data)
            
            assert result['decision'] == 'denied'
            assert 'Insufficient clearance' in result['message']
    
    @pytest.mark.asyncio
    async def test_calculate_risk_score(self, service, sample_request_data, sample_user, sample_resource_segment):
        """Test comprehensive risk score calculation"""
        # Mock individual evaluation methods
        service._evaluate_device_fingerprint = AsyncMock(return_value=85.0)
        service._evaluate_behavioral_patterns = AsyncMock(return_value=75.0)
        service._evaluate_peer_analysis = AsyncMock(return_value=80.0)
        service._evaluate_temporal_patterns = AsyncMock(return_value=70.0)
        service._evaluate_historical_patterns = AsyncMock(return_value=65.0)
        service._evaluate_justification_quality = Mock(return_value=80.0)
        service._identify_risk_factors = Mock(return_value=['unusual_time'])
        
        result = await service._calculate_risk_score(sample_request_data, sample_user, sample_resource_segment)
        
        assert 'riskScore' in result
        assert 'deviceFingerprint' in result
        assert 'behavioralPatterns' in result
        assert 'peerAnalysis' in result
        assert 'temporalModeling' in result
        assert 'historicalPatterns' in result
        assert 'justificationQuality' in result
        assert 'riskFactors' in result
        
        # Verify weighted calculation
        expected_score = (
            85.0 * service.WEIGHT_DEVICE_FINGERPRINT +
            75.0 * service.WEIGHT_BEHAVIORAL_PATTERNS +
            80.0 * service.WEIGHT_PEER_ANALYSIS +
            70.0 * service.WEIGHT_TEMPORAL_MODELING +
            65.0 * service.WEIGHT_HISTORICAL_PATTERNS +
            80.0 * service.WEIGHT_JUSTIFICATION_QUALITY
        )
        
        assert abs(result['riskScore'] - expected_score) < 0.1
    
    @pytest.mark.asyncio
    async def test_evaluate_device_fingerprint(self, service):
        """Test device fingerprint evaluation"""
        user_id = "user_123"
        device_info = {
            'fingerprint': 'device_hash',
            'trustScore': 90
        }
        
        # Mock device fingerprint service
        with patch('app.services.jit_access_service.device_fingerprint_service') as mock_service:
            mock_service.validate_device_fingerprint.return_value = {
                'is_valid': True,
                'trust_score': 90,
                'similarity': 95.0
            }
            
            result = await service._evaluate_device_fingerprint(user_id, device_info)
            
            assert result == 100.0  # 90 + 10 bonus for valid device
    
    @pytest.mark.asyncio
    async def test_evaluate_device_fingerprint_unrecognized(self, service):
        """Test device fingerprint evaluation for unrecognized device"""
        user_id = "user_123"
        device_info = {
            'fingerprint': 'unknown_device_hash'
        }
        
        with patch('app.services.jit_access_service.device_fingerprint_service') as mock_service:
            mock_service.validate_device_fingerprint.return_value = {
                'is_valid': False,
                'similarity': 60.0
            }
            
            result = await service._evaluate_device_fingerprint(user_id, device_info)
            
            assert result == 48.0  # 60 * 0.8
    
    @pytest.mark.asyncio
    async def test_evaluate_behavioral_patterns(self, service):
        """Test behavioral pattern evaluation"""
        user_id = "user_123"
        request_data = {'timestamp': datetime.utcnow()}
        
        with patch('app.services.jit_access_service.behavioral_biometrics') as mock_biometrics:
            mock_biometrics.analyze_request_behavior.return_value = {
                'is_consistent': True,
                'confidence': 85
            }
            
            result = await service._evaluate_behavioral_patterns(user_id, request_data)
            
            assert result == 90.0  # 85 + 5 bonus for consistent behavior
    
    @pytest.mark.asyncio
    async def test_evaluate_peer_analysis(self, service, sample_user, sample_resource_segment, sample_request_data):
        """Test peer analysis evaluation"""
        # Mock peer query
        mock_docs = []
        for i in range(3):
            mock_doc = Mock()
            mock_doc.to_dict.return_value = {
                'userId': f'peer_{i}',
                'role': 'faculty',
                'department': 'Computer Science'
            }
            mock_docs.append(mock_doc)
        
        mock_query = Mock()
        mock_query.limit.return_value.stream.return_value = mock_docs
        service.db.collection.return_value.where.return_value.where.return_value = mock_query
        
        # Mock peer request history
        service._get_user_jit_history = Mock(return_value=[
            {'resourceSegmentId': 'segment_123', 'status': 'granted', 'durationHours': 4, 'urgency': 'medium'},
            {'resourceSegmentId': 'segment_123', 'status': 'granted', 'durationHours': 3, 'urgency': 'medium'},
            {'resourceSegmentId': 'segment_123', 'status': 'denied', 'durationHours': 8, 'urgency': 'low'}
        ])
        
        result = await service._evaluate_peer_analysis(sample_user, sample_resource_segment, sample_request_data)
        
        assert result > 0
        assert result <= 100
    
    @pytest.mark.asyncio
    async def test_evaluate_temporal_patterns(self, service):
        """Test temporal pattern evaluation"""
        user_id = "user_123"
        
        # Test business hours request
        business_hour_request = {
            'timestamp': datetime.now().replace(hour=14, minute=0).isoformat()  # 2 PM
        }
        
        service._get_user_jit_history = Mock(return_value=[])
        
        result = await service._evaluate_temporal_patterns(user_id, business_hour_request)
        
        assert result == 80.0  # Business hours score
        
        # Test off-hours request
        off_hour_request = {
            'timestamp': datetime.now().replace(hour=2, minute=0).isoformat()  # 2 AM
        }
        
        result = await service._evaluate_temporal_patterns(user_id, off_hour_request)
        
        assert result == 30.0  # Off hours score
    
    @pytest.mark.asyncio
    async def test_evaluate_historical_patterns(self, service):
        """Test historical pattern evaluation"""
        user_id = "user_123"
        segment_id = "segment_123"
        
        # Mock successful history
        service._get_user_segment_history = Mock(return_value=[
            {'status': 'granted', 'grantedAt': datetime.utcnow() - timedelta(days=10)},
            {'status': 'granted', 'grantedAt': datetime.utcnow() - timedelta(days=20)},
            {'status': 'denied', 'grantedAt': datetime.utcnow() - timedelta(days=30)}
        ])
        
        service._is_recent = Mock(return_value=True)
        
        result = await service._evaluate_historical_patterns(user_id, segment_id)
        
        # Should be high due to good approval rate and recent success
        assert result > 70
        
        # Test no history
        service._get_user_segment_history = Mock(return_value=[])
        
        result = await service._evaluate_historical_patterns(user_id, segment_id)
        
        assert result == 50.0  # Neutral score for new access
    
    def test_evaluate_justification_quality(self, service):
        """Test justification quality evaluation"""
        # Test good justification
        good_justification = "I need access to the research lab to conduct experiments for my ongoing project on machine learning algorithms. This access is required to complete the data collection phase of my research which has a deadline next week."
        
        result = service._evaluate_justification_quality(good_justification)
        
        assert result > 70  # Should score well
        
        # Test poor justification
        poor_justification = "need access"
        
        result = service._evaluate_justification_quality(poor_justification)
        
        assert result < 30  # Should score poorly
        
        # Test empty justification
        result = service._evaluate_justification_quality("")
        
        assert result == 0.0
    
    @pytest.mark.asyncio
    async def test_apply_ml_evaluation(self, service, sample_request_data, sample_user, sample_resource_segment):
        """Test ML model evaluation"""
        risk_assessment = {
            'riskScore': 75.0,
            'deviceFingerprint': 85.0,
            'behavioralPatterns': 70.0
        }
        
        # Mock ML model predictions
        service.ml_models['confidence'].predict_proba.return_value = [[0.2, 0.8]]  # 80% approval probability
        service.ml_models['anomaly'].decision_function.return_value = [0.5]
        service.ml_models['anomaly'].predict.return_value = [1]  # Not anomaly
        service.scaler.transform.return_value = [[0.1, 0.2, 0.3]]
        
        # Mock feature importance
        service.ml_models['confidence'].feature_importances_ = [0.1, 0.2, 0.3]
        service._get_feature_names = Mock(return_value=['feature1', 'feature2', 'feature3'])
        
        result = await service._apply_ml_evaluation(sample_request_data, risk_assessment, sample_user, sample_resource_segment)
        
        assert result['mlConfidence'] == 80.0
        assert result['anomalyScore'] == 0.5
        assert result['isAnomaly'] is False
        assert 'featureImportance' in result
    
    def test_extract_ml_features(self, service, sample_request_data, sample_user, sample_resource_segment):
        """Test ML feature extraction"""
        risk_assessment = {
            'riskScore': 75.0,
            'deviceFingerprint': 85.0,
            'behavioralPatterns': 70.0,
            'peerAnalysis': 80.0,
            'temporalModeling': 75.0,
            'historicalPatterns': 65.0,
            'justificationQuality': 80.0
        }
        
        features = service._extract_ml_features(sample_request_data, risk_assessment, sample_user, sample_resource_segment)
        
        assert len(features) == 15  # Expected number of features
        assert all(0 <= f <= 1 for f in features)  # All features should be normalized
    
    def test_calculate_confidence_score(self, service):
        """Test confidence score calculation"""
        risk_assessment = {'riskScore': 80.0}
        ml_evaluation = {'mlConfidence': 85.0, 'isAnomaly': False}
        
        result = service._calculate_confidence_score(risk_assessment, ml_evaluation)
        
        expected = (80.0 * 0.6) + (85.0 * 0.4)  # Weighted combination
        assert abs(result - expected) < 0.1
        
        # Test with anomaly penalty
        ml_evaluation['isAnomaly'] = True
        result = service._calculate_confidence_score(risk_assessment, ml_evaluation)
        
        expected_with_penalty = expected * 0.7  # 30% penalty
        assert abs(result - expected_with_penalty) < 0.1
    
    def test_make_jit_decision(self, service, sample_resource_segment):
        """Test JIT access decision making"""
        risk_assessment = {'riskFactors': []}
        
        # Test auto-approve
        result = service._make_jit_decision(90.0, sample_resource_segment, risk_assessment)
        assert result['decision'] == 'granted'
        assert result['requiresApproval'] is False
        
        # Test require approval
        result = service._make_jit_decision(70.0, sample_resource_segment, risk_assessment)
        assert result['decision'] == 'pending_approval'
        assert result['requiresApproval'] is True
        
        # Test auto-deny
        result = service._make_jit_decision(20.0, sample_resource_segment, risk_assessment)
        assert result['decision'] == 'denied'
        assert result['requiresApproval'] is False
        
        # Test dual approval requirement
        sample_resource_segment.requires_dual_approval = True
        result = service._make_jit_decision(95.0, sample_resource_segment, risk_assessment)
        assert result['decision'] == 'pending_approval'
        assert result['requiresApproval'] is True
    
    def test_generate_approval_recommendations(self, service, sample_resource_segment):
        """Test approval recommendation generation"""
        risk_assessment = {
            'riskScore': 85.0,
            'riskFactors': ['unusual_time', 'poor_justification']
        }
        ml_evaluation = {
            'mlConfidence': 80.0,
            'isAnomaly': False
        }
        
        recommendations = service._generate_approval_recommendations(
            risk_assessment, ml_evaluation, sample_resource_segment
        )
        
        assert len(recommendations) > 0
        assert len(recommendations) <= 5  # Limited to 5 recommendations
        assert any('Low risk profile' in rec for rec in recommendations)
        assert any('Unusual access time' in rec for rec in recommendations)
        assert any('Weak justification' in rec for rec in recommendations)
    
    def test_analyze_peer_patterns(self, service, sample_request_data, sample_resource_segment):
        """Test peer pattern analysis"""
        peer_requests = [
            {'resourceSegmentId': 'segment_123', 'status': 'granted', 'durationHours': 4, 'urgency': 'medium'},
            {'resourceSegmentId': 'segment_123', 'status': 'granted', 'durationHours': 3, 'urgency': 'medium'},
            {'resourceSegmentId': 'segment_123', 'status': 'denied', 'durationHours': 8, 'urgency': 'low'},
            {'resourceSegmentId': 'other_segment', 'status': 'granted', 'durationHours': 2, 'urgency': 'high'}
        ]
        
        result = service._analyze_peer_patterns(sample_request_data, peer_requests, sample_resource_segment)
        
        assert result > 0
        assert result <= 100
        
        # Test with no peer data
        result = service._analyze_peer_patterns(sample_request_data, [], sample_resource_segment)
        assert result == 50.0
    
    def test_calculate_temporal_similarity(self, service):
        """Test temporal similarity calculation"""
        # Test exact match
        result = service._calculate_temporal_similarity(14, [14, 15, 13, 14, 16])
        assert result == 40.0  # 2 out of 5 matches = 40%
        
        # Test nearby match
        result = service._calculate_temporal_similarity(14, [15, 16, 17])
        assert result == 80.0  # Nearby similarity (±1)
        
        # Test no historical data
        result = service._calculate_temporal_similarity(14, [])
        assert result == 50.0
    
    def test_identify_risk_factors(self, service):
        """Test risk factor identification"""
        risk_factors = service._identify_risk_factors(
            device_score=40.0,  # Below 50
            behavioral_score=30.0,  # Below 40
            peer_score=35.0,  # Below 40
            temporal_score=25.0,  # Below 30
            historical_score=20.0,  # Below 30
            justification_score=35.0  # Below 40
        )
        
        expected_factors = [
            'unrecognized_device',
            'unusual_behavior',
            'atypical_request',
            'unusual_time',
            'poor_history',
            'poor_justification'
        ]
        
        assert all(factor in risk_factors for factor in expected_factors)
    
    def test_get_user_security_clearance(self, service):
        """Test user security clearance determination"""
        # Test different roles
        student_user = Mock(role='student')
        assert service._get_user_security_clearance(student_user) == 1
        
        faculty_user = Mock(role='faculty')
        assert service._get_user_security_clearance(faculty_user) == 3
        
        admin_user = Mock(role='admin')
        assert service._get_user_security_clearance(admin_user) == 5
        
        unknown_user = Mock(role='unknown')
        assert service._get_user_security_clearance(unknown_user) == 1
    
    def test_get_user_jit_history(self, service):
        """Test user JIT history retrieval"""
        user_id = "user_123"
        
        # Mock Firestore query
        mock_docs = []
        for i in range(3):
            mock_doc = Mock()
            mock_doc.to_dict.return_value = {'requestId': f'req_{i}', 'status': 'granted'}
            mock_docs.append(mock_doc)
        
        mock_query = Mock()
        mock_query.stream.return_value = mock_docs
        service.db.collection.return_value.where.return_value.limit.return_value = mock_query
        
        result = service._get_user_jit_history(user_id)
        
        assert len(result) == 3
        assert all('requestId' in req for req in result)
    
    def test_is_recent(self, service):
        """Test recency check"""
        # Test recent timestamp
        recent_time = datetime.utcnow() - timedelta(days=10)
        assert service._is_recent(recent_time, days=30) is True
        
        # Test old timestamp
        old_time = datetime.utcnow() - timedelta(days=40)
        assert service._is_recent(old_time, days=30) is False
        
        # Test string timestamp
        recent_string = (datetime.utcnow() - timedelta(days=10)).isoformat()
        assert service._is_recent(recent_string, days=30) is True
        
        # Test None timestamp
        assert service._is_recent(None, days=30) is False
    
    def test_error_handling(self, service):
        """Test error handling in various scenarios"""
        # Test ML evaluation with missing models
        service.ml_models = {}
        
        # Should handle gracefully and return default values
        result = service._calculate_confidence_score({}, {})
        assert result == 50.0  # Default neutral score
        
        # Test feature extraction with invalid data
        features = service._extract_ml_features({}, {}, Mock(), Mock())
        assert len(features) > 0  # Should still return features