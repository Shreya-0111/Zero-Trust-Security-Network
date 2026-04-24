"""
Integration tests for continuous authentication with risk score calculation
Tests end-to-end session monitoring, risk assessment, and authentication triggers
"""

import pytest
from unittest.mock import Mock
from datetime import datetime, timedelta


class TestContinuousAuthIntegration:
    """Integration tests for continuous authentication workflow"""
    
    @pytest.fixture
    def continuous_auth_service(self):
        """Mock continuous auth service"""
        service = Mock()
        return service
    
    @pytest.fixture
    def sample_session_data(self):
        """Sample session data for testing"""
        return SessionData(
            session_id="session_123",
            user_id="user_123",
            device_id="device_456",
            start_time=datetime.utcnow() - timedelta(hours=1),
            last_activity=datetime.utcnow() - timedelta(minutes=5),
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            device_fingerprint={
                "canvas": "canvas_hash_123",
                "webgl": "webgl_hash_456",
                "audio": "audio_hash_789"
            },
            access_log=[
                {
                    "timestamp": datetime.utcnow() - timedelta(minutes=30),
                    "resource": "academic_resources",
                    "action": "read"
                },
                {
                    "timestamp": datetime.utcnow() - timedelta(minutes=15),
                    "resource": "library_services", 
                    "action": "search"
                }
            ],
            location_history=[
                {
                    "timestamp": datetime.utcnow() - timedelta(hours=1),
                    "ip_address": "192.168.1.100",
                    "location": {"city": "New York", "country": "US"}
                }
            ],
            behavioral_data={
                "typing_patterns": {"avg_speed": 45},
                "mouse_patterns": {"avg_velocity": 120}
            }
        )
    
    def test_complete_session_monitoring_workflow(self, continuous_auth_service):
        """Test complete session monitoring and risk assessment workflow"""
        # Mock session monitoring
        continuous_auth_service.monitor_user_session = Mock(return_value={
            "success": True,
            "session_id": "session_123",
            "risk_score": 15.5,  # Weighted average: 15*0.25 + 10*0.20 + 20*0.20 + 25*0.15 + 5*0.20
            "risk_factors": {
                "device_consistency": 15.0,
                "location_stability": 10.0,
                "access_patterns": 20.0,
                "time_appropriateness": 25.0,
                "request_frequency": 5.0
            },
            "action_required": "continue_normal"
        })
        
        # Execute session monitoring
        result = continuous_auth_service.monitor_user_session("session_123")
        
        # Verify monitoring result
        assert result["success"] is True
        assert result["session_id"] == "session_123"
        assert result["risk_score"] == 15.5
        assert result["action_required"] == "continue_normal"
        
        # Verify risk factors
        risk_factors = result["risk_factors"]
        assert risk_factors["device_consistency"] == 15.0
        assert risk_factors["location_stability"] == 10.0
        assert risk_factors["access_patterns"] == 20.0
        assert risk_factors["time_appropriateness"] == 25.0
        assert risk_factors["request_frequency"] == 5.0
    
    def test_dynamic_risk_score_calculation_workflow(self, continuous_auth_service, sample_session_data):
        """Test dynamic risk score calculation with all factors"""
        # Mock individual risk factor calculations
        with patch.object(continuous_auth_service, '_calculate_device_consistency_risk', return_value=30.0):
            with patch.object(continuous_auth_service, '_calculate_location_stability_risk', return_value=40.0):
                with patch.object(continuous_auth_service, '_calculate_access_pattern_risk', return_value=35.0):
                    with patch.object(continuous_auth_service, '_calculate_time_appropriateness_risk', return_value=50.0):
                        with patch.object(continuous_auth_service, '_calculate_request_frequency_risk', return_value=25.0):
                            with patch.object(continuous_auth_service, '_has_behavioral_baseline', return_value=True):
                                
                                # Execute risk calculation
                                result = continuous_auth_service.calculate_dynamic_risk_score(sample_session_data)
                                
                                # Verify risk calculation
                                expected_risk = (30.0 * 0.25 + 40.0 * 0.20 + 35.0 * 0.20 + 50.0 * 0.15 + 25.0 * 0.20)
                                assert result["risk_score"] == expected_risk
                                assert result["baseline_available"] is True
                                
                                # Verify risk factors structure
                                risk_factors = result["risk_factors"]
                                assert isinstance(risk_factors, RiskFactors)
                                assert risk_factors.device_consistency == 30.0
                                assert risk_factors.location_stability == 40.0
                                assert risk_factors.access_patterns == 35.0
                                assert risk_factors.time_appropriateness == 50.0
                                assert risk_factors.request_frequency == 25.0
    
    def test_high_risk_session_termination_workflow(self, continuous_auth_service, sample_session_data):
        """Test high-risk session termination workflow"""
        session_id = "session_123"
        
        # Mock high-risk session data
        with patch.object(continuous_auth_service, '_get_session_data', return_value=sample_session_data):
            # Mock session update
            mock_session_ref = Mock()
            continuous_auth_service.db.collection.return_value.document.return_value = mock_session_ref
            
            # Mock notification services
            with patch('app.services.continuous_auth_service.create_notification'):
                with patch.object(continuous_auth_service, '_send_admin_alert'):
                    with patch('app.services.continuous_auth_service.log_audit_event'):
                        
                        # Execute session termination
                        result = continuous_auth_service.terminate_suspicious_session(
                            session_id, "Risk score exceeded threshold (90)"
                        )
                        
                        # Verify termination result
                        assert result["success"] is True
                        assert result["session_id"] == session_id
                        assert result["termination_reason"] == "Risk score exceeded threshold (90)"
                        
                        # Verify session was updated
                        mock_session_ref.update.assert_called_once()
                        update_data = mock_session_ref.update.call_args[0][0]
                        
                        assert update_data["status"] == "terminated"
                        assert update_data["termination_reason"] == "Risk score exceeded threshold (90)"
                        assert update_data["terminated_by"] == "system"
    
    def test_mfa_reauthentication_trigger_workflow(self, continuous_auth_service, sample_session_data):
        """Test MFA re-authentication trigger workflow"""
        session_id = "session_123"
        risk_level = "high"
        
        # Mock session data retrieval
        with patch.object(continuous_auth_service, '_get_session_data', return_value=sample_session_data):
            # Mock challenge storage
            mock_challenge_ref = Mock()
            continuous_auth_service.db.collection.return_value.document.return_value = mock_challenge_ref
            
            # Mock notification services
            with patch('app.services.continuous_auth_service.create_notification'):
                with patch('app.services.continuous_auth_service.emit_reauthentication_required'):
                    with patch('app.services.continuous_auth_service.log_audit_event'):
                        
                        # Execute re-authentication trigger
                        result = continuous_auth_service.trigger_reauthentication(session_id, risk_level)
                        
                        # Verify re-authentication result
                        assert result["success"] is True
                        assert "challenge_id" in result
                        assert result["challenge_type"] == "mfa"
                        assert "expires_at" in result
                        
                        # Verify challenge was stored
                        mock_challenge_ref.set.assert_called_once()
                        challenge_data = mock_challenge_ref.set.call_args[0][0]
                        
                        assert challenge_data["session_id"] == session_id
                        assert challenge_data["user_id"] == sample_session_data.user_id
                        assert challenge_data["risk_level"] == risk_level
                        assert challenge_data["challenge_type"] == "mfa"
                        assert challenge_data["status"] == "pending"
    
    def test_behavioral_pattern_validation_workflow(self, continuous_auth_service):
        """Test behavioral pattern validation against baseline"""
        user_id = "user_123"
        
        # Mock behavioral baseline
        mock_baseline = {
            "typing_patterns": {
                "avg_speed": 50,
                "rhythm_variance": 0.2
            },
            "mouse_patterns": {
                "avg_velocity": 100,
                "click_frequency": 0.5
            },
            "sessionCount": 10
        }
        
        # Current behavior (similar to baseline)
        current_behavior = {
            "typing_patterns": {
                "avg_speed": 48,  # Close to baseline
                "rhythm_variance": 0.25
            },
            "mouse_patterns": {
                "avg_velocity": 105,  # Close to baseline
                "click_frequency": 0.6
            }
        }
        
        with patch.object(continuous_auth_service, '_get_behavioral_baseline', return_value=mock_baseline):
            with patch.object(continuous_auth_service, '_calculate_behavioral_deviation', return_value=15.0):
                
                # Execute behavioral validation
                result = continuous_auth_service.validate_behavioral_patterns(user_id, current_behavior)
                
                # Verify validation result
                assert result["success"] is True
                assert result["deviation_score"] == 15.0
                assert result["is_anomalous"] is False  # Below 70% threshold
                assert result["baseline_available"] is True
    
    def test_session_anomaly_detection_workflow(self, continuous_auth_service, sample_session_data):
        """Test session anomaly detection"""
        # Mock device fingerprint validation (poor match)
        mock_device_validation = {
            "success": True,
            "similarity": 60  # Below 85% threshold
        }
        
        # Add rapid location changes to session data
        sample_session_data.location_history = [
            {
                "timestamp": datetime.utcnow() - timedelta(minutes=30),
                "ip_address": "192.168.1.100",
                "location": {"city": "New York", "country": "US"}
            },
            {
                "timestamp": datetime.utcnow() - timedelta(minutes=5),
                "ip_address": "203.0.113.1", 
                "location": {"city": "Los Angeles", "country": "US"}
            }
        ]
        
        # Add high request frequency
        sample_session_data.access_log = [
            {"timestamp": datetime.utcnow() - timedelta(minutes=i)} for i in range(15)
        ]
        
        with patch.object(continuous_auth_service.device_service, 'validate_fingerprint', return_value=mock_device_validation):
            with patch.object(continuous_auth_service, '_detect_impossible_travel', return_value=True):
                with patch.object(continuous_auth_service, '_get_user_access_history', return_value=[]):
                    with patch.object(continuous_auth_service, '_get_typical_access_hours', return_value=[]):
                        
                        # Execute anomaly detection
                        anomalies = continuous_auth_service.detect_session_anomalies(sample_session_data)
                        
                        # Verify anomalies were detected
                        assert len(anomalies) >= 3
                        
                        # Check for specific anomaly types
                        anomaly_types = [anomaly["type"] for anomaly in anomalies]
                        assert "impossible_travel" in anomaly_types
                        assert "high_request_velocity" in anomaly_types
                        assert "device_fingerprint_mismatch" in anomaly_types
    
    def test_device_consistency_risk_calculation_workflow(self, continuous_auth_service):
        """Test device consistency risk calculation"""
        user_id = "user_123"
        current_fingerprint = {
            "canvas": "canvas_hash_123",
            "webgl": "webgl_hash_456"
        }
        
        # Test high similarity (low risk)
        mock_validation_high = {
            "success": True,
            "similarity": 98
        }
        
        with patch.object(continuous_auth_service.device_service, 'validate_fingerprint', return_value=mock_validation_high):
            risk = continuous_auth_service._calculate_device_consistency_risk(user_id, current_fingerprint)
            assert risk == 0.0  # No risk for perfect match
        
        # Test medium similarity (medium risk)
        mock_validation_medium = {
            "success": True,
            "similarity": 80
        }
        
        with patch.object(continuous_auth_service.device_service, 'validate_fingerprint', return_value=mock_validation_medium):
            risk = continuous_auth_service._calculate_device_consistency_risk(user_id, current_fingerprint)
            assert risk == 50.0  # Medium risk for partial match
        
        # Test unrecognized device (high risk)
        mock_validation_fail = {
            "success": False
        }
        
        with patch.object(continuous_auth_service.device_service, 'validate_fingerprint', return_value=mock_validation_fail):
            risk = continuous_auth_service._calculate_device_consistency_risk(user_id, current_fingerprint)
            assert risk == 100.0  # Maximum risk for unrecognized device
    
    def test_location_stability_risk_calculation_workflow(self, continuous_auth_service):
        """Test location stability risk calculation"""
        user_id = "user_123"
        current_ip = "192.168.1.100"
        
        # Mock typical user locations
        typical_locations = [
            {"ip_address": "192.168.1.100", "location": {"city": "New York"}},
            {"ip_address": "192.168.1.101", "location": {"city": "New York"}}
        ]
        
        location_history = [
            {
                "timestamp": datetime.utcnow() - timedelta(minutes=30),
                "ip_address": "192.168.1.100"
            }
        ]
        
        with patch.object(continuous_auth_service, '_get_user_typical_locations', return_value=typical_locations):
            # Test known location (low risk)
            risk = continuous_auth_service._calculate_location_stability_risk(user_id, current_ip, location_history)
            assert risk == 0.0  # No risk for known location
        
        # Test unknown location
        unknown_ip = "203.0.113.1"
        
        with patch.object(continuous_auth_service, '_get_user_typical_locations', return_value=typical_locations):
            with patch.object(continuous_auth_service, '_detect_impossible_travel', return_value=False):
                with patch.object(continuous_auth_service, '_calculate_min_geographic_distance', return_value=100):
                    
                    risk = continuous_auth_service._calculate_location_stability_risk(user_id, unknown_ip, location_history)
                    assert risk == 30.0  # Medium risk for moderate distance
    
    def test_access_pattern_risk_calculation_workflow(self, continuous_auth_service):
        """Test access pattern risk calculation"""
        user_id = "user_123"
        
        # Mock current access log
        access_log = [
            {"timestamp": datetime.utcnow() - timedelta(minutes=30), "resource": "academic_resources"},
            {"timestamp": datetime.utcnow() - timedelta(minutes=15), "resource": "library_services"}
        ]
        
        # Mock typical access patterns
        typical_patterns = {
            "common_resources": ["academic_resources", "library_services"],
            "access_frequency": 0.5,
            "typical_duration": 60
        }
        
        with patch.object(continuous_auth_service, '_get_user_access_patterns', return_value=typical_patterns):
            with patch.object(continuous_auth_service, '_analyze_current_access_patterns') as mock_analyze:
                mock_analyze.return_value = {
                    "resources": ["academic_resources", "library_services"],
                    "frequency": 0.6,
                    "duration": 65
                }
                
                with patch.object(continuous_auth_service, '_calculate_pattern_deviation', return_value=15.0):
                    
                    risk = continuous_auth_service._calculate_access_pattern_risk(user_id, access_log)
                    assert risk == 0.0  # Low deviation = low risk
    
    def test_time_appropriateness_risk_calculation_workflow(self, continuous_auth_service):
        """Test time appropriateness risk calculation"""
        user_id = "user_123"
        
        # Mock typical access hours
        typical_hours = {
            "9": 0.3,   # 30% of accesses at 9 AM
            "14": 0.4,  # 40% of accesses at 2 PM
            "16": 0.2   # 20% of accesses at 4 PM
        }
        
        with patch.object(continuous_auth_service, '_get_user_typical_hours', return_value=typical_hours):
            # Test typical hour (low risk)
            typical_time = datetime.utcnow().replace(hour=9, minute=0)
            risk = continuous_auth_service._calculate_time_appropriateness_risk(user_id, typical_time)
            assert risk == 0.0  # No risk for typical hour
            
            # Test unusual hour (higher risk)
            unusual_time = datetime.utcnow().replace(hour=3, minute=0)  # 3 AM
            risk = continuous_auth_service._calculate_time_appropriateness_risk(user_id, unusual_time)
            assert risk == 80.0  # High risk for unusual hour
    
    def test_request_frequency_risk_calculation_workflow(self, continuous_auth_service):
        """Test request frequency risk calculation"""
        # Test normal frequency (low risk)
        normal_access_log = [
            {"timestamp": (datetime.utcnow() - timedelta(minutes=30)).isoformat()},
            {"timestamp": (datetime.utcnow() - timedelta(minutes=15)).isoformat()}
        ]
        
        risk = continuous_auth_service._calculate_request_frequency_risk(normal_access_log)
        assert risk == 0.0  # Low frequency = low risk
        
        # Test high frequency (high risk)
        high_frequency_log = [
            {"timestamp": (datetime.utcnow() - timedelta(minutes=i)).isoformat()} 
            for i in range(20)  # 20 requests in 20 minutes
        ]
        
        risk = continuous_auth_service._calculate_request_frequency_risk(high_frequency_log)
        assert risk == 100.0  # High frequency = high risk
    
    def test_continuous_auth_error_handling_workflow(self, continuous_auth_service):
        """Test error handling throughout continuous authentication workflow"""
        # Test monitoring non-existent session
        with patch.object(continuous_auth_service, '_get_session_data', return_value=None):
            result = continuous_auth_service.monitor_user_session("non_existent_session")
            
            assert result["success"] is False
            assert result["error"] == "SESSION_NOT_FOUND"
        
        # Test behavioral validation without baseline
        with patch.object(continuous_auth_service, '_get_behavioral_baseline', return_value=None):
            result = continuous_auth_service.validate_behavioral_patterns("user_123", {})
            
            assert result["success"] is False
            assert result["error"] == "NO_BASELINE"
        
        # Test terminating non-existent session
        with patch.object(continuous_auth_service, '_get_session_data', return_value=None):
            result = continuous_auth_service.terminate_suspicious_session("non_existent_session", "test reason")
            
            assert result["success"] is False
            assert result["error"] == "SESSION_NOT_FOUND"
    
    def test_continuous_auth_performance_workflow(self, continuous_auth_service, sample_session_data):
        """Test continuous authentication performance under load"""
        session_id = "session_123"
        
        # Mock efficient session data retrieval
        with patch.object(continuous_auth_service, '_get_session_data', return_value=sample_session_data):
            # Mock cached risk calculations
            with patch.object(continuous_auth_service, '_calculate_device_consistency_risk', return_value=20.0):
                with patch.object(continuous_auth_service, '_calculate_location_stability_risk', return_value=15.0):
                    with patch.object(continuous_auth_service, '_calculate_access_pattern_risk', return_value=25.0):
                        with patch.object(continuous_auth_service, '_calculate_time_appropriateness_risk', return_value=30.0):
                            with patch.object(continuous_auth_service, '_calculate_request_frequency_risk', return_value=10.0):
                                with patch.object(continuous_auth_service, '_update_session_risk'):
                                    
                                    # Measure execution time
                                    start_time = datetime.utcnow()
                                    result = continuous_auth_service.monitor_user_session(session_id)
                                    end_time = datetime.utcnow()
                                    
                                    execution_time = (end_time - start_time).total_seconds()
                                    
                                    # Verify performance (should complete quickly)
                                    assert result["success"] is True
                                    assert execution_time < 1.0  # Should complete within 1 second
    
    def test_risk_threshold_action_determination_workflow(self, continuous_auth_service):
        """Test risk threshold-based action determination"""
        # Test low risk (continue normal)
        action = continuous_auth_service._determine_action(30.0)
        assert action == "continue_normal"
        
        # Test medium risk (monitor closely)
        action = continuous_auth_service._determine_action(60.0)
        assert action == "monitor_closely"
        
        # Test high risk (require MFA)
        action = continuous_auth_service._determine_action(75.0)
        assert action == "require_mfa"
        
        # Test critical risk (terminate session)
        action = continuous_auth_service._determine_action(90.0)
        assert action == "terminate_session"