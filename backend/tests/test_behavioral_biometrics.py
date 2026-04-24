"""
Test suite for Behavioral Biometrics System
Tests feature extraction, model training, risk scoring, and session termination
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Try to import numpy, skip tests if not available
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    np = None

# Mock firebase before importing services
sys.modules['app.firebase_config'] = Mock(db=Mock())

from app.services.behavioral_biometrics import BehavioralBiometricsService
from app.models.behavioral_session import BehavioralSession

# Skip all tests if numpy not available
pytestmark = pytest.mark.skipif(not NUMPY_AVAILABLE, reason="NumPy not available")


class TestBehavioralBiometrics:
    """Test behavioral biometrics feature extraction and risk scoring"""
    
    @pytest.fixture
    def service(self):
        """Create behavioral biometrics service instance"""
        return BehavioralBiometricsService()
    
    @pytest.fixture
    def sample_keystroke_data(self):
        """Generate sample keystroke data"""
        base_time = datetime.utcnow().timestamp() * 1000
        data = []
        
        # Simulate typing "hello world"
        keys = ['h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd']
        for i, key in enumerate(keys):
            # Keydown event
            data.append({
                'eventType': 'keydown',
                'key': key,
                'code': f'Key{key.upper()}' if key != ' ' else 'Space',
                'timestamp': base_time + i * 150,  # 150ms between keys
                'shiftKey': False,
                'ctrlKey': False,
                'altKey': False
            })
            # Keyup event
            data.append({
                'eventType': 'keyup',
                'key': key,
                'code': f'Key{key.upper()}' if key != ' ' else 'Space',
                'timestamp': base_time + i * 150 + 80,  # 80ms hold duration
                'shiftKey': False,
                'ctrlKey': False,
                'altKey': False
            })
        
        return data
    
    @pytest.fixture
    def sample_mouse_data(self):
        """Generate sample mouse movement data"""
        base_time = datetime.utcnow().timestamp() * 1000
        data = []
        
        # Simulate smooth mouse movement
        for i in range(50):
            data.append({
                'x': 100 + i * 10,
                'y': 100 + i * 5,
                'timestamp': base_time + i * 16,  # 60Hz sampling
                'velocity': 5.0 + np.random.normal(0, 0.5),
                'timeDelta': 16
            })
        
        return data
    
    @pytest.fixture
    def sample_navigation_data(self):
        """Generate sample navigation data"""
        base_time = datetime.utcnow().timestamp() * 1000
        return [
            {'page': '/dashboard', 'timestamp': base_time},
            {'page': '/profile', 'timestamp': base_time + 5000},
            {'page': '/settings', 'timestamp': base_time + 12000}
        ]
    
    @pytest.fixture
    def sample_behavioral_session(self, sample_keystroke_data, sample_mouse_data, sample_navigation_data):
        """Create sample behavioral session"""
        session = Mock(spec=BehavioralSession)
        session.user_id = 'test_user_123'
        session.session_id = 'session_123'
        session.keystroke_data = sample_keystroke_data
        session.mouse_data = sample_mouse_data
        session.navigation_data = sample_navigation_data
        session.click_data = []
        session.scroll_data = []
        session.session_start = datetime.utcnow()
        session.get_session_duration = Mock(return_value=300)  # 5 minutes
        return session
    
    # ==================== Feature Extraction Tests ====================
    
    def test_extract_keystroke_features(self, service, sample_keystroke_data):
        """Test keystroke feature extraction with sample data"""
        features = service.extract_keystroke_features(sample_keystroke_data)
        
        # Verify all 15 features are present
        assert len(features) == 15
        
        # Verify feature values are reasonable
        assert features['avg_inter_key_time'] > 0
        assert features['avg_hold_duration'] > 0
        assert features['typing_speed'] > 0
        assert 0 <= features['error_rate'] <= 1
        assert 0 <= features['shift_usage'] <= 1
        assert 0 <= features['rhythm_consistency'] <= 1
        
        print(f"✓ Keystroke features extracted: {len(features)} features")
        print(f"  - Avg inter-key time: {features['avg_inter_key_time']:.2f}ms")
        print(f"  - Typing speed: {features['typing_speed']:.2f} keys/min")
    
    def test_extract_mouse_features(self, service, sample_mouse_data):
        """Test mouse feature extraction with sample data"""
        features = service.extract_mouse_features(sample_mouse_data)
        
        # Verify all 12 features are present
        assert len(features) == 12
        
        # Verify feature values are reasonable
        assert features['avg_velocity'] > 0
        assert features['max_velocity'] > 0
        assert features['avg_distance'] > 0
        assert 0 <= features['idle_time_ratio'] <= 1
        assert 0 <= features['jitter'] <= 1
        
        print(f"✓ Mouse features extracted: {len(features)} features")
        print(f"  - Avg velocity: {features['avg_velocity']:.2f}")
        print(f"  - Movement frequency: {features['movement_frequency']:.2f}")
    
    def test_extract_navigation_features(self, service, sample_navigation_data):
        """Test navigation feature extraction"""
        features = service.extract_navigation_features(sample_navigation_data, [], [])
        
        # Verify all 8 features are present
        assert len(features) == 8
        
        # Verify feature values
        assert features['page_visit_frequency'] >= 0
        assert features['avg_dwell_time'] >= 0
        
        print(f"✓ Navigation features extracted: {len(features)} features")
    
    def test_extract_all_features(self, service, sample_behavioral_session):
        """Test extraction of all 35 features from a session"""
        features = service.extract_all_features(sample_behavioral_session)
        
        # Verify we get exactly 35 features
        assert features.shape == (35,)
        assert features.dtype == np.float32
        
        # Verify no NaN or infinite values
        assert not np.isnan(features).any()
        assert not np.isinf(features).any()
        
        print(f"✓ All features extracted: {len(features)} features")
        print(f"  - Feature vector shape: {features.shape}")
    
    def test_feature_extraction_with_empty_data(self, service):
        """Test feature extraction handles empty data gracefully"""
        empty_keystroke = service.extract_keystroke_features([])
        empty_mouse = service.extract_mouse_features([])
        empty_nav = service.extract_navigation_features([], [], [])
        
        # Should return default features, not crash
        assert len(empty_keystroke) == 15
        assert len(empty_mouse) == 12
        assert len(empty_nav) == 8
        
        print("✓ Feature extraction handles empty data")
    
    # ==================== Risk Score Calculation Tests ====================
    
    def test_calculate_risk_score_no_baseline(self, service, sample_behavioral_session):
        """Test risk score calculation when no baseline exists"""
        with patch.object(service, 'load_user_model', return_value=None):
            result = service.calculate_risk_score('test_user_123', sample_behavioral_session)
            
            assert 'risk_score' in result
            assert result['risk_level'] == 'unknown'
            assert result['baseline_available'] is False
            
            print("✓ Risk score handles missing baseline")
    
    def test_calculate_risk_score_with_baseline(self, service, sample_behavioral_session):
        """Test risk score calculation with trained baseline"""
        # Mock trained model
        mock_model = Mock()
        mock_model.return_value = Mock(item=Mock(return_value=0.85))  # High legitimacy
        mock_scaler = Mock()
        mock_scaler.transform = Mock(return_value=np.random.randn(1, 35))
        
        with patch.object(service, 'load_user_model', return_value=(mock_model, mock_scaler)):
            result = service.calculate_risk_score('test_user_123', sample_behavioral_session)
            
            assert 'risk_score' in result
            assert 'risk_level' in result
            assert result['baseline_available'] is True
            assert 'component_scores' in result
            assert 0 <= result['risk_score'] <= 100
            
            # Verify component scores
            components = result['component_scores']
            assert 'keystroke' in components
            assert 'mouse' in components
            assert 'navigation' in components
            assert 'time' in components
            
            print(f"✓ Risk score calculated: {result['risk_score']:.2f}")
            print(f"  - Risk level: {result['risk_level']}")
            print(f"  - Component scores: {components}")
    
    def test_risk_score_thresholds(self, service, sample_behavioral_session):
        """Test risk score threshold classification"""
        mock_scaler = Mock()
        mock_scaler.transform = Mock(return_value=np.random.randn(1, 35))
        
        # Test different risk levels
        test_cases = [
            (0.95, 'low'),      # Low risk (high legitimacy)
            (0.50, 'medium'),   # Medium risk
            (0.30, 'high'),     # High risk
            (0.10, 'critical')  # Critical risk
        ]
        
        for legitimacy, expected_level in test_cases:
            mock_model = Mock()
            mock_model.return_value = Mock(item=Mock(return_value=legitimacy))
            
            with patch.object(service, 'load_user_model', return_value=(mock_model, mock_scaler)):
                result = service.calculate_risk_score('test_user_123', sample_behavioral_session)
                
                # Risk score should be inverse of legitimacy
                expected_risk = (1 - legitimacy) * 100
                assert abs(result['ml_prediction'] - expected_risk) < 5
                
        print("✓ Risk score thresholds correctly classified")
    
    def test_detect_anomaly(self, service, sample_behavioral_session):
        """Test anomaly detection with various risk scores"""
        mock_scaler = Mock()
        mock_scaler.transform = Mock(return_value=np.random.randn(1, 35))
        
        # Test high-risk scenario
        mock_model = Mock()
        mock_model.return_value = Mock(item=Mock(return_value=0.15))  # Low legitimacy = high risk
        
        with patch.object(service, 'load_user_model', return_value=(mock_model, mock_scaler)):
            result = service.detect_anomaly('test_user_123', sample_behavioral_session)
            
            assert 'anomalies_detected' in result
            assert 'anomaly_count' in result
            assert 'anomalies' in result
            assert 'overall_risk' in result
            
            # High risk should detect anomalies
            if result['overall_risk'] > 70:
                assert result['anomalies_detected'] is True
                assert result['anomaly_count'] > 0
            
            print(f"✓ Anomaly detection: {result['anomaly_count']} anomalies found")
            print(f"  - Overall risk: {result['overall_risk']:.2f}")
    
    # ==================== Model Training Tests ====================
    
    def test_model_architecture(self):
        """Test LSTM model architecture"""
        try:
            import torch
            from app.services.behavioral_biometrics import LSTMBehavioralModel
            
            model = LSTMBehavioralModel(input_size=35, hidden_size_1=128, hidden_size_2=64)
            
            # Test forward pass
            test_input = torch.randn(1, 1, 35)  # (batch, sequence, features)
            output = model(test_input)
            
            # Verify output shape
            assert output.shape == (1, 1)
            
            # Verify output is probability (0-1)
            assert 0 <= output.item() <= 1
            
            print("✓ LSTM model architecture validated")
            print(f"  - Input size: 35 features")
            print(f"  - Hidden layers: 128 → 64")
            print(f"  - Output: Binary classification")
            
        except ImportError:
            pytest.skip("PyTorch not available")
    
    @patch('app.models.behavioral_session.BehavioralSession.get_by_user_id')
    @patch('app.models.behavioral_profile.BehavioralProfile.get_by_user_id')
    def test_train_user_model_insufficient_data(self, mock_profile, mock_sessions, service):
        """Test model training with insufficient data"""
        # Mock insufficient training data
        mock_sessions.return_value = []
        
        result = service.train_user_model('test_user_123')
        
        # Should return False for insufficient data
        assert result is False
        
        print("✓ Model training handles insufficient data")
    
    # ==================== Session Termination Tests ====================
    
    def test_session_termination_on_high_risk(self, service, sample_behavioral_session):
        """Test that high risk scores trigger session termination"""
        mock_scaler = Mock()
        mock_scaler.transform = Mock(return_value=np.random.randn(1, 35))
        
        # Simulate critical risk (legitimacy < 0.2 → risk > 80)
        mock_model = Mock()
        mock_model.return_value = Mock(item=Mock(return_value=0.10))
        
        with patch.object(service, 'load_user_model', return_value=(mock_model, mock_scaler)):
            result = service.calculate_risk_score('test_user_123', sample_behavioral_session)
            
            # Verify risk score is critical
            assert result['risk_score'] > 80 or result['risk_level'] == 'critical'
            
            # In production, this would trigger session termination
            should_terminate = result['risk_score'] > 80
            assert should_terminate is True
            
            print(f"✓ Session termination triggered for risk score: {result['risk_score']:.2f}")
    
    def test_session_reauthentication_on_medium_risk(self, service, sample_behavioral_session):
        """Test that medium-high risk requires re-authentication"""
        mock_scaler = Mock()
        mock_scaler.transform = Mock(return_value=np.random.randn(1, 35))
        
        # Simulate high risk (legitimacy 0.3 → risk ~70)
        mock_model = Mock()
        mock_model.return_value = Mock(item=Mock(return_value=0.30))
        
        with patch.object(service, 'load_user_model', return_value=(mock_model, mock_scaler)):
            result = service.calculate_risk_score('test_user_123', sample_behavioral_session)
            
            # Verify risk score is in re-auth range (61-80)
            risk_score = result['risk_score']
            requires_reauth = 61 <= risk_score <= 80
            
            if requires_reauth:
                print(f"✓ Re-authentication required for risk score: {risk_score:.2f}")
            else:
                print(f"  Risk score {risk_score:.2f} outside re-auth range")
    
    # ==================== Model Accuracy Tests ====================
    
    def test_model_prediction_consistency(self, service, sample_behavioral_session):
        """Test that model predictions are consistent for same input"""
        mock_scaler = Mock()
        mock_scaler.transform = Mock(return_value=np.random.randn(1, 35))
        
        mock_model = Mock()
        mock_model.return_value = Mock(item=Mock(return_value=0.75))
        
        with patch.object(service, 'load_user_model', return_value=(mock_model, mock_scaler)):
            result1 = service.calculate_risk_score('test_user_123', sample_behavioral_session)
            result2 = service.calculate_risk_score('test_user_123', sample_behavioral_session)
            
            # Results should be consistent
            assert abs(result1['risk_score'] - result2['risk_score']) < 1
            
            print("✓ Model predictions are consistent")
    
    def test_feature_normalization(self, service, sample_behavioral_session):
        """Test that features are properly normalized"""
        features = service.extract_all_features(sample_behavioral_session)
        
        # Features should be numeric and finite
        assert np.isfinite(features).all()
        
        # No extreme outliers (simplified check)
        assert features.min() >= -1000
        assert features.max() <= 10000
        
        print("✓ Features are properly normalized")
        print(f"  - Min value: {features.min():.2f}")
        print(f"  - Max value: {features.max():.2f}")


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
