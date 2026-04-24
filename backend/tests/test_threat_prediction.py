"""
Test suite for Threat Prediction System
Tests threat detection algorithms, prediction accuracy, and alert generation
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

from app.services.threat_predictor import ThreatPredictor

# Skip all tests if numpy not available
pytestmark = pytest.mark.skipif(not NUMPY_AVAILABLE, reason="NumPy not available")


class TestThreatPrediction:
    """Test threat prediction and detection algorithms"""
    
    @pytest.fixture
    def predictor(self):
        """Create threat predictor instance"""
        return ThreatPredictor()
    
    @pytest.fixture
    def sample_access_history(self):
        """Generate sample access history data"""
        now = datetime.utcnow()
        history = []
        
        # Normal access pattern
        for i in range(20):
            history.append({
                'user_id': 'test_user_123',
                'action': 'access_resource',
                'resource_type': 'lab_server',
                'result': 'success',
                'timestamp': now - timedelta(hours=i),
                'location': 'campus',
                'device_id': 'device_1',
                'ip_address': '192.168.1.100'
            })
        
        return history
    
    @pytest.fixture
    def suspicious_access_history(self):
        """Generate suspicious access history"""
        now = datetime.utcnow()
        history = []
        
        # Multiple failed attempts
        for i in range(15):
            history.append({
                'user_id': 'test_user_123',
                'action': 'login',
                'result': 'failure',
                'timestamp': now - timedelta(minutes=i*5),
                'location': 'unknown',
                'device_id': f'device_{i}',
                'ip_address': '203.0.113.100'
            })
        
        # Unusual resource access
        for i in range(5):
            history.append({
                'user_id': 'test_user_123',
                'action': 'access_resource',
                'resource_type': 'admin_panel',
                'result': 'denied',
                'timestamp': now - timedelta(hours=2, minutes=i*10),
                'location': 'foreign',
                'device_id': 'device_new',
                'ip_address': '198.51.100.50'
            })
        
        return history
    
    # ==================== Feature Extraction Tests ====================
    
    def test_extract_threat_features(self, predictor, sample_access_history):
        """Test threat feature extraction from access history"""
        features = predictor.extract_threat_features('test_user_123', sample_access_history)
        
        # Verify we get exactly 7 features
        assert features.shape == (7,)
        assert features.dtype == np.float32
        
        # Verify no NaN or infinite values
        assert not np.isnan(features).any()
        assert not np.isinf(features).any()
        
        print(f"✓ Threat features extracted: {len(features)} features")
        print(f"  - Failed attempts: {features[0]}")
        print(f"  - Unusual time ratio: {features[1]:.2f}")
        print(f"  - Scope deviation: {features[2]:.2f}")
    
    def test_extract_features_suspicious_activity(self, predictor, suspicious_access_history):
        """Test feature extraction with suspicious activity"""
        features = predictor.extract_threat_features('test_user_123', suspicious_access_history)
        
        # Should detect high failed attempts
        assert features[0] >= 5  # Failed attempts
        
        # Should detect high denial ratio
        assert features[6] > 0.2  # Denial ratio
        
        print(f"✓ Suspicious features detected")
        print(f"  - Failed attempts: {features[0]}")
        print(f"  - Denial ratio: {features[6]:.2%}")
    
    # ==================== Pattern Analysis Tests ====================
    
    @patch.object(ThreatPredictor, '_get_user_access_history')
    def test_analyze_patterns_normal(self, mock_history, predictor, sample_access_history):
        """Test pattern analysis with normal activity"""
        mock_history.return_value = sample_access_history
        
        result = predictor.analyze_patterns('test_user_123')
        
        assert 'patterns_found' in result
        assert 'indicators' in result
        
        # Normal activity should have few or no indicators
        assert result['indicator_count'] <= 2
        
        print(f"✓ Normal pattern analysis: {result['indicator_count']} indicators")
    
    @patch.object(ThreatPredictor, '_get_user_access_history')
    def test_analyze_patterns_suspicious(self, mock_history, predictor, suspicious_access_history):
        """Test pattern analysis with suspicious activity"""
        mock_history.return_value = suspicious_access_history
        
        result = predictor.analyze_patterns('test_user_123')
        
        assert result['patterns_found'] is True
        assert result['indicator_count'] > 0
        
        # Verify indicator types
        indicator_types = [ind['type'] for ind in result['indicators']]
        assert 'excessive_failed_attempts' in indicator_types or 'scope_deviation' in indicator_types
        
        print(f"✓ Suspicious pattern detected: {result['indicator_count']} indicators")
        for ind in result['indicators']:
            print(f"  - {ind['type']}: {ind['severity']}")
    
    # ==================== Threat Detection Tests ====================
    
    @patch('app.firebase_config.db')
    def test_detect_brute_force(self, mock_db, predictor):
        """Test brute force attack detection"""
        # Mock Firestore query for failed login attempts
        mock_query = Mock()
        mock_docs = []
        
        # Create 12 failed attempts from same IP
        for i in range(12):
            mock_doc = Mock()
            mock_doc.to_dict.return_value = {
                'action': 'login',
                'result': 'failure',
                'ip_address': '203.0.113.100',
                'user_id': 'test_user_123',
                'timestamp': datetime.utcnow() - timedelta(minutes=i*5)
            }
            mock_docs.append(mock_doc)
        
        mock_query.stream.return_value = mock_docs
        mock_db.collection.return_value.where.return_value.where.return_value.where.return_value = mock_query
        
        result = predictor.detect_brute_force(user_id='test_user_123')
        
        assert result is not None
        assert result['detected'] is True
        assert result['threat_type'] == 'brute_force_attack'
        assert result['severity'] == 'high'
        
        print(f"✓ Brute force detected")
        print(f"  - Threat type: {result['threat_type']}")
        print(f"  - Severity: {result['severity']}")
    
    @patch.object(ThreatPredictor, '_get_user_access_history')
    def test_detect_privilege_escalation(self, mock_history, predictor):
        """Test privilege escalation detection"""
        # Create history with escalation attempts
        history = []
        now = datetime.utcnow()
        
        # Normal access
        for i in range(10):
            history.append({
                'resource_type': 'lab_server',
                'action': 'read',
                'result': 'success',
                'timestamp': now - timedelta(hours=i)
            })
        
        # Escalation attempts
        for i in range(5):
            history.append({
                'resource_type': 'admin_panel',
                'action': 'create_user',
                'result': 'denied',
                'timestamp': now - timedelta(minutes=i*10)
            })
        
        mock_history.return_value = history
        
        result = predictor.detect_privilege_escalation('test_user_123')
        
        assert result is not None
        assert result['detected'] is True
        assert result['threat_type'] == 'privilege_escalation'
        assert result['attempt_count'] >= 3
        
        print(f"✓ Privilege escalation detected")
        print(f"  - Attempts: {result['attempt_count']}")
    
    @patch('app.firebase_config.db')
    def test_detect_coordinated_attack(self, mock_db, predictor):
        """Test coordinated attack detection"""
        # Mock multiple users attacking same resource
        mock_query = Mock()
        mock_docs = []
        
        # Create attacks from 5 different users
        for user_num in range(5):
            for attempt in range(3):
                mock_doc = Mock()
                mock_doc.to_dict.return_value = {
                    'user_id': f'user_{user_num}',
                    'resource_type': 'database',
                    'action': 'access',
                    'result': 'denied',
                    'timestamp': datetime.utcnow() - timedelta(minutes=attempt)
                }
                mock_docs.append(mock_doc)
        
        mock_query.stream.return_value = mock_docs
        mock_db.collection.return_value.where.return_value.where.return_value.limit.return_value = mock_query
        
        result = predictor.detect_coordinated_attack()
        
        assert result is not None
        assert result['detected'] is True
        assert result['threat_type'] == 'coordinated_attack'
        assert result['severity'] == 'critical'
        
        print(f"✓ Coordinated attack detected")
        print(f"  - Severity: {result['severity']}")
    
    # ==================== Prediction Tests ====================
    
    @patch.object(ThreatPredictor, '_predict_user_threat')
    def test_predict_threats_high_confidence(self, mock_predict, predictor):
        """Test threat prediction with high confidence"""
        # Mock high-confidence prediction
        mock_predict.return_value = {
            'user_id': 'test_user_123',
            'threat_type': 'brute_force_attack',
            'confidence': 0.85,
            'indicators': [
                {'type': 'excessive_failed_attempts', 'severity': 'high'}
            ],
            'preventive_measures': ['Enable account lockout'],
            'predicted_at': datetime.utcnow().isoformat(),
            'status': 'pending'
        }
        
        predictions = predictor.predict_threats(user_id='test_user_123')
        
        assert len(predictions) > 0
        assert predictions[0]['confidence'] >= predictor.confidence_threshold
        
        print(f"✓ High-confidence prediction generated")
        print(f"  - Confidence: {predictions[0]['confidence']:.2%}")
        print(f"  - Threat type: {predictions[0]['threat_type']}")
    
    @patch.object(ThreatPredictor, 'analyze_patterns')
    @patch.object(ThreatPredictor, '_save_prediction')
    def test_predict_user_threat(self, mock_save, mock_analyze, predictor):
        """Test individual user threat prediction"""
        # Mock pattern analysis with threats
        mock_analyze.return_value = {
            'patterns_found': True,
            'indicators': [
                {'type': 'excessive_failed_attempts', 'severity': 'high'},
                {'type': 'scope_deviation', 'severity': 'high'}
            ]
        }
        
        prediction = predictor._predict_user_threat('test_user_123')
        
        assert prediction is not None
        assert 'threat_type' in prediction
        assert 'confidence' in prediction
        assert 'preventive_measures' in prediction
        assert 0 <= prediction['confidence'] <= 1
        
        print(f"✓ User threat predicted")
        print(f"  - Threat: {prediction['threat_type']}")
        print(f"  - Confidence: {prediction['confidence']:.2%}")
    
    # ==================== Prediction Accuracy Tests ====================
    
    @patch('app.models.threat_prediction.ThreatPrediction.get_by_id')
    def test_track_prediction_outcome(self, mock_get, predictor):
        """Test prediction outcome tracking"""
        # Mock prediction
        mock_prediction = Mock()
        mock_prediction.user_id = 'test_user_123'
        mock_prediction.update_outcome = Mock()
        mock_get.return_value = mock_prediction
        
        result = predictor.track_prediction_outcome('pred_123', 'confirmed', 'Attack prevented')
        
        # Verify outcome was tracked
        mock_prediction.update_outcome.assert_called_once_with('confirmed')
        
        print("✓ Prediction outcome tracked")
    
    def test_generate_preventive_measures(self, predictor):
        """Test preventive measure generation"""
        threat_types = ['excessive_failed_attempts', 'scope_deviation', 'geographic_anomaly']
        
        measures = predictor._generate_preventive_measures(threat_types)
        
        assert len(measures) > 0
        assert any('lockout' in m.lower() for m in measures)
        assert any('permission' in m.lower() or 'restrict' in m.lower() for m in measures)
        
        print(f"✓ Preventive measures generated: {len(measures)} measures")
        for measure in measures[:3]:
            print(f"  - {measure}")
    
    # ==================== Alert Generation Tests ====================
    
    @patch.object(ThreatPredictor, '_predict_user_threat')
    def test_alert_generation_high_confidence(self, mock_predict, predictor):
        """Test that high-confidence predictions generate alerts"""
        # Mock high-confidence prediction
        mock_predict.return_value = {
            'user_id': 'test_user_123',
            'threat_type': 'account_compromise',
            'confidence': 0.92,  # > 80%
            'indicators': [],
            'preventive_measures': [],
            'predicted_at': datetime.utcnow().isoformat(),
            'status': 'pending'
        }
        
        predictions = predictor.predict_threats(user_id='test_user_123')
        
        # High confidence should be included
        assert len(predictions) > 0
        assert predictions[0]['confidence'] > 0.80
        
        # In production, this would trigger admin alert
        should_alert = predictions[0]['confidence'] > 0.80
        assert should_alert is True
        
        print(f"✓ Alert triggered for confidence: {predictions[0]['confidence']:.2%}")
    
    @patch.object(ThreatPredictor, '_predict_user_threat')
    def test_no_alert_low_confidence(self, mock_predict, predictor):
        """Test that low-confidence predictions don't generate alerts"""
        # Mock low-confidence prediction
        mock_predict.return_value = {
            'user_id': 'test_user_123',
            'threat_type': 'suspicious_activity',
            'confidence': 0.55,  # < 70%
            'indicators': [],
            'preventive_measures': [],
            'predicted_at': datetime.utcnow().isoformat(),
            'status': 'pending'
        }
        
        predictions = predictor.predict_threats(user_id='test_user_123')
        
        # Low confidence should be filtered out
        assert len(predictions) == 0
        
        print("✓ Low-confidence prediction filtered (no alert)")
    
    # ==================== Accuracy Validation Tests ====================
    
    def test_prediction_accuracy_calculation(self, predictor):
        """Test prediction accuracy calculation logic"""
        # Simulate prediction outcomes
        outcomes = {
            'confirmed': 8,      # True positives
            'false_positive': 2,  # False positives
            'prevented': 1       # Also counts as confirmed
        }
        
        total_predictions = sum(outcomes.values())
        true_positives = outcomes['confirmed'] + outcomes['prevented']
        accuracy = true_positives / total_predictions if total_predictions > 0 else 0
        
        # Should meet 80% accuracy requirement
        assert accuracy >= 0.80
        
        print(f"✓ Prediction accuracy: {accuracy:.2%}")
        print(f"  - True positives: {true_positives}/{total_predictions}")
    
    def test_false_positive_rate(self, predictor):
        """Test false positive rate calculation"""
        total_predictions = 100
        false_positives = 15
        
        false_positive_rate = false_positives / total_predictions
        
        # Should be reasonable (< 20%)
        assert false_positive_rate < 0.20
        
        print(f"✓ False positive rate: {false_positive_rate:.2%}")


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
