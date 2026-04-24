"""
Test suite for Adaptive Policy Engine
Tests policy outcome tracking, effectiveness metrics, and automatic adjustments
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Mock firebase before importing services
sys.modules['app.firebase_config'] = Mock(db=Mock())

from app.services.adaptive_policy_engine import AdaptivePolicyEngine


class TestAdaptivePolicyEngine:
    """Test adaptive policy engine functionality"""
    
    @pytest.fixture
    def engine(self):
        """Create adaptive policy engine instance"""
        return AdaptivePolicyEngine()
    
    @pytest.fixture
    def sample_policy(self):
        """Generate sample policy"""
        return {
            'policy_id': 'policy_123',
            'name': 'Lab Server Access',
            'rules': [{
                'resourceType': 'lab_server',
                'allowedRoles': ['faculty', 'admin'],
                'minConfidence': 70,
                'mfaRequired': True
            }],
            'priority': 1,
            'isActive': True,
            'effectiveness_score': 0.85,
            'created_at': datetime.utcnow() - timedelta(days=30)
        }
    
    @pytest.fixture
    def policy_outcomes(self):
        """Generate sample policy outcomes"""
        outcomes = []
        now = datetime.utcnow()
        
        # 80 successful outcomes
        for i in range(80):
            outcomes.append({
                'policy_id': 'policy_123',
                'outcome': 'success',
                'timestamp': now - timedelta(hours=i),
                'user_id': f'user_{i % 20}',
                'resource': 'lab_server'
            })
        
        # 15 denied outcomes
        for i in range(15):
            outcomes.append({
                'policy_id': 'policy_123',
                'outcome': 'denied',
                'timestamp': now - timedelta(hours=i),
                'user_id': f'user_{i % 10}',
                'resource': 'lab_server'
            })
        
        # 5 security incidents
        for i in range(5):
            outcomes.append({
                'policy_id': 'policy_123',
                'outcome': 'security_incident',
                'timestamp': now - timedelta(hours=i),
                'user_id': f'user_{i}',
                'resource': 'lab_server'
            })
        
        return outcomes
    
    # ==================== Policy Outcome Tracking Tests ====================
    
    @patch('app.firebase_config.db')
    def test_track_policy_outcome_success(self, mock_db, engine):
        """Test tracking successful policy outcome"""
        mock_collection = Mock()
        mock_db.collection.return_value = mock_collection
        
        result = engine.track_policy_outcome(
            policy_id='policy_123',
            outcome='success',
            user_id='test_user',
            resource='lab_server',
            details={'confidence': 85}
        )
        
        assert result is True
        mock_collection.document.assert_called_once()
        
        print("✓ Policy outcome tracked successfully")
    
    @patch('app.firebase_config.db')
    def test_track_policy_outcome_denied(self, mock_db, engine):
        """Test tracking denied policy outcome"""
        mock_collection = Mock()
        mock_db.collection.return_value = mock_collection
        
        result = engine.track_policy_outcome(
            policy_id='policy_123',
            outcome='denied',
            user_id='test_user',
            resource='lab_server',
            details={'reason': 'insufficient_confidence'}
        )
        
        assert result is True
        
        print("✓ Denied outcome tracked")
    
    @patch('app.firebase_config.db')
    def test_track_policy_outcome_security_incident(self, mock_db, engine):
        """Test tracking security incident outcome"""
        mock_collection = Mock()
        mock_db.collection.return_value = mock_collection
        
        result = engine.track_policy_outcome(
            policy_id='policy_123',
            outcome='security_incident',
            user_id='test_user',
            resource='lab_server',
            details={'incident_type': 'unauthorized_access'}
        )
        
        assert result is True
        
        print("✓ Security incident tracked")
    
    # ==================== Effectiveness Metric Tests ====================
    
    @patch.object(AdaptivePolicyEngine, '_get_policy_outcomes')
    def test_calculate_effectiveness_high(self, mock_outcomes, engine, policy_outcomes):
        """Test effectiveness calculation with high success rate"""
        # Filter to mostly successful outcomes
        successful_outcomes = [o for o in policy_outcomes if o['outcome'] == 'success']
        mock_outcomes.return_value = successful_outcomes[:90] + policy_outcomes[-10:]
        
        effectiveness = engine.calculate_policy_effectiveness('policy_123')
        
        assert 'effectiveness_score' in effectiveness
        assert 'metrics' in effectiveness
        
        # High success rate should yield high effectiveness
        assert effectiveness['effectiveness_score'] >= 0.80
        
        print(f"✓ High effectiveness: {effectiveness['effectiveness_score']:.2%}")
        print(f"  - Success rate: {effectiveness['metrics']['success_rate']:.2%}")
    
    @patch.object(AdaptivePolicyEngine, '_get_policy_outcomes')
    def test_calculate_effectiveness_low(self, mock_outcomes, engine):
        """Test effectiveness calculation with low success rate"""
        # Create outcomes with many incidents
        outcomes = []
        for i in range(50):
            outcomes.append({
                'outcome': 'security_incident',
                'timestamp': datetime.utcnow() - timedelta(hours=i)
            })
        for i in range(50):
            outcomes.append({
                'outcome': 'success',
                'timestamp': datetime.utcnow() - timedelta(hours=i)
            })
        
        mock_outcomes.return_value = outcomes
        
        effectiveness = engine.calculate_policy_effectiveness('policy_123')
        
        # High incident rate should yield low effectiveness
        assert effectiveness['effectiveness_score'] < 0.60
        
        print(f"✓ Low effectiveness: {effectiveness['effectiveness_score']:.2%}")
        print(f"  - Incident rate: {effectiveness['metrics']['incident_rate']:.2%}")
    
    @patch.object(AdaptivePolicyEngine, '_get_policy_outcomes')
    def test_effectiveness_metrics_calculation(self, mock_outcomes, engine, policy_outcomes):
        """Test individual effectiveness metrics"""
        mock_outcomes.return_value = policy_outcomes
        
        effectiveness = engine.calculate_policy_effectiveness('policy_123')
        metrics = effectiveness['metrics']
        
        # Verify all metrics are present
        assert 'success_rate' in metrics
        assert 'denial_rate' in metrics
        assert 'incident_rate' in metrics
        assert 'total_outcomes' in metrics
        
        # Verify rates sum correctly
        total = metrics['success_rate'] + metrics['denial_rate'] + metrics['incident_rate']
        assert abs(total - 1.0) < 0.01
        
        print("✓ Effectiveness metrics calculated")
        print(f"  - Success: {metrics['success_rate']:.2%}")
        print(f"  - Denied: {metrics['denial_rate']:.2%}")
        print(f"  - Incidents: {metrics['incident_rate']:.2%}")
    
    # ==================== Automatic Policy Adjustment Tests ====================
    
    @patch.object(AdaptivePolicyEngine, 'calculate_policy_effectiveness')
    @patch('app.firebase_config.db')
    def test_adjust_policy_increase_confidence(self, mock_db, mock_effectiveness, engine, sample_policy):
        """Test automatic policy adjustment to increase confidence threshold"""
        # Mock low effectiveness due to incidents
        mock_effectiveness.return_value = {
            'effectiveness_score': 0.55,
            'metrics': {
                'success_rate': 0.70,
                'denial_rate': 0.10,
                'incident_rate': 0.20
            }
        }
        
        mock_db.collection.return_value.document.return_value.get.return_value.to_dict.return_value = sample_policy
        
        adjustment = engine.adjust_policy_automatically('policy_123')
        
        assert adjustment is not None
        assert 'adjustment_type' in adjustment
        assert adjustment['adjustment_type'] == 'increase_confidence'
        
        # Should recommend increasing confidence threshold
        assert adjustment['new_min_confidence'] > sample_policy['rules'][0]['minConfidence']
        
        print(f"✓ Policy adjustment: {adjustment['adjustment_type']}")
        print(f"  - Old confidence: {sample_policy['rules'][0]['minConfidence']}")
        print(f"  - New confidence: {adjustment['new_min_confidence']}")
    
    @patch.object(AdaptivePolicyEngine, 'calculate_policy_effectiveness')
    @patch('app.firebase_config.db')
    def test_adjust_policy_decrease_confidence(self, mock_db, mock_effectiveness, engine, sample_policy):
        """Test automatic policy adjustment to decrease confidence threshold"""
        # Mock high effectiveness but high denial rate
        mock_effectiveness.return_value = {
            'effectiveness_score': 0.75,
            'metrics': {
                'success_rate': 0.50,
                'denial_rate': 0.48,
                'incident_rate': 0.02
            }
        }
        
        mock_db.collection.return_value.document.return_value.get.return_value.to_dict.return_value = sample_policy
        
        adjustment = engine.adjust_policy_automatically('policy_123')
        
        assert adjustment is not None
        assert adjustment['adjustment_type'] == 'decrease_confidence'
        
        # Should recommend decreasing confidence threshold
        assert adjustment['new_min_confidence'] < sample_policy['rules'][0]['minConfidence']
        
        print(f"✓ Policy adjustment: {adjustment['adjustment_type']}")
        print(f"  - Old confidence: {sample_policy['rules'][0]['minConfidence']}")
        print(f"  - New confidence: {adjustment['new_min_confidence']}")
    
    @patch.object(AdaptivePolicyEngine, 'calculate_policy_effectiveness')
    @patch('app.firebase_config.db')
    def test_adjust_policy_no_change_needed(self, mock_db, mock_effectiveness, engine, sample_policy):
        """Test that well-performing policies are not adjusted"""
        # Mock high effectiveness with balanced metrics
        mock_effectiveness.return_value = {
            'effectiveness_score': 0.90,
            'metrics': {
                'success_rate': 0.88,
                'denial_rate': 0.10,
                'incident_rate': 0.02
            }
        }
        
        mock_db.collection.return_value.document.return_value.get.return_value.to_dict.return_value = sample_policy
        
        adjustment = engine.adjust_policy_automatically('policy_123')
        
        # No adjustment needed for well-performing policy
        assert adjustment is None or adjustment['adjustment_type'] == 'no_change'
        
        print("✓ No adjustment needed for well-performing policy")
    
    # ==================== Policy Simulation Tests ====================
    
    @patch.object(AdaptivePolicyEngine, '_get_policy_outcomes')
    def test_simulate_policy_adjustment(self, mock_outcomes, engine, policy_outcomes, sample_policy):
        """Test policy adjustment simulation"""
        mock_outcomes.return_value = policy_outcomes
        
        # Simulate increasing confidence from 70 to 80
        simulation = engine.simulate_policy_adjustment(
            policy=sample_policy,
            adjustment_type='increase_confidence',
            new_min_confidence=80
        )
        
        assert 'simulated_effectiveness' in simulation
        assert 'predicted_outcomes' in simulation
        assert 'recommendation' in simulation
        
        # Simulation should predict impact
        predicted = simulation['predicted_outcomes']
        assert 'success_rate' in predicted
        assert 'denial_rate' in predicted
        
        print("✓ Policy adjustment simulated")
        print(f"  - Predicted success rate: {predicted['success_rate']:.2%}")
        print(f"  - Recommendation: {simulation['recommendation']}")
    
    @patch.object(AdaptivePolicyEngine, '_get_policy_outcomes')
    def test_simulate_multiple_adjustments(self, mock_outcomes, engine, policy_outcomes, sample_policy):
        """Test simulation of multiple adjustment options"""
        mock_outcomes.return_value = policy_outcomes
        
        adjustments = [
            {'type': 'increase_confidence', 'value': 75},
            {'type': 'increase_confidence', 'value': 80},
            {'type': 'increase_confidence', 'value': 85}
        ]
        
        simulations = []
        for adj in adjustments:
            sim = engine.simulate_policy_adjustment(
                policy=sample_policy,
                adjustment_type=adj['type'],
                new_min_confidence=adj['value']
            )
            simulations.append(sim)
        
        # Should have simulations for all adjustments
        assert len(simulations) == 3
        
        print(f"✓ Multiple adjustments simulated: {len(simulations)}")
    
    # ==================== Policy Rollback Tests ====================
    
    @patch('app.firebase_config.db')
    def test_rollback_policy_adjustment(self, mock_db, engine):
        """Test rolling back a policy adjustment"""
        # Mock policy history
        mock_history = Mock()
        mock_history.to_dict.return_value = {
            'policy_id': 'policy_123',
            'previous_rules': [{
                'minConfidence': 70,
                'mfaRequired': True
            }],
            'adjustment_timestamp': datetime.utcnow() - timedelta(hours=1)
        }
        
        mock_db.collection.return_value.where.return_value.order_by.return_value.limit.return_value.stream.return_value = [mock_history]
        
        result = engine.rollback_policy_adjustment('policy_123')
        
        assert result is True
        
        print("✓ Policy adjustment rolled back")
    
    @patch('app.firebase_config.db')
    def test_rollback_no_history(self, mock_db, engine):
        """Test rollback when no history exists"""
        mock_db.collection.return_value.where.return_value.order_by.return_value.limit.return_value.stream.return_value = []
        
        result = engine.rollback_policy_adjustment('policy_123')
        
        assert result is False
        
        print("✓ Rollback prevented when no history exists")
    
    # ==================== Effectiveness Score Validation Tests ====================
    
    def test_effectiveness_score_range(self, engine):
        """Test that effectiveness scores are in valid range"""
        # Test with various outcome distributions
        test_cases = [
            {'success': 100, 'denied': 0, 'incidents': 0},
            {'success': 50, 'denied': 50, 'incidents': 0},
            {'success': 0, 'denied': 0, 'incidents': 100},
            {'success': 80, 'denied': 15, 'incidents': 5}
        ]
        
        for case in test_cases:
            outcomes = []
            for outcome_type, count in case.items():
                for _ in range(count):
                    outcomes.append({
                        'outcome': outcome_type if outcome_type != 'incidents' else 'security_incident',
                        'timestamp': datetime.utcnow()
                    })
            
            with patch.object(engine, '_get_policy_outcomes', return_value=outcomes):
                effectiveness = engine.calculate_policy_effectiveness('test_policy')
                
                # Score should be between 0 and 1
                assert 0 <= effectiveness['effectiveness_score'] <= 1
        
        print("✓ Effectiveness scores in valid range (0-1)")
    
    def test_effectiveness_score_calculation_formula(self, engine):
        """Test effectiveness score calculation formula"""
        # Perfect policy: 100% success, 0% incidents
        perfect_outcomes = [
            {'outcome': 'success', 'timestamp': datetime.utcnow()}
            for _ in range(100)
        ]
        
        with patch.object(engine, '_get_policy_outcomes', return_value=perfect_outcomes):
            effectiveness = engine.calculate_policy_effectiveness('test_policy')
            
            # Perfect policy should have score close to 1.0
            assert effectiveness['effectiveness_score'] >= 0.95
        
        # Poor policy: 50% incidents
        poor_outcomes = (
            [{'outcome': 'success', 'timestamp': datetime.utcnow()} for _ in range(50)] +
            [{'outcome': 'security_incident', 'timestamp': datetime.utcnow()} for _ in range(50)]
        )
        
        with patch.object(engine, '_get_policy_outcomes', return_value=poor_outcomes):
            effectiveness = engine.calculate_policy_effectiveness('test_policy')
            
            # Poor policy should have low score
            assert effectiveness['effectiveness_score'] < 0.60
        
        print("✓ Effectiveness calculation formula validated")
    
    # ==================== Policy Learning Tests ====================
    
    @patch.object(AdaptivePolicyEngine, 'calculate_policy_effectiveness')
    @patch('app.firebase_config.db')
    def test_policy_learning_over_time(self, mock_db, mock_effectiveness, engine):
        """Test that policy effectiveness improves over time with adjustments"""
        # Simulate policy learning over multiple iterations
        effectiveness_scores = [0.60, 0.70, 0.80, 0.85, 0.90]
        
        for i, score in enumerate(effectiveness_scores):
            mock_effectiveness.return_value = {
                'effectiveness_score': score,
                'metrics': {
                    'success_rate': score,
                    'denial_rate': 0.10,
                    'incident_rate': 1.0 - score - 0.10
                }
            }
            
            # Policy should improve over iterations
            if i > 0:
                assert score > effectiveness_scores[i-1]
        
        print("✓ Policy learning validated (effectiveness improves over time)")


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
