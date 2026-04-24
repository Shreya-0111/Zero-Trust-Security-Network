"""
Test suite for Contextual Intelligence Engine
Tests device health, network security, time/location evaluation, and context scoring
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Mock firebase before importing services
sys.modules['app.firebase_config'] = Mock(db=Mock())

from app.services.contextual_intelligence import ContextualIntelligence


class TestContextualIntelligence:
    """Test contextual intelligence evaluation"""
    
    @pytest.fixture
    def intelligence(self):
        """Create contextual intelligence instance"""
        return ContextualIntelligence()
    
    @pytest.fixture
    def secure_device_info(self):
        """Generate secure device configuration"""
        return {
            'os_version': '14.0',
            'os_updated': True,
            'has_antivirus': True,
            'antivirus_updated': True,
            'is_encrypted': True,
            'is_known': True,
            'is_compliant': True,
            'device_id': 'device_secure_123'
        }
    
    @pytest.fixture
    def insecure_device_info(self):
        """Generate insecure device configuration"""
        return {
            'os_version': '10.0',
            'os_updated': False,
            'has_antivirus': False,
            'antivirus_updated': False,
            'is_encrypted': False,
            'is_known': False,
            'is_compliant': False,
            'device_id': 'device_unknown_456'
        }
    
    @pytest.fixture
    def secure_network_info(self):
        """Generate secure network configuration"""
        return {
            'network_type': 'campus_wifi',
            'using_vpn': True,
            'ip_address': '192.168.1.100'
        }
    
    @pytest.fixture
    def insecure_network_info(self):
        """Generate insecure network configuration"""
        return {
            'network_type': 'public',
            'using_vpn': False,
            'ip_address': '203.0.113.100'
        }
    
    # ==================== Device Health Tests ====================
    
    def test_evaluate_device_health_secure(self, intelligence, secure_device_info):
        """Test device health evaluation with secure device"""
        result = intelligence.evaluate_device_health(secure_device_info)
        
        assert 'device_health_score' in result
        assert 'component_scores' in result
        assert 'risk_level' in result
        
        # Secure device should have high score
        assert result['device_health_score'] >= 80
        assert result['risk_level'] == 'low'
        
        # Verify component scores
        components = result['component_scores']
        assert components['os_version'] == 100
        assert components['security_software'] == 100
        assert components['encryption'] == 100
        
        print(f"✓ Secure device health: {result['device_health_score']:.2f}")
        print(f"  - Risk level: {result['risk_level']}")
    
    def test_evaluate_device_health_insecure(self, intelligence, insecure_device_info):
        """Test device health evaluation with insecure device"""
        result = intelligence.evaluate_device_health(insecure_device_info)
        
        # Insecure device should have low score
        assert result['device_health_score'] < 50
        assert result['risk_level'] in ['medium', 'high']
        
        # Verify component scores reflect issues
        components = result['component_scores']
        assert components['os_version'] < 100
        assert components['security_software'] == 0
        assert components['encryption'] == 0
        
        print(f"✓ Insecure device health: {result['device_health_score']:.2f}")
        print(f"  - Risk level: {result['risk_level']}")
    
    def test_device_health_component_weights(self, intelligence):
        """Test device health component weighting"""
        # Test with only OS updated
        device_info = {
            'os_updated': True,
            'has_antivirus': False,
            'is_encrypted': False,
            'is_known': False,
            'is_compliant': False
        }
        
        result = intelligence.evaluate_device_health(device_info)
        
        # OS is 30% weight, so score should be around 30
        assert 25 <= result['device_health_score'] <= 40
        
        print(f"✓ Component weighting validated: {result['device_health_score']:.2f}")
    
    # ==================== Network Security Tests ====================
    
    def test_evaluate_network_security_secure(self, intelligence, secure_network_info):
        """Test network security evaluation with secure network"""
        result = intelligence.evaluate_network_security(secure_network_info)
        
        assert 'network_security_score' in result
        assert 'component_scores' in result
        
        # Secure network should have high score
        assert result['network_security_score'] >= 70
        assert result['risk_level'] == 'low'
        
        # Campus WiFi + VPN should score well
        components = result['component_scores']
        assert components['network_type'] == 100
        assert components['vpn_usage'] == 100
        
        print(f"✓ Secure network: {result['network_security_score']:.2f}")
        print(f"  - Network type: campus_wifi")
        print(f"  - VPN: enabled")
    
    def test_evaluate_network_security_insecure(self, intelligence, insecure_network_info):
        """Test network security evaluation with insecure network"""
        result = intelligence.evaluate_network_security(insecure_network_info)
        
        # Public network without VPN should have low score
        assert result['network_security_score'] < 60
        assert result['risk_level'] in ['medium', 'high']
        
        components = result['component_scores']
        assert components['network_type'] == 20  # Public network
        assert components['vpn_usage'] == 30     # No VPN
        
        print(f"✓ Insecure network: {result['network_security_score']:.2f}")
        print(f"  - Network type: public")
        print(f"  - VPN: disabled")
    
    def test_network_type_scoring(self, intelligence):
        """Test different network type scores"""
        network_types = {
            'campus_wifi': 100,
            'vpn': 90,
            'home': 60,
            'public': 20,
            'unknown': 40
        }
        
        for net_type, expected_score in network_types.items():
            network_info = {
                'network_type': net_type,
                'using_vpn': False,
                'ip_address': '192.168.1.1'
            }
            
            result = intelligence.evaluate_network_security(network_info)
            components = result['component_scores']
            
            assert components['network_type'] == expected_score
        
        print("✓ Network type scoring validated")
    
    # ==================== Time Appropriateness Tests ====================
    
    @patch.object(ContextualIntelligence, '_get_typical_access_hours')
    def test_evaluate_time_appropriateness_business_hours(self, mock_typical, intelligence):
        """Test time evaluation during business hours"""
        mock_typical.return_value = set(range(9, 17))  # 9 AM - 5 PM
        
        # Test at 2 PM on a weekday
        access_time = datetime(2024, 11, 13, 14, 0, 0)  # Wednesday 2 PM
        
        result = intelligence.evaluate_time_appropriateness('test_user_123', access_time)
        
        assert 'time_appropriateness_score' in result
        assert result['time_appropriateness_score'] >= 80
        assert result['risk_level'] == 'low'
        assert result['is_typical_time'] is True
        
        print(f"✓ Business hours access: {result['time_appropriateness_score']:.2f}")
    
    @patch.object(ContextualIntelligence, '_get_typical_access_hours')
    def test_evaluate_time_appropriateness_unusual_hours(self, mock_typical, intelligence):
        """Test time evaluation during unusual hours"""
        mock_typical.return_value = set(range(9, 17))
        
        # Test at 3 AM
        access_time = datetime(2024, 11, 13, 3, 0, 0)
        
        result = intelligence.evaluate_time_appropriateness('test_user_123', access_time)
        
        # 2-6 AM should have low score
        assert result['time_appropriateness_score'] < 50
        assert result['risk_level'] in ['medium', 'high']
        assert result['is_typical_time'] is False
        
        print(f"✓ Unusual hours access: {result['time_appropriateness_score']:.2f}")
    
    @patch.object(ContextualIntelligence, '_get_typical_access_hours')
    def test_evaluate_time_weekend_vs_weekday(self, mock_typical, intelligence):
        """Test time evaluation on weekend vs weekday"""
        mock_typical.return_value = set(range(9, 17))
        
        # Weekday at 2 PM
        weekday_time = datetime(2024, 11, 13, 14, 0, 0)  # Wednesday
        weekday_result = intelligence.evaluate_time_appropriateness('test_user_123', weekday_time)
        
        # Weekend at 2 PM
        weekend_time = datetime(2024, 11, 16, 14, 0, 0)  # Saturday
        weekend_result = intelligence.evaluate_time_appropriateness('test_user_123', weekend_time)
        
        # Weekday should score higher than weekend
        assert weekday_result['time_appropriateness_score'] > weekend_result['time_appropriateness_score']
        
        print(f"✓ Weekday score: {weekday_result['time_appropriateness_score']:.2f}")
        print(f"  Weekend score: {weekend_result['time_appropriateness_score']:.2f}")
    
    # ==================== Impossible Travel Tests ====================
    
    @patch.object(ContextualIntelligence, '_get_last_access_location')
    @patch.object(ContextualIntelligence, '_calculate_distance')
    def test_detect_impossible_travel_detected(self, mock_distance, mock_last_location, intelligence):
        """Test impossible travel detection when travel is impossible"""
        # Mock last access in New York
        mock_last_location.return_value = {
            'latitude': 40.7128,
            'longitude': -74.0060,
            'timestamp': datetime.utcnow() - timedelta(hours=1)
        }
        
        # Mock distance of 5000 km (NY to London)
        mock_distance.return_value = 5000
        
        # Current location in London
        current_location = {
            'latitude': 51.5074,
            'longitude': -0.1278
        }
        
        result = intelligence.detect_impossible_travel(
            'test_user_123',
            current_location,
            datetime.utcnow()
        )
        
        assert result['impossible_travel'] is True
        assert result['distance_km'] == 5000
        assert result['time_diff_hours'] == 1
        assert result['required_speed_kmh'] == 5000
        assert result['risk_level'] == 'critical'
        
        print(f"✓ Impossible travel detected")
        print(f"  - Distance: {result['distance_km']} km")
        print(f"  - Time: {result['time_diff_hours']} hours")
        print(f"  - Required speed: {result['required_speed_kmh']} km/h")
    
    @patch.object(ContextualIntelligence, '_get_last_access_location')
    @patch.object(ContextualIntelligence, '_calculate_distance')
    def test_detect_impossible_travel_possible(self, mock_distance, mock_last_location, intelligence):
        """Test impossible travel detection when travel is possible"""
        # Mock last access 12 hours ago
        mock_last_location.return_value = {
            'latitude': 40.7128,
            'longitude': -74.0060,
            'timestamp': datetime.utcnow() - timedelta(hours=12)
        }
        
        # Mock distance of 5000 km
        mock_distance.return_value = 5000
        
        current_location = {
            'latitude': 51.5074,
            'longitude': -0.1278
        }
        
        result = intelligence.detect_impossible_travel(
            'test_user_123',
            current_location,
            datetime.utcnow()
        )
        
        # 5000 km in 12 hours = 417 km/h (possible by plane)
        assert result['impossible_travel'] is False
        assert result['risk_level'] == 'low'
        
        print(f"✓ Possible travel (not flagged)")
        print(f"  - Required speed: {result['required_speed_kmh']:.2f} km/h")
    
    @patch.object(ContextualIntelligence, '_get_last_access_location')
    def test_detect_impossible_travel_no_history(self, mock_last_location, intelligence):
        """Test impossible travel detection with no previous location"""
        mock_last_location.return_value = None
        
        current_location = {
            'latitude': 51.5074,
            'longitude': -0.1278
        }
        
        result = intelligence.detect_impossible_travel(
            'test_user_123',
            current_location,
            datetime.utcnow()
        )
        
        assert result['impossible_travel'] is False
        assert 'No previous location data' in result['reason']
        
        print("✓ No history case handled")
    
    # ==================== Overall Context Score Tests ====================
    
    @patch.object(ContextualIntelligence, '_get_historical_trust_score')
    @patch.object(ContextualIntelligence, '_evaluate_location_risk')
    def test_calculate_overall_context_score_high(self, mock_location, mock_trust, 
                                                   intelligence, secure_device_info, secure_network_info):
        """Test overall context score calculation with high security"""
        mock_trust.return_value = 90
        mock_location.return_value = 90
        
        result = intelligence.calculate_overall_context_score(
            'test_user_123',
            secure_device_info,
            secure_network_info,
            datetime.utcnow()
        )
        
        assert 'overall_context_score' in result
        assert 'requires_step_up_auth' in result
        assert 'component_scores' in result
        
        # High security should have high score
        assert result['overall_context_score'] >= 70
        assert result['requires_step_up_auth'] is False
        assert result['risk_level'] == 'low'
        
        print(f"✓ High security context: {result['overall_context_score']:.2f}")
        print(f"  - Step-up auth required: {result['requires_step_up_auth']}")
    
    @patch.object(ContextualIntelligence, '_get_historical_trust_score')
    @patch.object(ContextualIntelligence, '_evaluate_location_risk')
    def test_calculate_overall_context_score_low(self, mock_location, mock_trust,
                                                  intelligence, insecure_device_info, insecure_network_info):
        """Test overall context score calculation with low security"""
        mock_trust.return_value = 40
        mock_location.return_value = 30
        
        result = intelligence.calculate_overall_context_score(
            'test_user_123',
            insecure_device_info,
            insecure_network_info,
            datetime.utcnow()
        )
        
        # Low security should have low score
        assert result['overall_context_score'] < 60
        assert result['requires_step_up_auth'] is True
        assert result['risk_level'] in ['medium', 'high']
        
        print(f"✓ Low security context: {result['overall_context_score']:.2f}")
        print(f"  - Step-up auth required: {result['requires_step_up_auth']}")
    
    def test_context_score_component_weights(self, intelligence):
        """Test that component weights sum to 1.0"""
        from app.services.contextual_intelligence import (
            DEVICE_HEALTH_WEIGHT,
            NETWORK_SECURITY_WEIGHT,
            TIME_APPROPRIATENESS_WEIGHT,
            LOCATION_RISK_WEIGHT,
            HISTORICAL_TRUST_WEIGHT
        )
        
        total_weight = (
            DEVICE_HEALTH_WEIGHT +
            NETWORK_SECURITY_WEIGHT +
            TIME_APPROPRIATENESS_WEIGHT +
            LOCATION_RISK_WEIGHT +
            HISTORICAL_TRUST_WEIGHT
        )
        
        assert abs(total_weight - 1.0) < 0.01
        
        print(f"✓ Component weights validated: {total_weight:.2f}")
    
    # ==================== Step-Up Authentication Tests ====================
    
    @patch.object(ContextualIntelligence, '_get_historical_trust_score')
    @patch.object(ContextualIntelligence, '_evaluate_location_risk')
    def test_step_up_auth_trigger_low_score(self, mock_location, mock_trust, intelligence):
        """Test that low context score triggers step-up authentication"""
        mock_trust.return_value = 30
        mock_location.return_value = 20
        
        # Create low-security context
        device_info = {
            'os_updated': False,
            'has_antivirus': False,
            'is_encrypted': False,
            'is_known': False,
            'is_compliant': False
        }
        
        network_info = {
            'network_type': 'public',
            'using_vpn': False,
            'ip_address': '203.0.113.100'
        }
        
        result = intelligence.calculate_overall_context_score(
            'test_user_123',
            device_info,
            network_info
        )
        
        # Score < 60 should trigger step-up auth
        assert result['overall_context_score'] < 60
        assert result['requires_step_up_auth'] is True
        
        print(f"✓ Step-up auth triggered at score: {result['overall_context_score']:.2f}")
    
    @patch.object(ContextualIntelligence, '_get_historical_trust_score')
    @patch.object(ContextualIntelligence, '_evaluate_location_risk')
    def test_no_step_up_auth_high_score(self, mock_location, mock_trust, intelligence):
        """Test that high context score doesn't require step-up auth"""
        mock_trust.return_value = 95
        mock_location.return_value = 95
        
        # Create high-security context
        device_info = {
            'os_updated': True,
            'has_antivirus': True,
            'antivirus_updated': True,
            'is_encrypted': True,
            'is_known': True,
            'is_compliant': True
        }
        
        network_info = {
            'network_type': 'campus_wifi',
            'using_vpn': True,
            'ip_address': '192.168.1.100'
        }
        
        result = intelligence.calculate_overall_context_score(
            'test_user_123',
            device_info,
            network_info
        )
        
        # High score should not require step-up auth
        assert result['overall_context_score'] >= 60
        assert result['requires_step_up_auth'] is False
        
        print(f"✓ No step-up auth at score: {result['overall_context_score']:.2f}")
    
    # ==================== Recommendations Tests ====================
    
    def test_generate_recommendations(self, intelligence):
        """Test security recommendation generation"""
        # Create context with issues
        device_eval = {'device_health_score': 45}
        network_eval = {'network_security_score': 50}
        time_eval = {'time_appropriateness_score': 55}
        
        recommendations = intelligence._generate_recommendations(
            45,  # Low overall score
            device_eval,
            network_eval,
            time_eval
        )
        
        assert len(recommendations) > 0
        assert any('device' in r.lower() or 'security' in r.lower() for r in recommendations)
        assert any('vpn' in r.lower() or 'network' in r.lower() for r in recommendations)
        
        print(f"✓ Recommendations generated: {len(recommendations)}")
        for rec in recommendations:
            print(f"  - {rec}")


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
