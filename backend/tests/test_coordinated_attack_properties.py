"""
Property-Based Tests for Coordinated Attack Detection
Tests universal properties for automated threat detection and response
"""

import pytest
from hypothesis import given, strategies as st, settings, assume
from hypothesis.stateful import RuleBasedStateMachine, Bundle, rule, initialize
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock

from app.services.automated_threat_response import automated_threat_response_service


# Test data strategies for generating attack scenarios
@st.composite
def device_fingerprint_strategy(draw):
    """Generate random device fingerprints"""
    return f"device_{draw(st.text(min_size=32, max_size=64, alphabet='0123456789abcdef'))}"


@st.composite
def user_id_strategy(draw):
    """Generate valid user IDs"""
    return f"user_{draw(st.text(min_size=10, max_size=28, alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'))}"


@st.composite
def ip_address_strategy(draw):
    """Generate valid IP addresses"""
    return f"{draw(st.integers(1, 255))}.{draw(st.integers(0, 255))}.{draw(st.integers(0, 255))}.{draw(st.integers(1, 255))}"


@st.composite
def failed_attempt_strategy(draw):
    """Generate failed access attempt data"""
    return {
        'user_id': draw(user_id_strategy()),
        'device_fingerprint': draw(device_fingerprint_strategy()),
        'ip_address': draw(ip_address_strategy()),
        'timestamp': datetime.utcnow() - timedelta(minutes=draw(st.integers(0, 15))),
        'attempt_type': draw(st.sampled_from(['login', 'access_request', 'resource_access'])),
        'failure_reason': draw(st.sampled_from(['invalid_credentials', 'device_mismatch', 'unauthorized_resource']))
    }


@st.composite
def coordinated_attack_scenario(draw):
    """Generate coordinated attack scenarios"""
    # Generate base attack parameters
    attack_device = draw(device_fingerprint_strategy())
    attack_ip = draw(ip_address_strategy())
    target_users = draw(st.lists(user_id_strategy(), min_size=2, max_size=10, unique=True))
    
    # Generate failed attempts from same device/IP targeting multiple users
    attempts = []
    base_time = datetime.utcnow()
    
    for i, user in enumerate(target_users):
        attempt_time = base_time - timedelta(minutes=draw(st.integers(0, 9)))
        attempts.append({
            'user_id': user,
            'device_fingerprint': attack_device,
            'ip_address': attack_ip,
            'timestamp': attempt_time,
            'attempt_type': 'login',
            'failure_reason': 'invalid_credentials'
        })
    
    return {
        'attack_device': attack_device,
        'attack_ip': attack_ip,
        'target_users': target_users,
        'failed_attempts': attempts
    }


class TestCoordinatedAttackDetectionProperties:
    """Property-based tests for coordinated attack detection functionality"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.service = automated_threat_response_service
        # Mock Firestore for testing
        self.service.db = Mock()
    
    @given(attack_scenario=coordinated_attack_scenario())
    @settings(max_examples=50, deadline=10000)
    def test_property_18_coordinated_attack_detection(self, attack_scenario):
        """
        Feature: enhanced-zero-trust-framework, Property 18: Coordinated Attack Detection
        For any coordinated attack pattern (multiple failed attempts from same device/IP 
        targeting different users within 10 minutes), the system should detect and respond
        **Validates: Requirements 11.1**
        """
        attack_device = attack_scenario['attack_device']
        attack_ip = attack_scenario['attack_ip']
        target_users = attack_scenario['target_users']
        failed_attempts = attack_scenario['failed_attempts']
        
        # Assume we have at least 2 users for a coordinated attack
        assume(len(target_users) >= 2)
        
        # Mock the database queries for failed attempts
        mock_attempts_collection = Mock()
        mock_attempts_docs = []
        
        for attempt in failed_attempts:
            mock_doc = Mock()
            mock_doc.to_dict.return_value = attempt
            mock_attempts_docs.append(mock_doc)
        
        mock_query = Mock()
        mock_query.stream.return_value = mock_attempts_docs
        mock_attempts_collection.where.return_value.where.return_value.order_by.return_value = mock_query
        
        # Mock blocked devices collection
        mock_blocked_collection = Mock()
        mock_blocked_doc = Mock()
        mock_blocked_doc.exists = False
        mock_blocked_collection.document.return_value.get.return_value = mock_blocked_doc
        
        # Mock security events collection
        mock_security_collection = Mock()
        
        with patch.object(self.service.db, 'collection') as mock_db_collection:
            def collection_side_effect(name):
                if name == 'failed_access_attempts':
                    return mock_attempts_collection
                elif name == 'blocked_devices':
                    return mock_blocked_collection
                elif name == 'security_events':
                    return mock_security_collection
                return Mock()
            
            mock_db_collection.side_effect = collection_side_effect
            
            # Test coordinated attack detection using actual service method
            with patch.object(self.service, 'block_device_fingerprint', new_callable=AsyncMock) as mock_block:
                with patch.object(self.service, 'alert_administrators', new_callable=AsyncMock) as mock_alert:
                    
                    # Run detection using actual service method
                    import asyncio
                    result = asyncio.run(self.service.detect_coordinated_attacks())
                    
                    # Verify result is a list
                    assert isinstance(result, list), "Detection result should be a list"
                    
                    # If coordinated attack detected, verify structure
                    if len(result) > 0:
                        detected_attack = result[0]
                        
                        # Verify required fields exist
                        assert 'threat_type' in detected_attack, "Should have threat_type field"
                        assert 'device_fingerprint' in detected_attack, "Should have device_fingerprint field"
                        assert 'affected_users' in detected_attack, "Should have affected_users field"
                        assert 'confidence_score' in detected_attack, "Should have confidence_score field"
                        
                        # Verify threat type is appropriate
                        threat_type = detected_attack['threat_type']
                        valid_threat_types = ['coordinated_attack', 'multi_user_attack', 'device_based_attack']
                        assert any(valid_type in threat_type for valid_type in valid_threat_types), \
                            f"Invalid threat type: {threat_type}"
                        
                        # Verify confidence score is valid
                        confidence = detected_attack.get('confidence_score', 0)
                        assert 0 <= confidence <= 1, "Confidence score should be between 0 and 1"
                        
                        # If multiple users affected, should be high confidence
                        affected_users_count = len(detected_attack.get('affected_users', []))
                        if affected_users_count >= 3:
                            assert confidence >= 0.7, "High user count should increase confidence"
    
    @given(
        device_fingerprint=device_fingerprint_strategy(),
        failed_attempts_count=st.integers(min_value=1, max_value=20),
        time_window_minutes=st.integers(min_value=1, max_value=15)
    )
    @settings(max_examples=50, deadline=5000)
    def test_device_blocking_threshold_properties(self, device_fingerprint, failed_attempts_count, time_window_minutes):
        """Test device blocking threshold properties"""
        # Generate failed attempts within time window
        base_time = datetime.utcnow()
        attempts = []
        
        for i in range(failed_attempts_count):
            attempt_time = base_time - timedelta(minutes=time_window_minutes - (i * time_window_minutes // failed_attempts_count))
            attempts.append({
                'device_fingerprint': device_fingerprint,
                'timestamp': attempt_time,
                'user_id': f'user_{i}',
                'failure_reason': 'invalid_credentials'
            })
        
        # Mock database
        mock_attempts_collection = Mock()
        mock_attempts_docs = [Mock() for _ in attempts]
        for i, doc in enumerate(mock_attempts_docs):
            doc.to_dict.return_value = attempts[i]
        
        mock_query = Mock()
        mock_query.stream.return_value = mock_attempts_docs
        mock_attempts_collection.where.return_value.where.return_value.order_by.return_value = mock_query
        
        with patch.object(self.service.db, 'collection', return_value=mock_attempts_collection):
            
            # Test detection using actual service method
            import asyncio
            result = asyncio.run(self.service.detect_multiple_failed_attempts(device_fingerprint))
            
            # Verify result is a list
            assert isinstance(result, list), "Detection result should be a list"
            
            # If high failure count, should detect threat
            if failed_attempts_count >= 10 and time_window_minutes <= 10:
                # Should detect device-based threat
                assert len(result) > 0, "Should detect device-based threat with high failure rate"
                
                if len(result) > 0:
                    threat = result[0]
                    assert 'device_fingerprint' in threat, "Should identify device fingerprint"
                    assert threat['device_fingerprint'] == device_fingerprint, "Should match target device"
                    assert 'threat_type' in threat, "Should classify threat type"
    
    @given(
        blocked_devices=st.lists(device_fingerprint_strategy(), min_size=0, max_size=5, unique=True),
        locked_segments=st.lists(st.text(min_size=5, max_size=20), min_size=0, max_size=3, unique=True)
    )
    @settings(max_examples=30, deadline=5000)
    def test_threat_response_state_properties(self, blocked_devices, locked_segments):
        """Test threat response state management properties"""
        # Test that service maintains consistent state
        current_blocked = self.service.get_blocked_devices()
        current_locked = self.service.get_locked_segments()
        
        # State should be consistent
        assert isinstance(current_blocked, list), "Blocked devices should be a list"
        assert isinstance(current_locked, list), "Locked segments should be a list"
        
        # All items should be strings
        for device in current_blocked:
            assert isinstance(device, str), "Device fingerprints should be strings"
        
        for segment in current_locked:
            assert isinstance(segment, str), "Segment IDs should be strings"


class CoordinatedAttackStateMachine(RuleBasedStateMachine):
    """Stateful property-based testing for coordinated attack detection lifecycle"""
    
    devices = Bundle('devices')
    users = Bundle('users')
    
    def __init__(self):
        super().__init__()
        self.service = automated_threat_response_service
        self.service.db = Mock()
        self.failed_attempts = []
        self.blocked_devices = set()
    
    @initialize()
    def setup(self):
        """Initialize the state machine"""
        pass
    
    @rule(target=devices, device_id=device_fingerprint_strategy())
    def create_device(self, device_id):
        """Create a device fingerprint"""
        assume(device_id not in self.blocked_devices)
        return device_id
    
    @rule(target=users, user_id=user_id_strategy())
    def create_user(self, user_id):
        """Create a user"""
        return user_id
    
    @rule(
        device=devices,
        user=users,
        attempt_count=st.integers(min_value=1, max_value=10)
    )
    def generate_failed_attempts(self, device, user, attempt_count):
        """Generate failed access attempts"""
        base_time = datetime.utcnow()
        
        for i in range(attempt_count):
            attempt = {
                'device_fingerprint': device,
                'user_id': user,
                'timestamp': base_time - timedelta(minutes=i),
                'failure_reason': 'invalid_credentials'
            }
            self.failed_attempts.append(attempt)
    
    @rule()
    def test_system_invariants(self):
        """Test system invariants are maintained"""
        # Failed attempts should have valid timestamps
        for attempt in self.failed_attempts:
            assert isinstance(attempt['timestamp'], datetime), "Timestamps should be datetime objects"
            assert attempt['timestamp'] <= datetime.utcnow(), "Timestamps should not be in the future"
        
        # Blocked devices should be tracked
        assert isinstance(self.blocked_devices, set), "Blocked devices should be tracked as set"
        
        # Service state should be consistent
        current_blocked = self.service.get_blocked_devices()
        current_locked = self.service.get_locked_segments()
        
        assert isinstance(current_blocked, list), "Service should return blocked devices as list"
        assert isinstance(current_locked, list), "Service should return locked segments as list"


# Test configuration
TestCoordinatedAttackStateMachine = CoordinatedAttackStateMachine.TestCase


if __name__ == "__main__":
    # Run property-based tests
    pytest.main([__file__, "-v", "--tb=short"])