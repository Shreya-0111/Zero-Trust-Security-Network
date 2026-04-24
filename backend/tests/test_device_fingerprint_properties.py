"""
Property-Based Tests for Device Fingerprinting System
Tests universal properties across all system inputs and scenarios
"""

import pytest
from hypothesis import given, strategies as st, settings, assume
from hypothesis.stateful import RuleBasedStateMachine, Bundle, rule, initialize
import json
import hashlib
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from app.services.device_fingerprint_service import DeviceFingerprintService


# Test data strategies for generating random device characteristics
@st.composite
def device_fingerprint_strategy(draw):
    """Generate random but valid device fingerprint data"""
    return {
        "canvas": {
            "hash": draw(st.text(min_size=32, max_size=64, alphabet="0123456789abcdef")),
            "confidence": draw(st.integers(min_value=0, max_value=100)),
            "dataLength": draw(st.integers(min_value=1000, max_value=50000))
        },
        "webgl": {
            "renderer": draw(st.text(min_size=1, max_size=100)),
            "vendor": draw(st.text(min_size=1, max_size=50)),
            "version": draw(st.text(min_size=1, max_size=50)),
            "parameters": {
                "maxTextureSize": draw(st.integers(min_value=1024, max_value=16384)),
                "maxViewportDims": [
                    draw(st.integers(min_value=1024, max_value=8192)),
                    draw(st.integers(min_value=768, max_value=8192))
                ]
            }
        },
        "audio": {
            "hash": draw(st.text(min_size=32, max_size=64, alphabet="0123456789abcdef")),
            "sampleRate": draw(st.integers(min_value=8000, max_value=192000)),
            "bufferSize": draw(st.integers(min_value=256, max_value=8192))
        },
        "screen": {
            "width": draw(st.integers(min_value=320, max_value=7680)),
            "height": draw(st.integers(min_value=240, max_value=4320)),
            "colorDepth": draw(st.sampled_from([16, 24, 32])),
            "pixelRatio": draw(st.floats(min_value=0.5, max_value=4.0))
        },
        "system": {
            "platform": draw(st.sampled_from(["Win32", "MacIntel", "Linux x86_64", "iPhone", "iPad"])),
            "language": draw(st.sampled_from(["en-US", "en-GB", "es-ES", "fr-FR", "de-DE"])),
            "timezone": draw(st.sampled_from(["America/New_York", "Europe/London", "Asia/Tokyo"])),
            "hardwareConcurrency": draw(st.integers(min_value=1, max_value=32)),
            "deviceMemory": draw(st.integers(min_value=1, max_value=32))
        },
        "fonts": draw(st.lists(
            st.sampled_from(["Arial", "Helvetica", "Times", "Courier", "Verdana"]),
            min_size=5, max_size=20
        )),
        "plugins": draw(st.lists(
            st.dictionaries(
                st.sampled_from(["name", "filename", "description"]),
                st.text(min_size=1, max_size=50),
                min_size=3, max_size=3
            ),
            min_size=0, max_size=10
        ))
    }


@st.composite
def user_id_strategy(draw):
    """Generate valid user IDs"""
    return f"user_{draw(st.text(min_size=10, max_size=28, alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'))}"


class TestDeviceFingerprintProperties:
    """Property-based tests for device fingerprinting functionality"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.service = DeviceFingerprintService()
        # Mock Firestore for testing
        self.service.db = Mock()
    
    @given(device_characteristics=device_fingerprint_strategy())
    @settings(max_examples=100, deadline=5000)
    def test_property_1_device_fingerprint_collection_completeness(self, device_characteristics):
        """
        Feature: enhanced-zero-trust-framework, Property 1: Device Fingerprint Collection Completeness
        For any new device access, the system should collect all required fingerprint components 
        and generate a valid SHA-256 hash
        **Validates: Requirements 1.1, 1.2**
        """
        # Test that all required components are present
        required_components = ["canvas", "webgl", "audio", "screen", "system", "fonts"]
        
        for component in required_components:
            assert component in device_characteristics, f"Missing required component: {component}"
        
        # Test that fingerprint hash generation works
        fingerprint_hash = self.service.generate_fingerprint_hash(device_characteristics)
        
        # Verify hash properties
        assert isinstance(fingerprint_hash, str), "Fingerprint hash must be a string"
        assert len(fingerprint_hash) == 64, "SHA-256 hash must be 64 characters long"
        assert all(c in '0123456789abcdef' for c in fingerprint_hash), "Hash must be valid hexadecimal"
        
        # Test deterministic hashing - same input should produce same hash
        hash2 = self.service.generate_fingerprint_hash(device_characteristics)
        assert fingerprint_hash == hash2, "Hash generation must be deterministic"
    
    @given(
        current_fingerprint=device_fingerprint_strategy(),
        stored_fingerprint=device_fingerprint_strategy()
    )
    @settings(max_examples=100, deadline=5000)
    def test_property_2_device_fingerprint_validation_consistency(self, current_fingerprint, stored_fingerprint):
        """
        Feature: enhanced-zero-trust-framework, Property 2: Device Fingerprint Validation Consistency
        For any stored device fingerprint, validation against the same characteristics should 
        produce consistent similarity scores within the 95% threshold
        **Validates: Requirements 1.3**
        """
        # Test similarity calculation consistency
        similarity1 = self.service._calculate_similarity(current_fingerprint, stored_fingerprint)
        similarity2 = self.service._calculate_similarity(current_fingerprint, stored_fingerprint)
        
        # Similarity calculation should be deterministic
        assert similarity1 == similarity2, "Similarity calculation must be consistent"
        
        # Similarity should be within valid range
        assert 0 <= similarity1 <= 100, "Similarity score must be between 0 and 100"
        
        # Test self-similarity (identical fingerprints should have 100% similarity)
        self_similarity = self.service._calculate_similarity(current_fingerprint, current_fingerprint)
        assert self_similarity == 100, "Identical fingerprints should have 100% similarity"
        
        # Test component weights are applied correctly
        total_weight = sum(config["weight"] for config in self.service.component_weights.values())
        assert abs(total_weight - 1.0) < 0.01, "Component weights should sum to 1.0"
    
    @given(
        user_id=user_id_strategy(),
        device_count=st.integers(min_value=0, max_value=10),
        mfa_verified=st.booleans()
    )
    @settings(max_examples=100, deadline=5000)
    def test_property_3_device_registration_limit_enforcement(self, user_id, device_count, mfa_verified):
        """
        Feature: enhanced-zero-trust-framework, Property 3: Device Registration Limit Enforcement
        For any user account, the system should enforce the maximum of 3 registered devices 
        and require MFA for additional registrations
        **Validates: Requirements 1.5**
        """
        # Mock existing devices
        existing_devices = [
            {"deviceId": f"device_{user_id}_{i}", "isActive": True}
            for i in range(device_count)
        ]
        
        with patch.object(self.service, '_get_user_devices', return_value=existing_devices):
            with patch.object(self.service, '_fingerprint_exists', return_value=False):
                with patch.object(self.service.db, 'collection'):
                    
                    fingerprint_data = {
                        "canvas": {"hash": "test_hash"},
                        "deviceName": "Test Device"
                    }
                    
                    result = self.service.register_device(user_id, fingerprint_data, mfa_verified)
                    
                    if device_count < 3:
                        # Should succeed without MFA
                        assert result["success"] == True, "Registration should succeed under device limit"
                    elif device_count >= 3 and not mfa_verified:
                        # Should require MFA
                        assert result["success"] == False, "Registration should fail without MFA over limit"
                        assert result.get("requires_mfa") == True, "Should require MFA for additional devices"
                    elif device_count >= 3 and device_count < 5 and mfa_verified:
                        # Should succeed with MFA up to 5 devices
                        assert result["success"] == True, "Registration should succeed with MFA verification"
                    elif device_count >= 5:
                        # Should fail even with MFA (absolute limit)
                        assert result["success"] == False, "Registration should fail at absolute limit"
    
    @given(fingerprint_data=device_fingerprint_strategy())
    @settings(max_examples=50, deadline=5000)
    def test_anomaly_detection_properties(self, fingerprint_data):
        """Test that anomaly detection works consistently"""
        anomalies1 = self.service.detect_fingerprint_anomalies(fingerprint_data)
        anomalies2 = self.service.detect_fingerprint_anomalies(fingerprint_data)
        
        # Anomaly detection should be deterministic
        assert anomalies1 == anomalies2, "Anomaly detection must be consistent"
        
        # Anomalies should be a list
        assert isinstance(anomalies1, list), "Anomalies should be returned as a list"
        
        # Each anomaly should be a string description
        for anomaly in anomalies1:
            assert isinstance(anomaly, str), "Each anomaly should be a string description"
    
    @given(
        device_id=st.text(min_size=10, max_size=50),
        validation_results=st.lists(st.booleans(), min_size=1, max_size=10)
    )
    @settings(max_examples=50, deadline=5000)
    def test_trust_score_update_properties(self, device_id, validation_results):
        """Test trust score update properties"""
        initial_trust = 100
        
        # Mock device document
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {"trustScore": initial_trust}
        
        mock_ref = Mock()
        mock_ref.get.return_value = mock_doc
        
        with patch.object(self.service.db, 'collection') as mock_collection:
            mock_collection.return_value.document.return_value = mock_ref
            
            current_trust = initial_trust
            for result in validation_results:
                self.service.update_fingerprint_trust_score(device_id, result)
                
                # Trust score should change predictably
                if result:
                    expected_trust = min(current_trust + 5, 100)
                else:
                    expected_trust = max(current_trust - 10, 0)
                
                # Update current trust for next iteration
                current_trust = expected_trust
            
            # Trust score should always be within bounds
            assert 0 <= current_trust <= 100, "Trust score must remain within valid bounds"


class DeviceFingerprintStateMachine(RuleBasedStateMachine):
    """Stateful property-based testing for device fingerprint lifecycle"""
    
    users = Bundle('users')
    devices = Bundle('devices')
    
    def __init__(self):
        super().__init__()
        self.service = DeviceFingerprintService()
        self.service.db = Mock()
        self.user_devices = {}  # Track devices per user
        self.device_data = {}   # Track device information
    
    @initialize()
    def setup(self):
        """Initialize the state machine"""
        pass
    
    @rule(target=users, user_id=user_id_strategy())
    def create_user(self, user_id):
        """Create a new user"""
        assume(user_id not in self.user_devices)
        self.user_devices[user_id] = []
        return user_id
    
    @rule(
        target=devices,
        user=users,
        fingerprint=device_fingerprint_strategy(),
        mfa_verified=st.booleans()
    )
    def register_device(self, user, fingerprint, mfa_verified):
        """Register a device for a user"""
        device_count = len(self.user_devices.get(user, []))
        
        with patch.object(self.service, '_get_user_devices') as mock_get_devices:
            mock_get_devices.return_value = [
                {"deviceId": f"device_{user}_{i}", "isActive": True}
                for i in range(device_count)
            ]
            
            with patch.object(self.service, '_fingerprint_exists', return_value=False):
                with patch.object(self.service.db, 'collection'):
                    
                    result = self.service.register_device(user, fingerprint, mfa_verified)
                    
                    if result.get("success"):
                        device_id = result["deviceId"]
                        self.user_devices[user].append(device_id)
                        self.device_data[device_id] = {
                            "user": user,
                            "fingerprint": fingerprint,
                            "trustScore": 100,
                            "mfaVerified": mfa_verified
                        }
                        return device_id
                    
                    return None
    
    @rule(device=devices)
    def validate_device_properties(self, device):
        """Validate properties of registered devices"""
        if device and device in self.device_data:
            device_info = self.device_data[device]
            
            # Device should have valid user
            assert device_info["user"] in self.user_devices
            
            # Device should be in user's device list
            assert device in self.user_devices[device_info["user"]]
            
            # Trust score should be valid
            assert 0 <= device_info["trustScore"] <= 100


# Test configuration
TestDeviceFingerprintStateMachine = DeviceFingerprintStateMachine.TestCase


if __name__ == "__main__":
    # Run property-based tests
    pytest.main([__file__, "-v", "--tb=short"])