"""
Integration tests for device registration and validation workflow
Tests end-to-end device fingerprinting, registration, and validation flow
"""

import pytest
import json
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta

from app.services.device_fingerprint_service import DeviceFingerprintService
from app.services.auth_service import AuthService


class TestDeviceRegistrationIntegration:
    """Integration tests for device registration workflow"""
    
    @pytest.fixture
    def mock_db(self):
        """Mock Firestore database"""
        return Mock()
    
    @pytest.fixture
    def device_service(self, mock_db):
        """Device fingerprint service with mocked database"""
        with patch('app.services.device_fingerprint_service.firestore.client', return_value=mock_db):
            service = DeviceFingerprintService()
            service.db = mock_db
            return service
    
    @pytest.fixture
    def auth_service(self, mock_db):
        """Auth service with mocked database"""
        service = Mock()
        service.db = mock_db
        return service
    
    @pytest.fixture
    def sample_device_characteristics(self):
        """Sample device characteristics for testing"""
        return {
            "canvas": {
                "hash": "canvas_hash_123",
                "confidence": 100,
                "dataLength": 2048
            },
            "webgl": {
                "renderer": "ANGLE (Intel HD Graphics)",
                "vendor": "Google Inc.",
                "version": "WebGL 1.0"
            },
            "audio": {
                "hash": "audio_hash_456",
                "sampleRate": 44100,
                "bufferSize": 4096
            },
            "screen": {
                "width": 1920,
                "height": 1080,
                "colorDepth": 24,
                "pixelRatio": 1.0
            },
            "system": {
                "platform": "Win32",
                "language": "en-US",
                "timezone": "America/New_York",
                "hardwareConcurrency": 8
            }
        }
    
    @pytest.fixture
    def sample_user(self):
        """Sample user data"""
        return {
            "userId": "user_123",
            "email": "test@example.com",
            "role": "faculty",
            "name": "Test User",
            "isActive": True,
            "mfaEnabled": True
        }
    
    def test_complete_device_registration_flow(self, device_service, sample_device_characteristics, sample_user):
        """Test complete device registration workflow"""
        user_id = sample_user["userId"]
        
        # Mock dependencies
        device_service._get_user_devices = Mock(return_value=[])
        device_service._fingerprint_exists = Mock(return_value=False)
        
        # Mock Firestore operations
        mock_doc_ref = Mock()
        device_service.db.collection.return_value.document.return_value = mock_doc_ref
        
        # Mock encryption service
        with patch('app.services.device_fingerprint_service.encryption_service') as mock_encryption:
            mock_encryption.encrypt_device_fingerprint.return_value = "encrypted_fingerprint_data"
            
            # Step 1: Register device
            registration_result = device_service.register_device(
                user_id, sample_device_characteristics, mfa_verified=False
            )
            
            # Verify registration success
            assert registration_result["success"] is True
            assert "deviceId" in registration_result
            assert registration_result["trustScore"] == 100
            
            # Verify Firestore was called to store device
            mock_doc_ref.set.assert_called_once()
            stored_data = mock_doc_ref.set.call_args[0][0]
            
            assert stored_data["userId"] == user_id
            assert stored_data["fingerprintHash"] is not None
            assert stored_data["trustScore"] == 100
            assert stored_data["isApproved"] is True
            assert stored_data["isActive"] is True
    
    def test_device_registration_and_validation_flow(self, device_service, sample_device_characteristics):
        """Test device registration followed by validation"""
        user_id = "user_123"
        
        # Step 1: Register device
        device_service._get_user_devices = Mock(return_value=[])
        device_service._fingerprint_exists = Mock(return_value=False)
        
        mock_doc_ref = Mock()
        device_service.db.collection.return_value.document.return_value = mock_doc_ref
        
        with patch('app.services.device_fingerprint_service.encryption_service') as mock_encryption:
            mock_encryption.encrypt_device_fingerprint.return_value = "encrypted_data"
            
            registration_result = device_service.register_device(
                user_id, sample_device_characteristics
            )
            
            assert registration_result["success"] is True
            device_id = registration_result["deviceId"]
            
            # Step 2: Validate same device fingerprint
            mock_device = {
                "deviceId": device_id,
                "characteristics": "encrypted_data",
                "trustScore": 100,
                "fingerprintHash": device_service.generate_fingerprint_hash(sample_device_characteristics)
            }
            
            # Mock validation dependencies
            with patch('app.services.device_fingerprint_service.cache_service') as mock_cache:
                mock_cache.get_device_profile.return_value = None
                
                device_service._get_user_devices_cached = Mock(return_value=[mock_device])
                device_service._decrypt_characteristics_cached = Mock(return_value=sample_device_characteristics)
                device_service._calculate_similarity_optimized = Mock(return_value=100.0)
                device_service._update_verification_history_async = Mock()
                
                validation_result = device_service.validate_fingerprint(user_id, sample_device_characteristics)
                
                # Verify validation success
                assert validation_result["success"] is True
                assert validation_result["approved"] is True
                assert validation_result["similarity"] == 100.0
                assert validation_result["deviceId"] == device_id
    
    def test_device_registration_limit_enforcement_flow(self, device_service, sample_device_characteristics):
        """Test device registration limit enforcement workflow"""
        user_id = "user_123"
        
        # Mock user already has 3 devices
        existing_devices = [
            {"deviceId": "device_1", "userId": user_id},
            {"deviceId": "device_2", "userId": user_id},
            {"deviceId": "device_3", "userId": user_id}
        ]
        device_service._get_user_devices = Mock(return_value=existing_devices)
        
        # Step 1: Try to register 4th device without MFA
        result = device_service.register_device(user_id, sample_device_characteristics, mfa_verified=False)
        
        assert result["success"] is False
        assert result["error"] == "DEVICE_LIMIT_EXCEEDED"
        assert result["requires_mfa"] is True
        
        # Step 2: Register 4th device with MFA verification
        device_service._fingerprint_exists = Mock(return_value=False)
        mock_doc_ref = Mock()
        device_service.db.collection.return_value.document.return_value = mock_doc_ref
        
        with patch('app.services.device_fingerprint_service.encryption_service') as mock_encryption:
            mock_encryption.encrypt_device_fingerprint.return_value = "encrypted_data"
            
            result = device_service.register_device(user_id, sample_device_characteristics, mfa_verified=True)
            
            assert result["success"] is True
            assert "deviceId" in result
            
            # Verify MFA verification was recorded
            stored_data = mock_doc_ref.set.call_args[0][0]
            assert stored_data["mfaVerified"] is True
    
    def test_device_fingerprint_mismatch_flow(self, device_service, sample_device_characteristics):
        """Test device fingerprint mismatch detection workflow"""
        user_id = "user_123"
        
        # Register original device
        original_characteristics = sample_device_characteristics.copy()
        
        # Create modified characteristics (different device)
        modified_characteristics = sample_device_characteristics.copy()
        modified_characteristics["canvas"]["hash"] = "different_canvas_hash"
        modified_characteristics["webgl"]["renderer"] = "Different GPU"
        
        # Mock registered device
        mock_device = {
            "deviceId": "device_123",
            "characteristics": "encrypted_original_data",
            "trustScore": 95,
            "fingerprintHash": device_service.generate_fingerprint_hash(original_characteristics)
        }
        
        # Mock validation with different device
        with patch('app.services.device_fingerprint_service.cache_service') as mock_cache:
            mock_cache.get_device_profile.return_value = None
            
            device_service._get_user_devices_cached = Mock(return_value=[mock_device])
            device_service._decrypt_characteristics_cached = Mock(return_value=original_characteristics)
            device_service._calculate_similarity_optimized = Mock(return_value=65.0)  # Low similarity
            
            validation_result = device_service.validate_fingerprint(user_id, modified_characteristics)
            
            # Verify mismatch detection
            assert validation_result["success"] is False
            assert validation_result["approved"] is False
            assert validation_result["similarity"] == 65.0
            assert validation_result["requires_reregistration"] is True
            assert validation_result["error"] == "FINGERPRINT_MISMATCH"
    
    def test_device_trust_score_evolution_flow(self, device_service):
        """Test device trust score evolution over multiple validations"""
        device_id = "device_123"
        
        # Mock device document
        mock_device_data = {"trustScore": 80, "lastVerified": datetime.utcnow()}
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = mock_device_data
        
        mock_doc_ref = Mock()
        mock_doc_ref.get.return_value = mock_doc
        device_service.db.collection.return_value.document.return_value = mock_doc_ref
        
        # Step 1: Successful validation (trust score should increase)
        device_service.update_fingerprint_trust_score(device_id, True)
        
        update_call = mock_doc_ref.update.call_args[0][0]
        assert update_call["trustScore"] == 85  # 80 + 5
        
        # Reset mock for next call
        mock_doc_ref.reset_mock()
        mock_device_data["trustScore"] = 85
        
        # Step 2: Failed validation (trust score should decrease)
        device_service.update_fingerprint_trust_score(device_id, False)
        
        update_call = mock_doc_ref.update.call_args[0][0]
        assert update_call["trustScore"] == 75  # 85 - 10
        
        # Verify lastVerified was updated
        assert "lastVerified" in update_call
    
    def test_device_anomaly_detection_flow(self, device_service):
        """Test device anomaly detection during registration"""
        # Create suspicious device characteristics
        suspicious_characteristics = {
            "canvas": {
                "hash": "suspicious_hash",
                "confidence": 30  # Low confidence - anomaly
            },
            "webgl": {
                "renderer": "",  # Missing renderer - anomaly
                "vendor": "",
                "version": ""
            },
            "audio": {
                "hash": "audio_hash",
                "sampleRate": 44100,
                "bufferSize": 4096
            },
            "screen": {
                "width": 640,  # Unusual resolution - anomaly
                "height": 480,
                "colorDepth": 24,
                "pixelRatio": 1.0
            },
            "system": {
                "platform": "Win32",
                "userAgent": "Mozilla/5.0 HeadlessChrome/91.0.4472.124",  # Headless browser - anomaly
                "language": "en-US",
                "timezone": "UTC",
                "hardwareConcurrency": 64  # Unusually high - anomaly
            }
        }
        
        # Detect anomalies
        anomalies = device_service.detect_fingerprint_anomalies(suspicious_characteristics)
        
        # Verify multiple anomalies detected
        assert len(anomalies) >= 4
        assert "Low canvas fingerprint confidence" in anomalies
        assert "Missing WebGL renderer information" in anomalies
        assert "Unusual screen resolution" in anomalies
        assert "Headless browser detected" in anomalies
        assert "Unusually high CPU core count" in anomalies
    
    def test_device_cleanup_workflow(self, device_service):
        """Test device cleanup workflow for expired devices"""
        # Mock expired devices
        mock_expired_devices = []
        for i in range(3):
            mock_doc = Mock()
            mock_doc.reference = Mock()
            mock_expired_devices.append(mock_doc)
        
        # Mock query for expired devices
        mock_query = Mock()
        mock_query.get.return_value = mock_expired_devices
        
        device_service.db.collection.return_value.where.return_value.where.return_value = mock_query
        
        # Execute cleanup
        cleanup_count = device_service.cleanup_expired_fingerprints()
        
        # Verify cleanup results
        assert cleanup_count == 3
        
        # Verify all expired devices were deleted
        for mock_doc in mock_expired_devices:
            mock_doc.reference.delete.assert_called_once()
    
    def test_performance_optimization_workflow(self, device_service, sample_device_characteristics):
        """Test performance optimization features in validation workflow"""
        user_id = "user_123"
        
        # Test caching workflow
        with patch('app.services.device_fingerprint_service.cache_service') as mock_cache:
            # Step 1: Cache miss - full validation
            mock_cache.get_device_profile.return_value = None
            
            mock_device = {
                "deviceId": "device_123",
                "characteristics": "encrypted_data",
                "trustScore": 95
            }
            
            device_service._get_user_devices_cached = Mock(return_value=[mock_device])
            device_service._decrypt_characteristics_cached = Mock(return_value=sample_device_characteristics)
            device_service._calculate_similarity_optimized = Mock(return_value=96.5)
            device_service._update_verification_history_async = Mock()
            
            result1 = device_service.validate_fingerprint(user_id, sample_device_characteristics)
            
            # Verify cache was checked and result was cached
            mock_cache.get_device_profile.assert_called()
            mock_cache.cache_device_profile.assert_called()
            
            # Step 2: Cache hit - fast validation
            cached_result = {
                "success": True,
                "approved": True,
                "similarity": 96.5,
                "deviceId": "device_123",
                "response_time_ms": 15.0
            }
            mock_cache.get_device_profile.return_value = cached_result
            
            result2 = device_service.validate_fingerprint(user_id, sample_device_characteristics)
            
            # Verify cached result was returned
            assert result2 == cached_result
            assert result2["response_time_ms"] < 50  # Fast response from cache
    
    def test_error_handling_workflow(self, device_service, sample_device_characteristics):
        """Test error handling throughout the device registration workflow"""
        user_id = "user_123"
        
        # Test registration with database error
        device_service._get_user_devices = Mock(side_effect=Exception("Database connection failed"))
        
        with pytest.raises(Exception):
            device_service.register_device(user_id, sample_device_characteristics)
        
        # Test validation with invalid characteristics
        with pytest.raises(Exception):
            device_service.validate_fingerprint(user_id, None)
        
        # Test hash generation with invalid data
        with pytest.raises(Exception):
            device_service.generate_fingerprint_hash(None)
    
    def test_concurrent_device_registration_workflow(self, device_service, sample_device_characteristics):
        """Test concurrent device registration handling"""
        user_id = "user_123"
        
        # Simulate concurrent registration attempts
        device_service._get_user_devices = Mock(return_value=[])
        device_service._fingerprint_exists = Mock(side_effect=[False, True])  # Second attempt finds duplicate
        
        mock_doc_ref = Mock()
        device_service.db.collection.return_value.document.return_value = mock_doc_ref
        
        with patch('app.services.device_fingerprint_service.encryption_service') as mock_encryption:
            mock_encryption.encrypt_device_fingerprint.return_value = "encrypted_data"
            
            # First registration succeeds
            result1 = device_service.register_device(user_id, sample_device_characteristics)
            assert result1["success"] is True
            
            # Second registration with same fingerprint fails
            result2 = device_service.register_device(user_id, sample_device_characteristics)
            assert result2["success"] is False
            assert result2["error"] == "DUPLICATE_FINGERPRINT"