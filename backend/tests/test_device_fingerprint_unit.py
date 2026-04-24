"""
Unit tests for Device Fingerprint Service
Tests device fingerprinting components, validation, and registration
"""

import pytest
import hashlib
import json
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

from app.services.device_fingerprint_service import DeviceFingerprintService
from app.utils.error_handler import ValidationError


class TestDeviceFingerprintService:
    """Unit tests for DeviceFingerprintService"""
    
    @pytest.fixture
    def service(self):
        """Create DeviceFingerprintService instance for testing"""
        with patch('app.services.device_fingerprint_service.firestore.client'):
            service = DeviceFingerprintService()
            service.db = Mock()
            return service
    
    @pytest.fixture
    def sample_fingerprint_data(self):
        """Sample device fingerprint data for testing"""
        return {
            "canvas": {
                "hash": "abc123def456",
                "confidence": 100,
                "dataLength": 1024
            },
            "webgl": {
                "renderer": "ANGLE (Intel HD Graphics 620 Direct3D11 vs_5_0 ps_5_0)",
                "vendor": "Google Inc.",
                "version": "WebGL 1.0 (OpenGL ES 2.0 Chromium)"
            },
            "audio": {
                "hash": "def456ghi789",
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
    
    def test_generate_fingerprint_hash(self, service, sample_fingerprint_data):
        """Test fingerprint hash generation"""
        # Test successful hash generation
        hash_result = service.generate_fingerprint_hash(sample_fingerprint_data)
        
        assert isinstance(hash_result, str)
        assert len(hash_result) == 64  # SHA-256 produces 64-character hex string
        
        # Test consistency - same input should produce same hash
        hash_result2 = service.generate_fingerprint_hash(sample_fingerprint_data)
        assert hash_result == hash_result2
        
        # Test different input produces different hash
        modified_data = sample_fingerprint_data.copy()
        modified_data["canvas"]["hash"] = "different_hash"
        different_hash = service.generate_fingerprint_hash(modified_data)
        assert hash_result != different_hash
    
    def test_normalize_characteristics(self, service, sample_fingerprint_data):
        """Test characteristic normalization for consistent hashing"""
        normalized = service._normalize_characteristics(sample_fingerprint_data)
        
        # Check that all expected components are present
        assert "canvas" in normalized
        assert "webgl" in normalized
        assert "audio" in normalized
        assert "screen" in normalized
        assert "system" in normalized
        
        # Check canvas normalization
        assert "hash" in normalized["canvas"]
        assert "confidence" in normalized["canvas"]
        assert normalized["canvas"]["confidence"] == 100.0
        
        # Check WebGL normalization
        assert "renderer" in normalized["webgl"]
        assert "vendor" in normalized["webgl"]
        assert "version" in normalized["webgl"]
        
        # Check screen normalization includes pixel ratio rounding
        assert normalized["screen"]["pixelRatio"] == 1.0
    
    @pytest.mark.asyncio
    async def test_register_device_success(self, service, sample_fingerprint_data):
        """Test successful device registration"""
        user_id = "test_user_123"
        
        # Mock existing devices check
        service._get_user_devices = Mock(return_value=[])
        service._fingerprint_exists = Mock(return_value=False)
        
        # Mock Firestore operations
        mock_doc_ref = Mock()
        service.db.collection.return_value.document.return_value = mock_doc_ref
        
        # Mock encryption service
        with patch('app.services.device_fingerprint_service.encryption_service') as mock_encryption:
            mock_encryption.encrypt_device_fingerprint.return_value = "encrypted_data"
            
            result = service.register_device(user_id, sample_fingerprint_data)
            
            assert result["success"] is True
            assert "deviceId" in result
            assert result["trustScore"] == 100
            assert "Device registered successfully" in result["message"]
            
            # Verify Firestore was called
            mock_doc_ref.set.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_register_device_limit_exceeded(self, service, sample_fingerprint_data):
        """Test device registration when limit is exceeded"""
        user_id = "test_user_123"
        
        # Mock existing devices (3 devices already registered)
        existing_devices = [{"deviceId": f"device_{i}"} for i in range(3)]
        service._get_user_devices = Mock(return_value=existing_devices)
        
        result = service.register_device(user_id, sample_fingerprint_data, mfa_verified=False)
        
        assert result["success"] is False
        assert result["error"] == "DEVICE_LIMIT_EXCEEDED"
        assert result["requires_mfa"] is True
    
    @pytest.mark.asyncio
    async def test_register_device_with_mfa_bypass(self, service, sample_fingerprint_data):
        """Test device registration with MFA verification bypasses limit"""
        user_id = "test_user_123"
        
        # Mock existing devices (3 devices already registered)
        existing_devices = [{"deviceId": f"device_{i}"} for i in range(3)]
        service._get_user_devices = Mock(return_value=existing_devices)
        service._fingerprint_exists = Mock(return_value=False)
        
        # Mock Firestore operations
        mock_doc_ref = Mock()
        service.db.collection.return_value.document.return_value = mock_doc_ref
        
        with patch('app.services.device_fingerprint_service.encryption_service') as mock_encryption:
            mock_encryption.encrypt_device_fingerprint.return_value = "encrypted_data"
            
            result = service.register_device(user_id, sample_fingerprint_data, mfa_verified=True)
            
            assert result["success"] is True
            assert result["mfaVerified"] is True
    
    @pytest.mark.asyncio
    async def test_validate_fingerprint_success(self, service, sample_fingerprint_data):
        """Test successful fingerprint validation"""
        user_id = "test_user_123"
        
        # Mock cached result (cache miss)
        with patch('app.services.device_fingerprint_service.cache_service') as mock_cache:
            mock_cache.get_device_profile.return_value = None
            
            # Mock user devices
            mock_device = {
                "deviceId": "device_123",
                "characteristics": "encrypted_data",
                "trustScore": 95
            }
            service._get_user_devices_cached = Mock(return_value=[mock_device])
            
            # Mock decryption and similarity calculation
            service._decrypt_characteristics_cached = Mock(return_value=sample_fingerprint_data)
            service._calculate_similarity_optimized = Mock(return_value=96.5)
            service._update_verification_history_async = Mock()
            
            result = service.validate_fingerprint(user_id, sample_fingerprint_data)
            
            assert result["success"] is True
            assert result["approved"] is True
            assert result["similarity"] == 96.5
            assert result["deviceId"] == "device_123"
            assert result["response_time_ms"] > 0
    
    @pytest.mark.asyncio
    async def test_validate_fingerprint_no_devices(self, service, sample_fingerprint_data):
        """Test fingerprint validation when no devices are registered"""
        user_id = "test_user_123"
        
        with patch('app.services.device_fingerprint_service.cache_service') as mock_cache:
            mock_cache.get_device_profile.return_value = None
            service._get_user_devices_cached = Mock(return_value=[])
            
            result = service.validate_fingerprint(user_id, sample_fingerprint_data)
            
            assert result["success"] is False
            assert result["error"] == "NO_REGISTERED_DEVICES"
            assert result["similarity"] == 0
    
    @pytest.mark.asyncio
    async def test_validate_fingerprint_mismatch(self, service, sample_fingerprint_data):
        """Test fingerprint validation with low similarity"""
        user_id = "test_user_123"
        
        with patch('app.services.device_fingerprint_service.cache_service') as mock_cache:
            mock_cache.get_device_profile.return_value = None
            
            mock_device = {
                "deviceId": "device_123",
                "characteristics": "encrypted_data",
                "trustScore": 95
            }
            service._get_user_devices_cached = Mock(return_value=[mock_device])
            service._decrypt_characteristics_cached = Mock(return_value=sample_fingerprint_data)
            service._calculate_similarity_optimized = Mock(return_value=75.0)  # Below 85% threshold
            
            result = service.validate_fingerprint(user_id, sample_fingerprint_data)
            
            assert result["success"] is False
            assert result["approved"] is False
            assert result["similarity"] == 75.0
            assert result["requires_reregistration"] is True
    
    def test_calculate_similarity(self, service):
        """Test similarity calculation between fingerprints"""
        current = {
            "canvas": {"hash": "abc123"},
            "webgl": {"renderer": "Intel", "vendor": "Intel", "version": "1.0"},
            "audio": {"hash": "def456"},
            "screen": {"width": 1920, "height": 1080},
            "system": {"platform": "Win32", "language": "en-US", "timezone": "UTC"}
        }
        
        # Test identical fingerprints
        stored_identical = current.copy()
        similarity = service._calculate_similarity(current, stored_identical)
        assert similarity == 100.0
        
        # Test partial match
        stored_partial = current.copy()
        stored_partial["canvas"]["hash"] = "different_hash"  # Canvas mismatch
        similarity = service._calculate_similarity(current, stored_partial)
        assert similarity < 100.0
        assert similarity > 0.0
    
    def test_compare_component_canvas(self, service):
        """Test canvas component comparison"""
        current = {"hash": "abc123"}
        stored_same = {"hash": "abc123"}
        stored_different = {"hash": "def456"}
        
        # Test identical canvas
        similarity = service._compare_component(current, stored_same, "canvas")
        assert similarity == 1.0
        
        # Test different canvas
        similarity = service._compare_component(current, stored_different, "canvas")
        assert similarity == 0.0
    
    def test_compare_component_webgl(self, service):
        """Test WebGL component comparison"""
        current = {"renderer": "Intel", "vendor": "Intel", "version": "1.0"}
        stored_same = {"renderer": "Intel", "vendor": "Intel", "version": "1.0"}
        stored_partial = {"renderer": "Intel", "vendor": "AMD", "version": "1.0"}
        
        # Test identical WebGL
        similarity = service._compare_component(current, stored_same, "webgl")
        assert similarity == 1.0
        
        # Test partial match (2 out of 3 match)
        similarity = service._compare_component(current, stored_partial, "webgl")
        assert abs(similarity - 0.667) < 0.01  # 2/3 ≈ 0.667
    
    def test_compare_component_screen_tolerance(self, service):
        """Test screen component comparison with tolerance"""
        current = {"width": 1920, "height": 1080}
        stored_same = {"width": 1920, "height": 1080}
        stored_close = {"width": 1900, "height": 1060}  # Within 100px tolerance
        stored_far = {"width": 1600, "height": 900}  # Outside tolerance
        
        # Test identical screen
        similarity = service._compare_component(current, stored_same, "screen")
        assert similarity == 1.0
        
        # Test close match (within tolerance)
        similarity = service._compare_component(current, stored_close, "screen")
        assert similarity == 0.8
        
        # Test far match (outside tolerance)
        similarity = service._compare_component(current, stored_far, "screen")
        assert similarity == 0.0
    
    def test_detect_fingerprint_anomalies(self, service, sample_fingerprint_data):
        """Test anomaly detection in fingerprint data"""
        # Test normal fingerprint (no anomalies)
        anomalies = service.detect_fingerprint_anomalies(sample_fingerprint_data)
        assert len(anomalies) == 0
        
        # Test low canvas confidence
        low_confidence_data = sample_fingerprint_data.copy()
        low_confidence_data["canvas"]["confidence"] = 30
        anomalies = service.detect_fingerprint_anomalies(low_confidence_data)
        assert "Low canvas fingerprint confidence" in anomalies
        
        # Test unusual screen resolution
        small_screen_data = sample_fingerprint_data.copy()
        small_screen_data["screen"]["width"] = 640
        small_screen_data["screen"]["height"] = 480
        anomalies = service.detect_fingerprint_anomalies(small_screen_data)
        assert "Unusual screen resolution" in anomalies
        
        # Test headless browser detection
        headless_data = sample_fingerprint_data.copy()
        headless_data["system"]["userAgent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 HeadlessChrome/91.0.4472.124"
        anomalies = service.detect_fingerprint_anomalies(headless_data)
        assert "Headless browser detected" in anomalies
    
    @pytest.mark.asyncio
    async def test_update_fingerprint_trust_score(self, service):
        """Test trust score updates"""
        device_id = "device_123"
        
        # Mock device document
        mock_device_data = {"trustScore": 80, "lastVerified": datetime.utcnow()}
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = mock_device_data
        
        mock_doc_ref = Mock()
        mock_doc_ref.get.return_value = mock_doc
        service.db.collection.return_value.document.return_value = mock_doc_ref
        
        # Test successful validation (trust score increase)
        service.update_fingerprint_trust_score(device_id, True)
        mock_doc_ref.update.assert_called_once()
        
        # Verify trust score increased
        update_call = mock_doc_ref.update.call_args[0][0]
        assert update_call["trustScore"] == 85  # 80 + 5
        
        # Reset mock
        mock_doc_ref.reset_mock()
        
        # Test failed validation (trust score decrease)
        service.update_fingerprint_trust_score(device_id, False)
        update_call = mock_doc_ref.update.call_args[0][0]
        assert update_call["trustScore"] == 70  # 80 - 10
    
    @pytest.mark.asyncio
    async def test_cleanup_expired_fingerprints(self, service):
        """Test cleanup of expired device fingerprints"""
        # Mock query results
        mock_docs = []
        for i in range(3):
            mock_doc = Mock()
            mock_doc.reference = Mock()
            mock_docs.append(mock_doc)
        
        mock_query = Mock()
        mock_query.get.return_value = mock_docs
        
        # Chain the query methods
        service.db.collection.return_value.where.return_value.where.return_value = mock_query
        
        cleanup_count = service.cleanup_expired_fingerprints()
        
        assert cleanup_count == 3
        
        # Verify all documents were deleted
        for mock_doc in mock_docs:
            mock_doc.reference.delete.assert_called_once()
    
    def test_performance_optimization_caching(self, service, sample_fingerprint_data):
        """Test performance optimization features"""
        user_id = "test_user_123"
        
        # Test cached device profile retrieval
        with patch('app.services.device_fingerprint_service.cache_service') as mock_cache:
            cached_devices = [{"deviceId": "cached_device"}]
            mock_cache.get_device_profile.return_value = cached_devices
            
            devices = service._get_user_devices_cached(user_id)
            
            assert devices == cached_devices
            mock_cache.get_device_profile.assert_called_once()
    
    def test_error_handling(self, service):
        """Test error handling in various scenarios"""
        # Test hash generation with invalid data
        with pytest.raises(Exception):
            service.generate_fingerprint_hash(None)
        
        # Test similarity calculation with missing components
        current = {"canvas": {"hash": "abc"}}
        stored = {"webgl": {"renderer": "Intel"}}
        
        # Should handle missing components gracefully
        similarity = service._calculate_similarity(current, stored)
        assert similarity >= 0.0
        assert similarity <= 100.0