"""
Enhanced Data Encryption Service for Zero Trust Framework

This service provides comprehensive AES-256 encryption for all PII data
with separate encryption keys for different data types and key rotation support.
"""

import os
import json
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from firebase_admin import firestore
import redis
import base64
from redis_config import is_redis_available

logger = logging.getLogger(__name__)

class DataEncryptionService:
    """
    Comprehensive data encryption service implementing AES-256 encryption
    with separate keys for different data types and key rotation support.
    """
    
    # Data type categories for separate encryption keys
    DATA_TYPES = {
        'PII': 'personally_identifiable_information',
        'DEVICE': 'device_fingerprints',
        'VISITOR': 'visitor_data',
        'AUDIT': 'audit_logs',
        'SESSION': 'session_data',
        'BIOMETRIC': 'biometric_data',
        'LOCATION': 'location_data',
        'BEHAVIORAL': 'behavioral_patterns'
    }
    
    # Key rotation interval (90 days)
    KEY_ROTATION_INTERVAL = timedelta(days=90)
    
    def __init__(self):
        """Initialize the encryption service with key management"""
        self.db = firestore.client()
        
        if is_redis_available():
            self.redis_client = redis.Redis(
                host=os.getenv('REDIS_HOST', 'localhost'),
                port=int(os.getenv('REDIS_PORT', 6379)),
                decode_responses=True
            )
        else:
            self.redis_client = None
            logger.info("Redis not available, skipping Redis initialization in EncryptionService")
        
        # Master key for key encryption (should be stored in HSM in production)
        self.master_key = self._get_or_create_master_key()
        
        # Initialize encryption keys for each data type
        self.encryption_keys = {}
        self._initialize_encryption_keys()
        
        # Key rotation tracking
        self._setup_key_rotation_tracking()
        
        logger.info("Data encryption service initialized with AES-256 encryption")
    
    def _get_or_create_master_key(self) -> bytes:
        """
        Get or create the master encryption key.
        In production, this should be stored in an HSM (Hardware Security Module).
        """
        master_key_env = os.getenv('MASTER_ENCRYPTION_KEY')
        
        if master_key_env:
            try:
                return base64.b64decode(master_key_env.encode())
            except Exception as e:
                logger.error(f"Error decoding master key from environment: {str(e)}")
        
        # Generate new master key if not found
        master_key = os.urandom(32)  # 256-bit key
        master_key_b64 = base64.b64encode(master_key).decode()
        
        logger.warning(
            "Generated new master key. In production, store this in HSM: "
            f"MASTER_ENCRYPTION_KEY={master_key_b64}"
        )
        
        return master_key
    
    def _initialize_encryption_keys(self) -> None:
        """Initialize encryption keys for each data type"""
        for data_type, description in self.DATA_TYPES.items():
            key_info = self._get_or_create_data_type_key(data_type)
            self.encryption_keys[data_type] = key_info
            
            logger.info(f"Initialized encryption key for {description}")
    
    def _get_or_create_data_type_key(self, data_type: str) -> Dict[str, Any]:
        """Get or create encryption key for specific data type"""
        try:
            # Try to get existing key from Firestore
            key_doc = self.db.collection('encryptionKeys').document(data_type).get()
            
            if key_doc.exists:
                key_data = key_doc.to_dict()
                
                # Check if key needs rotation
                created_at = key_data.get('createdAt')
                if created_at and self._needs_key_rotation(created_at):
                    logger.info(f"Key rotation needed for {data_type}")
                    return self._rotate_data_type_key(data_type, key_data)
                
                # Decrypt the stored key using master key
                encrypted_key = base64.b64decode(key_data['encryptedKey'])
                decrypted_key = self._decrypt_with_master_key(encrypted_key)
                
                return {
                    'key': decrypted_key,
                    'key_id': key_data['keyId'],
                    'created_at': created_at,
                    'version': key_data.get('version', 1)
                }
            else:
                # Create new key
                return self._create_new_data_type_key(data_type)
                
        except Exception as e:
            logger.error(f"Error getting/creating key for {data_type}: {str(e)}")
            # Fallback to temporary key
            return self._create_temporary_key(data_type)
    
    def _create_new_data_type_key(self, data_type: str) -> Dict[str, Any]:
        """Create a new encryption key for a data type"""
        # Generate new 256-bit key
        new_key = os.urandom(32)
        key_id = hashlib.sha256(f"{data_type}_{datetime.utcnow().isoformat()}".encode()).hexdigest()[:16]
        created_at = datetime.utcnow()
        
        # Encrypt key with master key for storage
        encrypted_key = self._encrypt_with_master_key(new_key)
        
        # Store in Firestore
        key_data = {
            'keyId': key_id,
            'encryptedKey': base64.b64encode(encrypted_key).decode(),
            'dataType': data_type,
            'createdAt': created_at,
            'version': 1,
            'isActive': True,
            'rotationScheduled': created_at + self.KEY_ROTATION_INTERVAL
        }
        
        self.db.collection('encryptionKeys').document(data_type).set(key_data)
        
        logger.info(f"Created new encryption key for {data_type} (ID: {key_id})")
        
        return {
            'key': new_key,
            'key_id': key_id,
            'created_at': created_at,
            'version': 1
        }
    
    def _rotate_data_type_key(self, data_type: str, old_key_data: Dict) -> Dict[str, Any]:
        """Rotate encryption key for a data type"""
        try:
            # Create new key
            new_key = os.urandom(32)
            new_key_id = hashlib.sha256(f"{data_type}_{datetime.utcnow().isoformat()}_rotated".encode()).hexdigest()[:16]
            created_at = datetime.utcnow()
            new_version = old_key_data.get('version', 1) + 1
            
            # Encrypt new key with master key
            encrypted_new_key = self._encrypt_with_master_key(new_key)
            
            # Archive old key
            old_key_archive = {
                **old_key_data,
                'archivedAt': created_at,
                'isActive': False,
                'replacedBy': new_key_id
            }
            
            self.db.collection('encryptionKeysArchive').document(
                f"{data_type}_v{old_key_data.get('version', 1)}"
            ).set(old_key_archive)
            
            # Store new key
            new_key_data = {
                'keyId': new_key_id,
                'encryptedKey': base64.b64encode(encrypted_new_key).decode(),
                'dataType': data_type,
                'createdAt': created_at,
                'version': new_version,
                'isActive': True,
                'rotationScheduled': created_at + self.KEY_ROTATION_INTERVAL,
                'previousVersion': old_key_data.get('version', 1)
            }
            
            self.db.collection('encryptionKeys').document(data_type).set(new_key_data)
            
            logger.info(f"Rotated encryption key for {data_type} (new ID: {new_key_id}, version: {new_version})")
            
            return {
                'key': new_key,
                'key_id': new_key_id,
                'created_at': created_at,
                'version': new_version
            }
            
        except Exception as e:
            logger.error(f"Error rotating key for {data_type}: {str(e)}")
            raise
    
    def _create_temporary_key(self, data_type: str) -> Dict[str, Any]:
        """Create temporary key as fallback"""
        try:
            temp_key = os.urandom(32)
            temp_key_id = f"temp_{data_type}_{datetime.utcnow().timestamp()}"
            
            logger.warning(f"Created temporary key for {data_type} - should be replaced with persistent key")
            
            return {
                'key': temp_key,
                'key_id': temp_key_id,
                'created_at': datetime.utcnow(),
                'version': 0  # Version 0 indicates temporary key
            }
        except Exception as e:
            logger.error(f"Error creating temporary key for {data_type}: {str(e)}")
            # Ultimate fallback - use a fixed key for development
            if os.getenv('FLASK_ENV') == 'development':
                # Use a fixed 32-byte key for development
                dev_key = hashlib.sha256(f"dev_key_{data_type}".encode()).digest()
                return {
                    'key': dev_key,
                    'key_id': f"dev_{data_type}",
                    'created_at': datetime.utcnow(),
                    'version': -1  # Version -1 indicates development key
                }
            raise
    
    def _encrypt_with_master_key(self, data: bytes) -> bytes:
        """Encrypt data using the master key"""
        # Generate random IV
        iv = os.urandom(16)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.master_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        
        # Pad data to block size
        padded_data = self._pad_data(data)
        
        # Encrypt
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return IV + encrypted data
        return iv + encrypted_data
    
    def _decrypt_with_master_key(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using the master key"""
        # Extract IV and encrypted data
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.master_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        
        decryptor = cipher.decryptor()
        
        # Decrypt
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        return self._unpad_data(padded_data)
    
    def _pad_data(self, data: bytes) -> bytes:
        """Apply PKCS7 padding"""
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _unpad_data(self, padded_data: bytes) -> bytes:
        """Remove PKCS7 padding"""
        padding_length = padded_data[-1]
        return padded_data[:-padding_length]
    
    def _needs_key_rotation(self, created_at: datetime) -> bool:
        """Check if key needs rotation based on age"""
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
        
        age = datetime.utcnow() - created_at.replace(tzinfo=None)
        return age >= self.KEY_ROTATION_INTERVAL
    
    def _setup_key_rotation_tracking(self) -> None:
        """Set up automatic key rotation tracking"""
        try:
            if not self.redis_client:
                return

            # Store rotation schedule in Redis for monitoring
            for data_type in self.DATA_TYPES.keys():
                key_info = self.encryption_keys.get(data_type)
                if key_info and key_info.get('created_at'):
                    next_rotation = key_info['created_at'] + self.KEY_ROTATION_INTERVAL
                    self.redis_client.set(
                        f"key_rotation_schedule:{data_type}",
                        next_rotation.isoformat(),
                        ex=int(self.KEY_ROTATION_INTERVAL.total_seconds())
                    )
        except Exception as e:
            logger.error(f"Error setting up key rotation tracking: {str(e)}")
    
    def encrypt_data(self, data: Any, data_type: str, additional_context: Optional[Dict] = None) -> str:
        """
        Encrypt data using the appropriate key for the data type.
        
        Args:
            data: Data to encrypt (will be JSON serialized)
            data_type: Type of data (must be in DATA_TYPES)
            additional_context: Additional context for encryption metadata
            
        Returns:
            Base64 encoded encrypted data with metadata
        """
        if data_type not in self.DATA_TYPES:
            raise ValueError(f"Invalid data type: {data_type}. Must be one of {list(self.DATA_TYPES.keys())}")
        
        try:
            # Get encryption key for data type
            key_info = self.encryption_keys.get(data_type)
            if not key_info:
                logger.error(f"No encryption key found for data type: {data_type}")
                key_info = self._get_or_create_data_type_key(data_type)
                self.encryption_keys[data_type] = key_info
            
            encryption_key = key_info.get('key')
            if not encryption_key or not isinstance(encryption_key, (bytes, bytearray)):
                logger.warning(f"Encryption key missing for {data_type}; generating temporary key")
                key_info = self._create_temporary_key(data_type)
                self.encryption_keys[data_type] = key_info
                encryption_key = key_info['key']
            
            if len(encryption_key) != 32:
                logger.warning(f"Invalid key size ({len(encryption_key)}) for {data_type}; regenerating key")
                key_info = self._create_temporary_key(data_type)
                self.encryption_keys[data_type] = key_info
                encryption_key = key_info['key']
            
            # Serialize data
            if isinstance(data, (dict, list)):
                data_json = json.dumps(data, sort_keys=True, separators=(',', ':'))
            else:
                data_json = str(data)
            
            # Create encryption metadata
            metadata = {
                'data_type': data_type,
                'key_id': key_info['key_id'],
                'key_version': key_info['version'],
                'encrypted_at': datetime.utcnow().isoformat(),
                'algorithm': 'AES-256-CBC'
            }
            
            if additional_context:
                metadata['context'] = additional_context
            
            # Generate random IV
            iv = os.urandom(16)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(encryption_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            
            encryptor = cipher.encryptor()
            
            # Pad and encrypt data
            padded_data = self._pad_data(data_json.encode('utf-8'))
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Combine metadata, IV, and encrypted data
            result = {
                'metadata': metadata,
                'iv': base64.b64encode(iv).decode(),
                'data': base64.b64encode(encrypted_data).decode()
            }
            
            # Return as base64 encoded JSON
            return base64.b64encode(json.dumps(result).encode()).decode()
            
        except Exception as e:
            logger.error(f"Error encrypting data of type {data_type}: {str(e)}")
            raise
    
    def decrypt_data(self, encrypted_data: str, expected_data_type: Optional[str] = None) -> Tuple[Any, Dict]:
        """
        Decrypt data and return both the data and metadata.
        
        Args:
            encrypted_data: Base64 encoded encrypted data with metadata
            expected_data_type: Expected data type for validation
            
        Returns:
            Tuple of (decrypted_data, metadata)
        """
        try:
            # Decode the encrypted package
            package_json = base64.b64decode(encrypted_data.encode()).decode()
            package = json.loads(package_json)
            
            metadata = package['metadata']
            iv = base64.b64decode(package['iv'])
            ciphertext = base64.b64decode(package['data'])
            
            # Validate data type if specified
            if expected_data_type and metadata['data_type'] != expected_data_type:
                raise ValueError(f"Data type mismatch: expected {expected_data_type}, got {metadata['data_type']}")
            
            data_type = metadata['data_type']
            key_id = metadata['key_id']
            key_version = metadata['key_version']
            
            # Get decryption key
            decryption_key = self._get_decryption_key(data_type, key_id, key_version)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(decryption_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            
            decryptor = cipher.decryptor()
            
            # Decrypt and unpad
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            data_json = self._unpad_data(padded_data).decode('utf-8')
            
            # Try to parse as JSON, fallback to string
            try:
                decrypted_data = json.loads(data_json)
            except json.JSONDecodeError:
                decrypted_data = data_json
            
            return decrypted_data, metadata
            
        except Exception as e:
            logger.error(f"Error decrypting data: {str(e)}")
            raise
    
    def _get_decryption_key(self, data_type: str, key_id: str, key_version: int) -> bytes:
        """Get decryption key, handling key rotation"""
        current_key_info = self.encryption_keys.get(data_type)
        
        # Check if we need the current key
        if current_key_info and current_key_info['key_id'] == key_id:
            return current_key_info['key']
        
        # Check archived keys for older versions
        try:
            archived_key_doc = self.db.collection('encryptionKeysArchive').document(
                f"{data_type}_v{key_version}"
            ).get()
            
            if archived_key_doc.exists:
                archived_key_data = archived_key_doc.to_dict()
                if archived_key_data['keyId'] == key_id:
                    encrypted_key = base64.b64decode(archived_key_data['encryptedKey'])
                    return self._decrypt_with_master_key(encrypted_key)
            
            raise ValueError(f"Decryption key not found: {data_type}/{key_id}/v{key_version}")
            
        except Exception as e:
            logger.error(f"Error retrieving decryption key: {str(e)}")
            raise
    
    def rotate_all_keys(self) -> Dict[str, bool]:
        """Manually rotate all encryption keys"""
        results = {}
        
        for data_type in self.DATA_TYPES.keys():
            try:
                old_key_data = self.db.collection('encryptionKeys').document(data_type).get().to_dict()
                if old_key_data:
                    new_key_info = self._rotate_data_type_key(data_type, old_key_data)
                    self.encryption_keys[data_type] = new_key_info
                    results[data_type] = True
                else:
                    results[data_type] = False
                    
            except Exception as e:
                logger.error(f"Error rotating key for {data_type}: {str(e)}")
                results[data_type] = False
        
        # Update rotation tracking
        self._setup_key_rotation_tracking()
        
        return results
    
    def get_key_status(self) -> Dict[str, Dict]:
        """Get status of all encryption keys"""
        status = {}
        
        for data_type in self.DATA_TYPES.keys():
            key_info = self.encryption_keys.get(data_type)
            if key_info:
                next_rotation = key_info['created_at'] + self.KEY_ROTATION_INTERVAL
                days_until_rotation = (next_rotation - datetime.utcnow()).days
                
                status[data_type] = {
                    'key_id': key_info['key_id'],
                    'version': key_info['version'],
                    'created_at': key_info['created_at'].isoformat(),
                    'next_rotation': next_rotation.isoformat(),
                    'days_until_rotation': days_until_rotation,
                    'needs_rotation': days_until_rotation <= 0
                }
            else:
                status[data_type] = {'error': 'Key not initialized'}
        
        return status
    
    def encrypt_pii_data(self, pii_data: Dict) -> str:
        """Convenience method for encrypting PII data"""
        return self.encrypt_data(pii_data, 'PII', {'classification': 'personally_identifiable'})
    
    def decrypt_pii_data(self, encrypted_pii: str) -> Dict:
        """Convenience method for decrypting PII data"""
        data, metadata = self.decrypt_data(encrypted_pii, 'PII')
        return data
    
    def encrypt_device_fingerprint(self, fingerprint_data: Dict) -> str:
        """Convenience method for encrypting device fingerprint data"""
        return self.encrypt_data(fingerprint_data, 'DEVICE', {'classification': 'device_identification'})
    
    def decrypt_device_fingerprint(self, encrypted_fingerprint: str) -> Dict:
        """Convenience method for decrypting device fingerprint data"""
        data, metadata = self.decrypt_data(encrypted_fingerprint, 'DEVICE')
        return data


# Global instance
encryption_service = DataEncryptionService()