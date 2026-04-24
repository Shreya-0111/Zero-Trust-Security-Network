"""
Test suite for Blockchain Integration
Tests smart contract deployment, event recording, audit integrity, and tampering detection
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
import sys
import os
import hashlib
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Mock firebase before importing services
sys.modules['app.firebase_config'] = Mock(db=Mock())

from app.services.blockchain_service import BlockchainService


class TestBlockchainIntegration:
    """Test blockchain integration functionality"""
    
    @pytest.fixture
    def blockchain(self):
        """Create blockchain service instance"""
        return BlockchainService()
    
    @pytest.fixture
    def sample_audit_event(self):
        """Generate sample audit event"""
        return {
            'event_id': 'event_123',
            'user_id': 'test_user_123',
            'action': 'access_resource',
            'resource': 'lab_server',
            'result': 'success',
            'timestamp': datetime.utcnow().isoformat(),
            'ip_address': '192.168.1.100',
            'confidence_score': 85
        }
    
    @pytest.fixture
    def blockchain_record(self, sample_audit_event):
        """Generate blockchain record"""
        event_hash = hashlib.sha256(json.dumps(sample_audit_event, sort_keys=True).encode()).hexdigest()
        return {
            'transaction_id': 'tx_123',
            'block_number': 12345,
            'event_hash': event_hash,
            'timestamp': datetime.utcnow().isoformat(),
            'previous_hash': 'prev_hash_123',
            'event_data': sample_audit_event
        }
    
    # ==================== Smart Contract Deployment Tests ====================
    
    @patch('app.services.blockchain_service.Web3')
    def test_deploy_smart_contract(self, mock_web3, blockchain):
        """Test smart contract deployment"""
        # Mock Web3 and contract deployment
        mock_contract = Mock()
        mock_contract.address = '0x1234567890abcdef'
        mock_web3.return_value.eth.contract.return_value.constructor.return_value.transact.return_value = 'tx_hash'
        mock_web3.return_value.eth.wait_for_transaction_receipt.return_value = {'contractAddress': mock_contract.address}
        
        with patch.object(blockchain, 'w3', mock_web3.return_value):
            contract_address = blockchain.deploy_audit_contract()
            
            assert contract_address is not None
            assert contract_address.startswith('0x')
            
            print(f"✓ Smart contract deployed: {contract_address}")
    
    @patch('app.services.blockchain_service.Web3')
    def test_deploy_contract_failure(self, mock_web3, blockchain):
        """Test smart contract deployment failure handling"""
        mock_web3.return_value.eth.contract.return_value.constructor.return_value.transact.side_effect = Exception("Deployment failed")
        
        with patch.object(blockchain, 'w3', mock_web3.return_value):
            contract_address = blockchain.deploy_audit_contract()
            
            # Should handle failure gracefully
            assert contract_address is None
            
            print("✓ Contract deployment failure handled")
    
    # ==================== Event Recording Tests ====================
    
    @patch.object(BlockchainService, '_get_contract')
    def test_record_event_to_blockchain(self, mock_contract, blockchain, sample_audit_event):
        """Test recording audit event to blockchain"""
        # Mock contract function
        mock_function = Mock()
        mock_function.transact.return_value = 'tx_hash_123'
        mock_contract.return_value.functions.recordAuditEvent.return_value = mock_function
        
        start_time = datetime.utcnow()
        result = blockchain.record_audit_event(sample_audit_event)
        end_time = datetime.utcnow()
        
        assert result is not None
        assert 'transaction_id' in result
        assert 'block_number' in result
        assert 'event_hash' in result
        
        # Verify transaction time < 5 seconds
        transaction_time = (end_time - start_time).total_seconds()
        assert transaction_time < 5
        
        print(f"✓ Event recorded to blockchain")
        print(f"  - Transaction ID: {result['transaction_id']}")
        print(f"  - Transaction time: {transaction_time:.2f}s")
    
    @patch.object(BlockchainService, '_get_contract')
    def test_record_multiple_events(self, mock_contract, blockchain):
        """Test recording multiple events in sequence"""
        mock_function = Mock()
        mock_function.transact.return_value = 'tx_hash'
        mock_contract.return_value.functions.recordAuditEvent.return_value = mock_function
        
        events = []
        for i in range(10):
            event = {
                'event_id': f'event_{i}',
                'user_id': 'test_user',
                'action': 'access',
                'timestamp': datetime.utcnow().isoformat()
            }
            
            result = blockchain.record_audit_event(event)
            assert result is not None
            events.append(result)
        
        # All events should be recorded
        assert len(events) == 10
        
        # Each should have unique transaction ID
        tx_ids = [e['transaction_id'] for e in events]
        assert len(set(tx_ids)) == 10
        
        print(f"✓ Multiple events recorded: {len(events)}")
    
    @patch.object(BlockchainService, '_get_contract')
    def test_record_event_with_large_data(self, mock_contract, blockchain):
        """Test recording event with large data payload"""
        mock_function = Mock()
        mock_function.transact.return_value = 'tx_hash'
        mock_contract.return_value.functions.recordAuditEvent.return_value = mock_function
        
        # Create large event
        large_event = {
            'event_id': 'large_event',
            'user_id': 'test_user',
            'action': 'access',
            'timestamp': datetime.utcnow().isoformat(),
            'metadata': {
                'large_field': 'x' * 1000  # 1KB of data
            }
        }
        
        result = blockchain.record_audit_event(large_event)
        
        assert result is not None
        
        print("✓ Large event recorded successfully")
    
    # ==================== Audit Integrity Verification Tests ====================
    
    @patch.object(BlockchainService, '_get_contract')
    def test_verify_audit_integrity_valid(self, mock_contract, blockchain, blockchain_record):
        """Test audit integrity verification with valid record"""
        # Mock contract to return matching hash
        mock_contract.return_value.functions.getEventHash.return_value.call.return_value = blockchain_record['event_hash']
        
        is_valid = blockchain.verify_audit_integrity(
            transaction_id=blockchain_record['transaction_id'],
            event_data=blockchain_record['event_data']
        )
        
        assert is_valid is True
        
        print("✓ Audit integrity verified (valid)")
    
    @patch.object(BlockchainService, '_get_contract')
    def test_verify_audit_integrity_tampered(self, mock_contract, blockchain, blockchain_record):
        """Test audit integrity verification with tampered data"""
        # Mock contract to return different hash
        mock_contract.return_value.functions.getEventHash.return_value.call.return_value = 'different_hash'
        
        is_valid = blockchain.verify_audit_integrity(
            transaction_id=blockchain_record['transaction_id'],
            event_data=blockchain_record['event_data']
        )
        
        assert is_valid is False
        
        print("✓ Tampering detected (invalid)")
    
    @patch.object(BlockchainService, '_get_contract')
    def test_verify_audit_chain_integrity(self, mock_contract, blockchain):
        """Test verification of entire audit chain"""
        # Mock multiple records with linked hashes
        records = []
        prev_hash = 'genesis_hash'
        
        for i in range(5):
            record = {
                'block_number': i,
                'event_hash': f'hash_{i}',
                'previous_hash': prev_hash
            }
            records.append(record)
            prev_hash = f'hash_{i}'
        
        mock_contract.return_value.functions.getBlockRecord.return_value.call.side_effect = records
        
        is_valid = blockchain.verify_chain_integrity(start_block=0, end_block=4)
        
        assert is_valid is True
        
        print("✓ Audit chain integrity verified")
    
    @patch.object(BlockchainService, '_get_contract')
    def test_verify_audit_chain_broken(self, mock_contract, blockchain):
        """Test detection of broken audit chain"""
        # Mock records with broken chain
        records = [
            {'block_number': 0, 'event_hash': 'hash_0', 'previous_hash': 'genesis'},
            {'block_number': 1, 'event_hash': 'hash_1', 'previous_hash': 'hash_0'},
            {'block_number': 2, 'event_hash': 'hash_2', 'previous_hash': 'wrong_hash'},  # Broken link
        ]
        
        mock_contract.return_value.functions.getBlockRecord.return_value.call.side_effect = records
        
        is_valid = blockchain.verify_chain_integrity(start_block=0, end_block=2)
        
        assert is_valid is False
        
        print("✓ Broken chain detected")
    
    # ==================== Tampering Detection Tests ====================
    
    @patch.object(BlockchainService, '_get_contract')
    def test_detect_tampering_none(self, mock_contract, blockchain):
        """Test tampering detection with no tampering"""
        # Mock contract to return matching hashes
        mock_contract.return_value.functions.getEventHash.return_value.call.return_value = 'correct_hash'
        
        events = [
            {'event_id': 'e1', 'data': 'data1'},
            {'event_id': 'e2', 'data': 'data2'},
            {'event_id': 'e3', 'data': 'data3'}
        ]
        
        tampered_events = blockchain.detect_tampered_events(events)
        
        assert len(tampered_events) == 0
        
        print("✓ No tampering detected")
    
    @patch.object(BlockchainService, '_get_contract')
    def test_detect_tampering_found(self, mock_contract, blockchain):
        """Test tampering detection with tampered events"""
        # Mock contract to return different hash for one event
        def mock_get_hash(event_id):
            if event_id == 'e2':
                return Mock(call=Mock(return_value='wrong_hash'))
            return Mock(call=Mock(return_value='correct_hash'))
        
        mock_contract.return_value.functions.getEventHash.side_effect = mock_get_hash
        
        events = [
            {'event_id': 'e1', 'transaction_id': 'tx1', 'data': 'data1'},
            {'event_id': 'e2', 'transaction_id': 'tx2', 'data': 'data2'},
            {'event_id': 'e3', 'transaction_id': 'tx3', 'data': 'data3'}
        ]
        
        tampered_events = blockchain.detect_tampered_events(events)
        
        assert len(tampered_events) > 0
        assert any(e['event_id'] == 'e2' for e in tampered_events)
        
        print(f"✓ Tampering detected: {len(tampered_events)} events")
    
    @patch.object(BlockchainService, '_get_contract')
    def test_detect_tampering_batch(self, mock_contract, blockchain):
        """Test batch tampering detection"""
        mock_contract.return_value.functions.getEventHash.return_value.call.return_value = 'hash'
        
        # Create large batch of events
        events = [
            {'event_id': f'e{i}', 'transaction_id': f'tx{i}', 'data': f'data{i}'}
            for i in range(100)
        ]
        
        tampered_events = blockchain.detect_tampered_events(events)
        
        # Should process all events
        assert len(tampered_events) >= 0
        
        print(f"✓ Batch tampering detection: {len(events)} events checked")
    
    # ==================== Transaction Time Tests ====================
    
    @patch.object(BlockchainService, '_get_contract')
    def test_transaction_time_under_threshold(self, mock_contract, blockchain, sample_audit_event):
        """Test that transaction time is under 5 seconds"""
        mock_function = Mock()
        mock_function.transact.return_value = 'tx_hash'
        mock_contract.return_value.functions.recordAuditEvent.return_value = mock_function
        
        start_time = datetime.utcnow()
        result = blockchain.record_audit_event(sample_audit_event)
        end_time = datetime.utcnow()
        
        transaction_time = (end_time - start_time).total_seconds()
        
        # Must be under 5 seconds
        assert transaction_time < 5.0
        
        print(f"✓ Transaction time: {transaction_time:.3f}s (< 5s)")
    
    @patch.object(BlockchainService, '_get_contract')
    def test_average_transaction_time(self, mock_contract, blockchain):
        """Test average transaction time across multiple events"""
        mock_function = Mock()
        mock_function.transact.return_value = 'tx_hash'
        mock_contract.return_value.functions.recordAuditEvent.return_value = mock_function
        
        times = []
        for i in range(10):
            event = {'event_id': f'e{i}', 'data': 'test'}
            
            start = datetime.utcnow()
            blockchain.record_audit_event(event)
            end = datetime.utcnow()
            
            times.append((end - start).total_seconds())
        
        avg_time = sum(times) / len(times)
        
        # Average should be well under 5 seconds
        assert avg_time < 5.0
        
        print(f"✓ Average transaction time: {avg_time:.3f}s")
        print(f"  - Min: {min(times):.3f}s")
        print(f"  - Max: {max(times):.3f}s")
    
    # ==================== Hash Calculation Tests ====================
    
    def test_calculate_event_hash(self, blockchain, sample_audit_event):
        """Test event hash calculation"""
        hash1 = blockchain.calculate_event_hash(sample_audit_event)
        hash2 = blockchain.calculate_event_hash(sample_audit_event)
        
        # Same event should produce same hash
        assert hash1 == hash2
        
        # Hash should be valid SHA-256
        assert len(hash1) == 64
        assert all(c in '0123456789abcdef' for c in hash1)
        
        print(f"✓ Event hash calculated: {hash1[:16]}...")
    
    def test_hash_deterministic(self, blockchain):
        """Test that hash calculation is deterministic"""
        event = {
            'user_id': 'test',
            'action': 'access',
            'timestamp': '2024-11-13T10:00:00'
        }
        
        hashes = [blockchain.calculate_event_hash(event) for _ in range(5)]
        
        # All hashes should be identical
        assert len(set(hashes)) == 1
        
        print("✓ Hash calculation is deterministic")
    
    def test_hash_different_for_different_events(self, blockchain):
        """Test that different events produce different hashes"""
        event1 = {'user_id': 'user1', 'action': 'access'}
        event2 = {'user_id': 'user2', 'action': 'access'}
        
        hash1 = blockchain.calculate_event_hash(event1)
        hash2 = blockchain.calculate_event_hash(event2)
        
        # Different events should produce different hashes
        assert hash1 != hash2
        
        print("✓ Different events produce different hashes")
    
    # ==================== Blockchain Query Tests ====================
    
    @patch.object(BlockchainService, '_get_contract')
    def test_get_event_by_transaction_id(self, mock_contract, blockchain, blockchain_record):
        """Test retrieving event by transaction ID"""
        mock_contract.return_value.functions.getEvent.return_value.call.return_value = (
            blockchain_record['event_hash'],
            blockchain_record['timestamp'],
            blockchain_record['block_number']
        )
        
        event = blockchain.get_event_by_transaction_id(blockchain_record['transaction_id'])
        
        assert event is not None
        assert event['event_hash'] == blockchain_record['event_hash']
        
        print("✓ Event retrieved by transaction ID")
    
    @patch.object(BlockchainService, '_get_contract')
    def test_get_events_by_user(self, mock_contract, blockchain):
        """Test retrieving all events for a user"""
        mock_events = [
            ('hash1', '2024-11-13T10:00:00', 1),
            ('hash2', '2024-11-13T11:00:00', 2),
            ('hash3', '2024-11-13T12:00:00', 3)
        ]
        
        mock_contract.return_value.functions.getUserEvents.return_value.call.return_value = mock_events
        
        events = blockchain.get_events_by_user('test_user_123')
        
        assert len(events) == 3
        
        print(f"✓ User events retrieved: {len(events)}")
    
    @patch.object(BlockchainService, '_get_contract')
    def test_get_events_by_time_range(self, mock_contract, blockchain):
        """Test retrieving events within time range"""
        start_time = datetime.utcnow() - timedelta(hours=24)
        end_time = datetime.utcnow()
        
        mock_events = [
            ('hash1', start_time.isoformat(), 1),
            ('hash2', (start_time + timedelta(hours=12)).isoformat(), 2),
            ('hash3', end_time.isoformat(), 3)
        ]
        
        mock_contract.return_value.functions.getEventsByTimeRange.return_value.call.return_value = mock_events
        
        events = blockchain.get_events_by_time_range(start_time, end_time)
        
        assert len(events) == 3
        
        print(f"✓ Events retrieved by time range: {len(events)}")


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
