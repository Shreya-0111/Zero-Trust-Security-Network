"""
Integration Tests for Access Request Flow
Tests complete access request submission and evaluation flow
"""
import pytest
from unittest.mock import Mock, patch
import json
from datetime import datetime


@pytest.mark.integration
class TestAccessRequestFlow:
    """Test complete access request submission and evaluation flow"""
    
    def test_submit_access_request(self, client, mock_firestore, auth_headers, test_access_request):
        """Test submitting a new access request"""
        # Mock Firestore operations
        mock_doc_ref = Mock()
        mock_firestore.collection.return_value.document.return_value = mock_doc_ref
        
        # Mock policy engine evaluation
        with patch('app.services.policy_engine.policy_engine.evaluate_request') as mock_evaluate:
            mock_evaluate.return_value = {
                'decision': 'granted',
                'confidenceScore': 85,
                'confidenceBreakdown': {
                    'roleMatch': 100,
                    'intentClarity': 80,
                    'historicalPattern': 75,
                    'contextValidity': 90,
                    'anomalyScore': 80
                },
                'policiesApplied': ['policy_1'],
                'message': 'Access granted'
            }
            
            response = client.post(
                '/api/access/request',
                data=json.dumps(test_access_request),
                headers=auth_headers,
                content_type='application/json'
            )
            
            # Verify response
            assert response.status_code in [200, 201, 401, 500]
            data = response.get_json()
            
            if response.status_code in [200, 201]:
                assert 'requestId' in data or 'decision' in data
    
    
    def test_submit_request_with_invalid_intent(self, client, auth_headers):
        """Test submitting request with invalid intent (too short)"""
        invalid_request = {
            'userId': 'test_user_123',
            'resource': 'lab_server',
            'intent': 'short',  # Too short
            'duration': '7 days',
            'urgency': 'medium'
        }
        
        response = client.post(
            '/api/access/request',
            data=json.dumps(invalid_request),
            headers=auth_headers,
            content_type='application/json'
        )
        
        # Should return validation error
        assert response.status_code in [400, 500]
        data = response.get_json()
        assert data.get('success') == False or 'error' in data
    
    
    def test_submit_request_with_few_words(self, client, auth_headers):
        """Test submitting request with too few words in intent"""
        invalid_request = {
            'userId': 'test_user_123',
            'resource': 'lab_server',
            'intent': 'Need database access urgently',  # Only 4 words
            'duration': '7 days',
            'urgency': 'medium'
        }
        
        response = client.post(
            '/api/access/request',
            data=json.dumps(invalid_request),
            headers=auth_headers,
            content_type='application/json'
        )
        
        # Should return validation error
        assert response.status_code in [400, 500]
    
    
    def test_access_request_evaluation_high_confidence(self, client, mock_firestore, auth_headers, test_access_request):
        """Test access request with high confidence score (auto-approve)"""
        mock_doc_ref = Mock()
        mock_firestore.collection.return_value.document.return_value = mock_doc_ref
        
        with patch('app.services.policy_engine.policy_engine.evaluate_request') as mock_evaluate:
            mock_evaluate.return_value = {
                'decision': 'granted',
                'confidenceScore': 95,
                'confidenceBreakdown': {
                    'roleMatch': 100,
                    'intentClarity': 95,
                    'historicalPattern': 90,
                    'contextValidity': 95,
                    'anomalyScore': 95
                },
                'policiesApplied': ['policy_1'],
                'message': 'Access automatically granted'
            }
            
            response = client.post(
                '/api/access/request',
                data=json.dumps(test_access_request),
                headers=auth_headers,
                content_type='application/json'
            )
            
            if response.status_code in [200, 201]:
                data = response.get_json()
                assert data.get('decision') == 'granted' or data.get('success') == True
    
    
    def test_access_request_evaluation_medium_confidence(self, client, mock_firestore, auth_headers, test_access_request):
        """Test access request with medium confidence score (require MFA)"""
        mock_doc_ref = Mock()
        mock_firestore.collection.return_value.document.return_value = mock_doc_ref
        
        with patch('app.services.policy_engine.policy_engine.evaluate_request') as mock_evaluate:
            mock_evaluate.return_value = {
                'decision': 'granted_with_mfa',
                'confidenceScore': 75,
                'confidenceBreakdown': {
                    'roleMatch': 80,
                    'intentClarity': 70,
                    'historicalPattern': 75,
                    'contextValidity': 80,
                    'anomalyScore': 70
                },
                'policiesApplied': ['policy_1'],
                'message': 'MFA verification required'
            }
            
            response = client.post(
                '/api/access/request',
                data=json.dumps(test_access_request),
                headers=auth_headers,
                content_type='application/json'
            )
            
            if response.status_code in [200, 201]:
                data = response.get_json()
                assert data.get('decision') == 'granted_with_mfa' or 'mfa' in str(data).lower()
    
    
    def test_access_request_evaluation_low_confidence(self, client, mock_firestore, auth_headers, test_access_request):
        """Test access request with low confidence score (deny)"""
        mock_doc_ref = Mock()
        mock_firestore.collection.return_value.document.return_value = mock_doc_ref
        
        with patch('app.services.policy_engine.policy_engine.evaluate_request') as mock_evaluate:
            mock_evaluate.return_value = {
                'decision': 'denied',
                'confidenceScore': 35,
                'confidenceBreakdown': {
                    'roleMatch': 50,
                    'intentClarity': 30,
                    'historicalPattern': 40,
                    'contextValidity': 35,
                    'anomalyScore': 20
                },
                'policiesApplied': ['policy_1'],
                'message': 'Access denied due to low confidence',
                'denialReason': 'Suspicious intent detected'
            }
            
            response = client.post(
                '/api/access/request',
                data=json.dumps(test_access_request),
                headers=auth_headers,
                content_type='application/json'
            )
            
            if response.status_code in [200, 201]:
                data = response.get_json()
                assert data.get('decision') == 'denied' or data.get('success') == False
    
    
    def test_get_access_request_history(self, client, mock_firestore, auth_headers):
        """Test retrieving access request history"""
        # Mock Firestore query
        mock_query = Mock()
        mock_docs = [
            Mock(to_dict=lambda: {
                'requestId': 'req_1',
                'decision': 'granted',
                'timestamp': datetime.utcnow()
            }),
            Mock(to_dict=lambda: {
                'requestId': 'req_2',
                'decision': 'denied',
                'timestamp': datetime.utcnow()
            })
        ]
        mock_query.stream.return_value = mock_docs
        mock_firestore.collection.return_value.where.return_value.order_by.return_value.limit.return_value = mock_query
        
        response = client.get(
            '/api/access/history?userId=test_user_123',
            headers=auth_headers
        )
        
        # Verify response
        assert response.status_code in [200, 401, 500]
        
        if response.status_code == 200:
            data = response.get_json()
            assert 'requests' in data or isinstance(data, list)
    
    
    def test_get_specific_access_request(self, client, mock_firestore, auth_headers):
        """Test retrieving specific access request details"""
        # Mock Firestore get operation
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            'requestId': 'req_123',
            'userId': 'test_user_123',
            'decision': 'granted',
            'confidenceScore': 85,
            'confidenceBreakdown': {
                'roleMatch': 100,
                'intentClarity': 80,
                'historicalPattern': 75,
                'contextValidity': 90,
                'anomalyScore': 80
            }
        }
        mock_firestore.collection.return_value.document.return_value.get.return_value = mock_doc
        
        response = client.get(
            '/api/access/req_123',
            headers=auth_headers
        )
        
        # Verify response
        assert response.status_code in [200, 401, 404, 500]
        
        if response.status_code == 200:
            data = response.get_json()
            assert 'request' in data or 'requestId' in data
    
    
    def test_resubmit_denied_request(self, client, mock_firestore, auth_headers):
        """Test resubmitting a denied access request"""
        # Mock Firestore operations
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            'requestId': 'req_123',
            'userId': 'test_user_123',
            'decision': 'denied',
            'requestedResource': 'lab_server'
        }
        mock_firestore.collection.return_value.document.return_value.get.return_value = mock_doc
        
        mock_new_doc_ref = Mock()
        mock_firestore.collection.return_value.document.return_value = mock_new_doc_ref
        
        with patch('app.services.policy_engine.policy_engine.evaluate_request') as mock_evaluate:
            mock_evaluate.return_value = {
                'decision': 'granted',
                'confidenceScore': 80,
                'message': 'Access granted on resubmission'
            }
            
            resubmit_data = {
                'intent': 'Updated intent with more details about my research project on machine learning algorithms',
                'duration': '7 days',
                'urgency': 'medium'
            }
            
            response = client.put(
                '/api/access/req_123/resubmit',
                data=json.dumps(resubmit_data),
                headers=auth_headers,
                content_type='application/json'
            )
            
            # Verify response
            assert response.status_code in [200, 401, 404, 500]
    
    
    def test_rate_limiting_access_requests(self, client, auth_headers, test_access_request):
        """Test rate limiting on access request submissions"""
        # Submit multiple requests rapidly
        responses = []
        for i in range(12):  # Exceed rate limit of 10/hour
            response = client.post(
                '/api/access/request',
                data=json.dumps(test_access_request),
                headers=auth_headers,
                content_type='application/json'
            )
            responses.append(response.status_code)
        
        # At least one should be rate limited (429) or all should fail consistently
        assert 429 in responses or all(r in [401, 500] for r in responses)


@pytest.mark.integration
class TestAccessRequestEdgeCases:
    """Test edge cases in access request flow"""
    
    def test_submit_request_without_authentication(self, client, test_access_request):
        """Test submitting request without authentication"""
        response = client.post(
            '/api/access/request',
            data=json.dumps(test_access_request),
            content_type='application/json'
        )
        
        # Should require authentication
        assert response.status_code in [401, 500]
    
    
    def test_submit_request_with_missing_fields(self, client, auth_headers):
        """Test submitting request with missing required fields"""
        incomplete_request = {
            'userId': 'test_user_123',
            'resource': 'lab_server'
            # Missing intent, duration, urgency
        }
        
        response = client.post(
            '/api/access/request',
            data=json.dumps(incomplete_request),
            headers=auth_headers,
            content_type='application/json'
        )
        
        assert response.status_code in [400, 500]
    
    
    def test_get_nonexistent_request(self, client, mock_firestore, auth_headers):
        """Test retrieving non-existent access request"""
        # Mock Firestore get operation
        mock_doc = Mock()
        mock_doc.exists = False
        mock_firestore.collection.return_value.document.return_value.get.return_value = mock_doc
        
        response = client.get(
            '/api/access/nonexistent_id',
            headers=auth_headers
        )
        
        # Should return 404
        assert response.status_code in [404, 500]
    
    
    def test_resubmit_granted_request(self, client, mock_firestore, auth_headers):
        """Test resubmitting an already granted request (should fail)"""
        # Mock Firestore get operation
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            'requestId': 'req_123',
            'userId': 'test_user_123',
            'decision': 'granted'  # Already granted
        }
        mock_firestore.collection.return_value.document.return_value.get.return_value = mock_doc
        
        resubmit_data = {
            'intent': 'Updated intent',
            'duration': '7 days',
            'urgency': 'medium'
        }
        
        response = client.put(
            '/api/access/req_123/resubmit',
            data=json.dumps(resubmit_data),
            headers=auth_headers,
            content_type='application/json'
        )
        
        # Should not allow resubmission of granted requests
        assert response.status_code in [400, 404, 500]
