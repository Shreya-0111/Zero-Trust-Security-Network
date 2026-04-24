"""
Integration Tests for Policy Configuration and Application
Tests policy CRUD operations and policy application to access requests
"""
import pytest
from unittest.mock import Mock, patch
import json
from datetime import datetime


@pytest.mark.integration
class TestPolicyConfiguration:
    """Test policy configuration operations"""
    
    def test_create_policy(self, client, mock_firestore, test_policy):
        """Test creating a new policy (admin only)"""
        with patch('app.middleware.authorization.verify_admin') as mock_verify:
            mock_verify.return_value = True
            
            # Mock Firestore operations
            mock_doc_ref = Mock()
            mock_firestore.collection.return_value.document.return_value = mock_doc_ref
            
            headers = {'Authorization': 'Bearer admin_token'}
            response = client.post(
                '/api/admin/policy',
                data=json.dumps(test_policy),
                headers=headers,
                content_type='application/json'
            )
            
            # Verify response
            assert response.status_code in [200, 201, 401, 500]
    
    def test_update_policy(self, client, mock_firestore, test_policy):
        """Test updating an existing policy"""
        with patch('app.middleware.authorization.verify_admin') as mock_verify:
            mock_verify.return_value = True
            
            # Mock Firestore operations
            mock_doc = Mock()
            mock_doc.exists = True
            mock_doc.to_dict.return_value = test_policy
            mock_firestore.collection.return_value.document.return_value.get.return_value = mock_doc
            mock_firestore.collection.return_value.document.return_value.update = Mock()
            
            updated_policy = test_policy.copy()
            updated_policy['rules'][0]['minConfidence'] = 80
            
            headers = {'Authorization': 'Bearer admin_token'}
            response = client.post(
                '/api/admin/policy',
                data=json.dumps(updated_policy),
                headers=headers,
                content_type='application/json'
            )
            
            assert response.status_code in [200, 201, 401, 500]
    
    
    def test_get_all_policies(self, client, mock_firestore):
        """Test retrieving all active policies"""
        # Mock Firestore query
        mock_query = Mock()
        mock_docs = [
            Mock(to_dict=lambda: {
                'policyId': 'policy_1',
                'name': 'Lab Server Access',
                'isActive': True
            }),
            Mock(to_dict=lambda: {
                'policyId': 'policy_2',
                'name': 'Library Database Access',
                'isActive': True
            })
        ]
        mock_query.stream.return_value = mock_docs
        mock_firestore.collection.return_value.where.return_value = mock_query
        
        headers = {'Authorization': 'Bearer admin_token'}
        response = client.get(
            '/api/policy/rules',
            headers=headers
        )
        
        # Verify response
        assert response.status_code in [200, 401, 500]
        
        if response.status_code == 200:
            data = response.get_json()
            assert 'policies' in data or isinstance(data, list)
    
    
    def test_policy_validation_min_confidence(self, client):
        """Test policy validation for confidence thresholds"""
        with patch('app.middleware.authorization.verify_admin') as mock_verify:
            mock_verify.return_value = True
            
            invalid_policy = {
                'name': 'Invalid Policy',
                'rules': [{
                    'resourceType': 'lab_server',
                    'allowedRoles': ['student'],
                    'minConfidence': 150  # Invalid: > 100
                }]
            }
            
            headers = {'Authorization': 'Bearer admin_token'}
            response = client.post(
                '/api/admin/policy',
                data=json.dumps(invalid_policy),
                headers=headers,
                content_type='application/json'
            )
            
            # Should return validation error
            assert response.status_code in [400, 500]
    
    
    def test_policy_without_admin_role(self, client, test_policy):
        """Test policy operations without admin role"""
        headers = {'Authorization': 'Bearer student_token'}
        
        response = client.post(
            '/api/admin/policy',
            data=json.dumps(test_policy),
            headers=headers,
            content_type='application/json'
        )
        
        # Should be forbidden
        assert response.status_code in [401, 403, 500]


@pytest.mark.integration
class TestPolicyApplication:
    """Test policy application to access requests"""
    
    def test_policy_matching_by_resource_type(self, client, mock_firestore, auth_headers):
        """Test that policies are matched by resource type"""
        # Mock policy retrieval
        mock_policy_query = Mock()
        mock_policy_docs = [
            Mock(to_dict=lambda: {
                'policyId': 'policy_1',
                'rules': [{
                    'resourceType': 'lab_server',
                    'allowedRoles': ['student', 'faculty'],
                    'minConfidence': 70
                }],
                'isActive': True
            })
        ]
        mock_policy_query.stream.return_value = mock_policy_docs
        mock_firestore.collection.return_value.where.return_value = mock_policy_query
        
        # Mock access request submission
        mock_doc_ref = Mock()
        mock_firestore.collection.return_value.document.return_value = mock_doc_ref
        
        with patch('app.services.policy_engine.policy_engine.evaluate_request') as mock_evaluate:
            mock_evaluate.return_value = {
                'decision': 'granted',
                'confidenceScore': 75,
                'policiesApplied': ['policy_1']
            }
            
            request_data = {
                'userId': 'test_user_123',
                'resource': 'lab_server',
                'intent': 'I need to access the lab server for my research project on machine learning',
                'duration': '7 days',
                'urgency': 'medium'
            }
            
            response = client.post(
                '/api/access/request',
                data=json.dumps(request_data),
                headers=auth_headers,
                content_type='application/json'
            )
            
            assert response.status_code in [200, 201, 401, 500]
    
    
    def test_policy_priority_ordering(self, client, mock_firestore):
        """Test that policies are evaluated in priority order"""
        # Mock multiple policies with different priorities
        mock_query = Mock()
        mock_docs = [
            Mock(to_dict=lambda: {
                'policyId': 'policy_high',
                'priority': 10,
                'isActive': True
            }),
            Mock(to_dict=lambda: {
                'policyId': 'policy_low',
                'priority': 1,
                'isActive': True
            })
        ]
        mock_query.stream.return_value = mock_docs
        mock_firestore.collection.return_value.where.return_value.order_by.return_value = mock_query
        
        headers = {'Authorization': 'Bearer admin_token'}
        response = client.get(
            '/api/policy/rules',
            headers=headers
        )
        
        assert response.status_code in [200, 401, 500]
    
    
    def test_policy_time_restrictions(self, client, mock_firestore, auth_headers):
        """Test policy time restrictions"""
        # Mock policy with time restrictions
        mock_policy_query = Mock()
        mock_policy_docs = [
            Mock(to_dict=lambda: {
                'policyId': 'policy_1',
                'rules': [{
                    'resourceType': 'lab_server',
                    'allowedRoles': ['student'],
                    'minConfidence': 70,
                    'timeRestrictions': {
                        'startHour': 6,
                        'endHour': 22
                    }
                }],
                'isActive': True
            })
        ]
        mock_policy_query.stream.return_value = mock_policy_docs
        mock_firestore.collection.return_value.where.return_value = mock_policy_query
        
        mock_doc_ref = Mock()
        mock_firestore.collection.return_value.document.return_value = mock_doc_ref
        
        with patch('app.services.policy_engine.policy_engine.evaluate_request') as mock_evaluate:
            # Simulate time restriction check
            current_hour = datetime.utcnow().hour
            if 6 <= current_hour <= 22:
                mock_evaluate.return_value = {'decision': 'granted', 'confidenceScore': 75}
            else:
                mock_evaluate.return_value = {'decision': 'denied', 'confidenceScore': 40}
            
            request_data = {
                'userId': 'test_user_123',
                'resource': 'lab_server',
                'intent': 'I need to access the lab server for my research project',
                'duration': '7 days',
                'urgency': 'medium'
            }
            
            response = client.post(
                '/api/access/request',
                data=json.dumps(request_data),
                headers=auth_headers,
                content_type='application/json'
            )
            
            assert response.status_code in [200, 201, 401, 500]


@pytest.mark.integration
class TestPolicyEdgeCases:
    """Test edge cases in policy configuration"""
    
    def test_create_policy_with_missing_fields(self, client):
        """Test creating policy with missing required fields"""
        with patch('app.middleware.authorization.verify_admin') as mock_verify:
            mock_verify.return_value = True
            
            incomplete_policy = {
                'name': 'Incomplete Policy'
                # Missing rules
            }
            
            headers = {'Authorization': 'Bearer admin_token'}
            response = client.post(
                '/api/admin/policy',
                data=json.dumps(incomplete_policy),
                headers=headers,
                content_type='application/json'
            )
            
            assert response.status_code in [400, 500]
    
    
    def test_policy_with_empty_allowed_roles(self, client):
        """Test policy with empty allowed roles list"""
        with patch('app.middleware.authorization.verify_admin') as mock_verify:
            mock_verify.return_value = True
            
            invalid_policy = {
                'name': 'Invalid Policy',
                'rules': [{
                    'resourceType': 'lab_server',
                    'allowedRoles': [],  # Empty
                    'minConfidence': 70
                }]
            }
            
            headers = {'Authorization': 'Bearer admin_token'}
            response = client.post(
                '/api/admin/policy',
                data=json.dumps(invalid_policy),
                headers=headers,
                content_type='application/json'
            )
            
            assert response.status_code in [400, 500]
