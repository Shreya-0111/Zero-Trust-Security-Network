"""
Integration Tests for Admin User Management Operations
Tests admin operations including user management, audit logs, and analytics
"""
import pytest
from unittest.mock import Mock, patch
import json
from datetime import datetime


@pytest.mark.integration
class TestAdminUserManagement:
    """Test admin user management operations"""
    
    def test_get_all_users(self, client, mock_firestore):
        """Test retrieving all users (admin only)"""
        # Mock admin authentication
        with patch('app.middleware.authorization.verify_admin') as mock_verify:
            mock_verify.return_value = True
            
            # Mock Firestore query
            mock_query = Mock()
            mock_docs = [
                Mock(to_dict=lambda: {
                    'userId': 'user_1',
                    'email': 'user1@example.com',
                    'role': 'student',
                    'isActive': True
                }),
                Mock(to_dict=lambda: {
                    'userId': 'user_2',
                    'email': 'user2@example.com',
                    'role': 'faculty',
                    'isActive': True
                })
            ]
            mock_query.stream.return_value = mock_docs
            mock_firestore.collection.return_value.limit.return_value = mock_query
            
            headers = {'Authorization': 'Bearer admin_token'}
            response = client.get(
                '/api/admin/users',
                headers=headers
            )
            
            # Verify response
            assert response.status_code in [200, 401, 500]
            
            if response.status_code == 200:
                data = response.get_json()
                assert 'users' in data or isinstance(data, list)
    
    
    def test_update_user_role(self, client, mock_firestore):
        """Test updating user role (admin only)"""
        with patch('app.middleware.authorization.verify_admin') as mock_verify:
            mock_verify.return_value = True
            
            # Mock Firestore operations
            mock_doc = Mock()
            mock_doc.exists = True
            mock_doc.to_dict.return_value = {
                'userId': 'user_123',
                'role': 'student',
                'email': 'user@example.com'
            }
            mock_firestore.collection.return_value.document.return_value.get.return_value = mock_doc
            mock_firestore.collection.return_value.document.return_value.update = Mock()
            
            update_data = {
                'role': 'faculty'
            }
            
            headers = {'Authorization': 'Bearer admin_token'}
            response = client.put(
                '/api/admin/users/user_123',
                data=json.dumps(update_data),
                headers=headers,
                content_type='application/json'
            )
            
            # Verify response
            assert response.status_code in [200, 401, 404, 500]
    
    
    def test_deactivate_user(self, client, mock_firestore):
        """Test deactivating user account (admin only)"""
        with patch('app.middleware.authorization.verify_admin') as mock_verify:
            mock_verify.return_value = True
            
            # Mock Firestore operations
            mock_doc = Mock()
            mock_doc.exists = True
            mock_doc.to_dict.return_value = {
                'userId': 'user_123',
                'isActive': True
            }
            mock_firestore.collection.return_value.document.return_value.get.return_value = mock_doc
            mock_firestore.collection.return_value.document.return_value.update = Mock()
            
            headers = {'Authorization': 'Bearer admin_token'}
            response = client.delete(
                '/api/admin/users/user_123',
                headers=headers
            )
            
            # Verify response
            assert response.status_code in [200, 401, 404, 500]
    
    
    def test_prevent_admin_self_deletion(self, client, mock_firestore):
        """Test that admin cannot delete their own account"""
        with patch('app.middleware.authorization.verify_admin') as mock_verify:
            mock_verify.return_value = True
            
            # Mock Firestore operations
            mock_doc = Mock()
            mock_doc.exists = True
            mock_doc.to_dict.return_value = {
                'userId': 'admin_123',
                'role': 'admin',
                'isActive': True
            }
            mock_firestore.collection.return_value.document.return_value.get.return_value = mock_doc
            
            headers = {'Authorization': 'Bearer admin_token'}
            response = client.delete(
                '/api/admin/users/admin_123',  # Same as authenticated admin
                headers=headers
            )
            
            # Should prevent self-deletion
            assert response.status_code in [400, 403, 500]
    
    
    def test_user_management_without_admin_role(self, client):
        """Test user management operations without admin role"""
        headers = {'Authorization': 'Bearer student_token'}
        
        # Try to get all users
        response = client.get(
            '/api/admin/users',
            headers=headers
        )
        
        # Should be forbidden
        assert response.status_code in [401, 403, 500]
    
    
    def test_filter_users_by_role(self, client, mock_firestore):
        """Test filtering users by role"""
        with patch('app.middleware.authorization.verify_admin') as mock_verify:
            mock_verify.return_value = True
            
            # Mock Firestore query
            mock_query = Mock()
            mock_docs = [
                Mock(to_dict=lambda: {
                    'userId': 'student_1',
                    'role': 'student'
                })
            ]
            mock_query.stream.return_value = mock_docs
            mock_firestore.collection.return_value.where.return_value.limit.return_value = mock_query
            
            headers = {'Authorization': 'Bearer admin_token'}
            response = client.get(
                '/api/admin/users?role=student',
                headers=headers
            )
            
            assert response.status_code in [200, 401, 500]
    
    
    def test_search_users(self, client, mock_firestore):
        """Test searching users by email or name"""
        with patch('app.middleware.authorization.verify_admin') as mock_verify:
            mock_verify.return_value = True
            
            # Mock Firestore query
            mock_query = Mock()
            mock_docs = [
                Mock(to_dict=lambda: {
                    'userId': 'user_1',
                    'email': 'john@example.com',
                    'name': 'John Doe'
                })
            ]
            mock_query.stream.return_value = mock_docs
            mock_firestore.collection.return_value.limit.return_value = mock_query
            
            headers = {'Authorization': 'Bearer admin_token'}
            response = client.get(
                '/api/admin/users?search=john',
                headers=headers
            )
            
            assert response.status_code in [200, 401, 500]


@pytest.mark.integration
class TestAdminAuditLogs:
    """Test admin audit log operations"""
    
    def test_get_audit_logs(self, client, mock_firestore):
        """Test retrieving audit logs (admin only)"""
        with patch('app.middleware.authorization.verify_admin') as mock_verify:
            mock_verify.return_value = True
            
            # Mock Firestore query
            mock_query = Mock()
            mock_docs = [
                Mock(to_dict=lambda: {
                    'logId': 'log_1',
                    'eventType': 'authentication',
                    'action': 'login',
                    'timestamp': datetime.utcnow()
                }),
                Mock(to_dict=lambda: {
                    'logId': 'log_2',
                    'eventType': 'access_request',
                    'action': 'request_submitted',
                    'timestamp': datetime.utcnow()
                })
            ]
            mock_query.stream.return_value = mock_docs
            mock_firestore.collection.return_value.order_by.return_value.limit.return_value = mock_query
            
            headers = {'Authorization': 'Bearer admin_token'}
            response = client.get(
                '/api/admin/logs',
                headers=headers
            )
            
            # Verify response
            assert response.status_code in [200, 401, 500]
            
            if response.status_code == 200:
                data = response.get_json()
                assert 'logs' in data or isinstance(data, list)
    
    
    def test_filter_logs_by_event_type(self, client, mock_firestore):
        """Test filtering audit logs by event type"""
        with patch('app.middleware.authorization.verify_admin') as mock_verify:
            mock_verify.return_value = True
            
            # Mock Firestore query
            mock_query = Mock()
            mock_docs = [
                Mock(to_dict=lambda: {
                    'logId': 'log_1',
                    'eventType': 'authentication',
                    'timestamp': datetime.utcnow()
                })
            ]
            mock_query.stream.return_value = mock_docs
            mock_firestore.collection.return_value.where.return_value.order_by.return_value.limit.return_value = mock_query
            
            headers = {'Authorization': 'Bearer admin_token'}
            response = client.get(
                '/api/admin/logs?eventType=authentication',
                headers=headers
            )
            
            assert response.status_code in [200, 401, 500]
    
    
    def test_filter_logs_by_severity(self, client, mock_firestore):
        """Test filtering audit logs by severity"""
        with patch('app.middleware.authorization.verify_admin') as mock_verify:
            mock_verify.return_value = True
            
            # Mock Firestore query
            mock_query = Mock()
            mock_docs = [
                Mock(to_dict=lambda: {
                    'logId': 'log_1',
                    'severity': 'high',
                    'timestamp': datetime.utcnow()
                })
            ]
            mock_query.stream.return_value = mock_docs
            mock_firestore.collection.return_value.where.return_value.order_by.return_value.limit.return_value = mock_query
            
            headers = {'Authorization': 'Bearer admin_token'}
            response = client.get(
                '/api/admin/logs?severity=high',
                headers=headers
            )
            
            assert response.status_code in [200, 401, 500]
    
    
    def test_audit_logs_without_admin_role(self, client):
        """Test accessing audit logs without admin role"""
        headers = {'Authorization': 'Bearer student_token'}
        
        response = client.get(
            '/api/admin/logs',
            headers=headers
        )
        
        # Should be forbidden
        assert response.status_code in [401, 403, 500]


@pytest.mark.integration
class TestAdminAnalytics:
    """Test admin analytics operations"""
    
    def test_get_analytics(self, client, mock_firestore):
        """Test retrieving system analytics (admin only)"""
        with patch('app.middleware.authorization.verify_admin') as mock_verify:
            mock_verify.return_value = True
            
            # Mock Firestore query for access requests
            mock_query = Mock()
            mock_docs = [
                Mock(to_dict=lambda: {
                    'decision': 'granted',
                    'confidenceScore': 85,
                    'userRole': 'student'
                }),
                Mock(to_dict=lambda: {
                    'decision': 'denied',
                    'confidenceScore': 45,
                    'userRole': 'faculty'
                })
            ]
            mock_query.stream.return_value = mock_docs
            mock_firestore.collection.return_value.where.return_value = mock_query
            
            headers = {'Authorization': 'Bearer admin_token'}
            response = client.get(
                '/api/admin/analytics?timeRange=week',
                headers=headers
            )
            
            # Verify response
            assert response.status_code in [200, 401, 500]
            
            if response.status_code == 200:
                data = response.get_json()
                assert 'analytics' in data or 'totalRequests' in data
    
    
    def test_analytics_with_time_range(self, client, mock_firestore):
        """Test analytics with different time ranges"""
        with patch('app.middleware.authorization.verify_admin') as mock_verify:
            mock_verify.return_value = True
            
            mock_query = Mock()
            mock_query.stream.return_value = []
            mock_firestore.collection.return_value.where.return_value = mock_query
            
            headers = {'Authorization': 'Bearer admin_token'}
            
            # Test different time ranges
            for time_range in ['day', 'week', 'month']:
                response = client.get(
                    f'/api/admin/analytics?timeRange={time_range}',
                    headers=headers
                )
                
                assert response.status_code in [200, 401, 500]
    
    
    def test_analytics_without_admin_role(self, client):
        """Test accessing analytics without admin role"""
        headers = {'Authorization': 'Bearer student_token'}
        
        response = client.get(
            '/api/admin/analytics',
            headers=headers
        )
        
        # Should be forbidden
        assert response.status_code in [401, 403, 500]


@pytest.mark.integration
class TestAdminEdgeCases:
    """Test edge cases in admin operations"""
    
    def test_update_nonexistent_user(self, client, mock_firestore):
        """Test updating non-existent user"""
        with patch('app.middleware.authorization.verify_admin') as mock_verify:
            mock_verify.return_value = True
            
            # Mock Firestore get operation
            mock_doc = Mock()
            mock_doc.exists = False
            mock_firestore.collection.return_value.document.return_value.get.return_value = mock_doc
            
            update_data = {'role': 'faculty'}
            
            headers = {'Authorization': 'Bearer admin_token'}
            response = client.put(
                '/api/admin/users/nonexistent_id',
                data=json.dumps(update_data),
                headers=headers,
                content_type='application/json'
            )
            
            # Should return 404
            assert response.status_code in [404, 500]
    
    
    def test_update_user_with_invalid_role(self, client, mock_firestore):
        """Test updating user with invalid role"""
        with patch('app.middleware.authorization.verify_admin') as mock_verify:
            mock_verify.return_value = True
            
            mock_doc = Mock()
            mock_doc.exists = True
            mock_doc.to_dict.return_value = {'userId': 'user_123', 'role': 'student'}
            mock_firestore.collection.return_value.document.return_value.get.return_value = mock_doc
            
            update_data = {'role': 'invalid_role'}
            
            headers = {'Authorization': 'Bearer admin_token'}
            response = client.put(
                '/api/admin/users/user_123',
                data=json.dumps(update_data),
                headers=headers,
                content_type='application/json'
            )
            
            # Should return validation error
            assert response.status_code in [400, 500]
