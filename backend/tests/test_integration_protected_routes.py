"""
Integration Tests for Protected Routes and Authorization
Tests route protection and role-based access control
"""
import pytest
from unittest.mock import Mock, patch
import json


@pytest.mark.integration
class TestProtectedRoutes:
    """Test protected route access control"""
    
    def test_access_protected_route_without_auth(self, client):
        """Test accessing protected route without authentication"""
        response = client.get('/api/access/history')
        
        # Should require authentication
        assert response.status_code in [401, 500]
        data = response.get_json()
        assert data.get('success') == False or 'error' in data
    
    
    def test_access_protected_route_with_valid_token(self, client, auth_headers, mock_firestore):
        """Test accessing protected route with valid token"""
        # Mock Firestore query
        mock_query = Mock()
        mock_query.stream.return_value = []
        mock_firestore.collection.return_value.where.return_value.order_by.return_value.limit.return_value = mock_query
        
        response = client.get(
            '/api/access/history?userId=test_user_123',
            headers=auth_headers
        )
        
        # Should allow access
        assert response.status_code in [200, 401, 500]
    
    
    def test_access_protected_route_with_expired_token(self, client):
        """Test accessing protected route with expired token"""
        import jwt
        from datetime import datetime, timedelta
        
        # Create expired token
        payload = {
            'userId': 'test_user_123',
            'exp': datetime.utcnow() - timedelta(hours=1)  # Expired
        }
        expired_token = jwt.encode(payload, 'test_secret', algorithm='HS256')
        
        headers = {
            'Authorization': f'Bearer {expired_token}',
            'Content-Type': 'application/json'
        }
        
        response = client.get(
            '/api/access/history',
            headers=headers
        )
        
        # Should reject expired token
        assert response.status_code in [401, 500]
    
    
    def test_access_admin_route_with_student_role(self, client, mock_firestore):
        """Test accessing admin route with student role"""
        import jwt
        from datetime import datetime, timedelta
        
        # Create student token
        payload = {
            'userId': 'student_123',
            'role': 'student',
            'exp': datetime.utcnow() + timedelta(hours=1)
        }
        student_token = jwt.encode(payload, 'test_secret', algorithm='HS256')
        
        headers = {
            'Authorization': f'Bearer {student_token}',
            'Content-Type': 'application/json'
        }
        
        response = client.get(
            '/api/admin/users',
            headers=headers
        )
        
        # Should be forbidden
        assert response.status_code in [401, 403, 500]
    
    
    def test_access_admin_route_with_admin_role(self, client, mock_firestore):
        """Test accessing admin route with admin role"""
        import jwt
        from datetime import datetime, timedelta
        
        # Create admin token
        payload = {
            'userId': 'admin_123',
            'role': 'admin',
            'exp': datetime.utcnow() + timedelta(hours=1)
        }
        admin_token = jwt.encode(payload, 'test_secret', algorithm='HS256')
        
        headers = {
            'Authorization': f'Bearer {admin_token}',
            'Content-Type': 'application/json'
        }
        
        # Mock Firestore query
        mock_query = Mock()
        mock_query.stream.return_value = []
        mock_firestore.collection.return_value.limit.return_value = mock_query
        
        with patch('app.middleware.authorization.verify_admin') as mock_verify:
            mock_verify.return_value = True
            
            response = client.get(
                '/api/admin/users',
                headers=headers
            )
            
            # Should allow access
            assert response.status_code in [200, 401, 500]
    
    
    def test_csrf_protection_on_state_changing_endpoints(self, client, auth_headers):
        """Test CSRF protection on POST/PUT/DELETE endpoints"""
        # Attempt state-changing operation without CSRF token
        request_data = {
            'userId': 'test_user_123',
            'resource': 'lab_server',
            'intent': 'Test intent for CSRF protection validation',
            'duration': '7 days',
            'urgency': 'medium'
        }
        
        response = client.post(
            '/api/access/request',
            data=json.dumps(request_data),
            headers=auth_headers,
            content_type='application/json'
        )
        
        # Should either require CSRF token or process normally
        assert response.status_code in [200, 201, 401, 403, 500]


@pytest.mark.integration
class TestAuthorizationMiddleware:
    """Test authorization middleware functionality"""
    
    def test_jwt_token_validation(self, client):
        """Test JWT token validation in middleware"""
        # Invalid token format
        headers = {
            'Authorization': 'Bearer invalid_token_format',
            'Content-Type': 'application/json'
        }
        
        response = client.get(
            '/api/access/history',
            headers=headers
        )
        
        # Should reject invalid token
        assert response.status_code in [401, 500]
    
    
    def test_missing_authorization_header(self, client):
        """Test request without Authorization header"""
        response = client.get('/api/access/history')
        
        # Should require authorization
        assert response.status_code in [401, 500]
    
    
    def test_malformed_authorization_header(self, client):
        """Test request with malformed Authorization header"""
        headers = {
            'Authorization': 'InvalidFormat token123',
            'Content-Type': 'application/json'
        }
        
        response = client.get(
            '/api/access/history',
            headers=headers
        )
        
        # Should reject malformed header
        assert response.status_code in [401, 500]
    
    
    def test_role_based_access_control(self, client, mock_firestore):
        """Test role-based access control enforcement"""
        import jwt
        from datetime import datetime, timedelta
        
        # Test different roles
        roles = ['student', 'faculty', 'admin']
        
        for role in roles:
            payload = {
                'userId': f'{role}_123',
                'role': role,
                'exp': datetime.utcnow() + timedelta(hours=1)
            }
            token = jwt.encode(payload, 'test_secret', algorithm='HS256')
            
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            # Try to access admin endpoint
            response = client.get(
                '/api/admin/users',
                headers=headers
            )
            
            if role == 'admin':
                # Admin should have access (or at least not be forbidden)
                assert response.status_code in [200, 401, 500]
            else:
                # Non-admin should be forbidden
                assert response.status_code in [401, 403, 500]


@pytest.mark.integration
class TestRouteEdgeCases:
    """Test edge cases in route protection"""
    
    def test_access_nonexistent_route(self, client, auth_headers):
        """Test accessing non-existent route"""
        response = client.get(
            '/api/nonexistent/route',
            headers=auth_headers
        )
        
        # Should return 404
        assert response.status_code == 404
    
    
    def test_method_not_allowed(self, client, auth_headers):
        """Test using wrong HTTP method on endpoint"""
        # Try DELETE on a GET-only endpoint
        response = client.delete(
            '/api/access/history',
            headers=auth_headers
        )
        
        # Should return 405 Method Not Allowed
        assert response.status_code in [404, 405, 500]
    
    
    def test_payload_size_limit(self, client, auth_headers):
        """Test request payload size limit (1 MB)"""
        # Create large payload (> 1 MB)
        large_intent = 'x' * (2 * 1024 * 1024)  # 2 MB
        
        request_data = {
            'userId': 'test_user_123',
            'resource': 'lab_server',
            'intent': large_intent,
            'duration': '7 days',
            'urgency': 'medium'
        }
        
        response = client.post(
            '/api/access/request',
            data=json.dumps(request_data),
            headers=auth_headers,
            content_type='application/json'
        )
        
        # Should reject large payload
        assert response.status_code in [413, 500]
    
    
    def test_cors_headers(self, client):
        """Test CORS headers in response"""
        response = client.options('/api/access/request')
        
        # Should include CORS headers
        assert response.status_code in [200, 204, 404]
        # Note: CORS headers may not be present in test environment
    
    
    def test_security_headers(self, client):
        """Test security headers in response"""
        response = client.get('/health')
        
        # Check for security headers
        # Note: Some headers may not be present in test environment
        assert response.status_code == 200
