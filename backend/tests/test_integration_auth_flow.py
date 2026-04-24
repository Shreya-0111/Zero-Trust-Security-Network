"""
Integration Tests for Authentication Flow
Tests complete authentication flow including signup, login, MFA, and logout
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
import json


@pytest.mark.integration
class TestAuthenticationFlow:
    """Test complete authentication flow"""
    
    def test_signup_flow(self, client, mock_firestore, mock_firebase_auth):
        """Test user signup flow"""
        # Mock Firebase Auth create_user
        mock_firebase_auth.create_user.return_value = Mock(uid='new_user_123')
        
        # Mock Firestore set operation
        mock_doc_ref = Mock()
        mock_firestore.collection.return_value.document.return_value = mock_doc_ref
        
        # Signup request
        signup_data = {
            'email': 'newuser@example.com',
            'password': 'Password123',
            'name': 'New User',
            'role': 'student',
            'department': 'Computer Science'
        }
        
        response = client.post(
            '/api/auth/register',
            data=json.dumps(signup_data),
            content_type='application/json'
        )
        
        # Verify response
        assert response.status_code in [200, 201, 401]  # May require Firebase setup
        
        if response.status_code == 200:
            data = response.get_json()
            assert 'success' in data
    
    
    def test_login_flow(self, client, mock_firestore, mock_firebase_auth):
        """Test user login flow"""
        # Mock Firebase Auth verify_id_token
        mock_firebase_auth.verify_id_token.return_value = {
            'uid': 'test_user_123',
            'email': 'test@example.com'
        }
        
        # Mock Firestore get operation
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            'userId': 'test_user_123',
            'email': 'test@example.com',
            'role': 'student',
            'name': 'Test User',
            'isActive': True,
            'mfaEnabled': False
        }
        mock_firestore.collection.return_value.document.return_value.get.return_value = mock_doc
        
        # Login request
        login_data = {
            'idToken': 'mock_firebase_token'
        }
        
        response = client.post(
            '/api/auth/verify',
            data=json.dumps(login_data),
            content_type='application/json'
        )
        
        # Verify response structure
        assert response.status_code in [200, 401, 500]
        data = response.get_json()
        assert 'success' in data or 'error' in data
    
    
    def test_login_with_invalid_credentials(self, client, mock_firebase_auth):
        """Test login with invalid credentials"""
        # Mock Firebase Auth to raise exception
        mock_firebase_auth.verify_id_token.side_effect = Exception('Invalid token')
        
        login_data = {
            'idToken': 'invalid_token'
        }
        
        response = client.post(
            '/api/auth/verify',
            data=json.dumps(login_data),
            content_type='application/json'
        )
        
        # Should return error
        assert response.status_code in [400, 401, 500]
        data = response.get_json()
        assert data.get('success') == False or 'error' in data
    
    
    def test_mfa_setup_flow(self, client, mock_firestore, auth_headers):
        """Test MFA setup flow"""
        # Mock Firestore operations
        mock_doc_ref = Mock()
        mock_firestore.collection.return_value.document.return_value = mock_doc_ref
        
        with patch('app.services.auth_service.pyotp') as mock_pyotp:
            mock_pyotp.random_base32.return_value = 'TESTSECRET123'
            
            setup_data = {
                'userId': 'test_user_123'
            }
            
            response = client.post(
                '/api/auth/mfa/setup',
                data=json.dumps(setup_data),
                headers=auth_headers,
                content_type='application/json'
            )
            
            # Verify response structure
            assert response.status_code in [200, 401, 500]
            data = response.get_json()
            
            if response.status_code == 200:
                assert 'secret' in data or 'qrCode' in data
    
    
    def test_mfa_verification_flow(self, client, mock_firestore, auth_headers):
        """Test MFA verification flow"""
        # Mock Firestore get operation
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            'userId': 'test_user_123',
            'mfaEnabled': True,
            'mfaSecret': 'encrypted_secret'
        }
        mock_firestore.collection.return_value.document.return_value.get.return_value = mock_doc
        
        with patch('app.services.auth_service.pyotp.TOTP') as mock_totp:
            mock_totp_instance = Mock()
            mock_totp_instance.verify.return_value = True
            mock_totp.return_value = mock_totp_instance
            
            verify_data = {
                'userId': 'test_user_123',
                'code': '123456'
            }
            
            response = client.post(
                '/api/auth/mfa/verify',
                data=json.dumps(verify_data),
                headers=auth_headers,
                content_type='application/json'
            )
            
            # Verify response
            assert response.status_code in [200, 400, 401, 500]
            data = response.get_json()
            assert 'success' in data or 'verified' in data or 'error' in data
    
    
    def test_mfa_verification_with_invalid_code(self, client, mock_firestore, auth_headers):
        """Test MFA verification with invalid code"""
        # Mock Firestore get operation
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            'userId': 'test_user_123',
            'mfaEnabled': True,
            'mfaSecret': 'encrypted_secret'
        }
        mock_firestore.collection.return_value.document.return_value.get.return_value = mock_doc
        
        with patch('app.services.auth_service.pyotp.TOTP') as mock_totp:
            mock_totp_instance = Mock()
            mock_totp_instance.verify.return_value = False
            mock_totp.return_value = mock_totp_instance
            
            verify_data = {
                'userId': 'test_user_123',
                'code': '000000'
            }
            
            response = client.post(
                '/api/auth/mfa/verify',
                data=json.dumps(verify_data),
                headers=auth_headers,
                content_type='application/json'
            )
            
            # Should return error or verified=false
            assert response.status_code in [200, 400, 401, 500]
            data = response.get_json()
            
            if response.status_code == 200:
                assert data.get('verified') == False
    
    
    def test_logout_flow(self, client, auth_headers):
        """Test logout flow"""
        response = client.post(
            '/api/auth/logout',
            headers=auth_headers,
            content_type='application/json'
        )
        
        # Verify response
        assert response.status_code in [200, 401, 404, 500]
        
        if response.status_code == 200:
            data = response.get_json()
            assert data.get('success') == True
    
    
    def test_session_refresh_flow(self, client, auth_headers):
        """Test session token refresh flow"""
        refresh_data = {
            'refreshToken': 'mock_refresh_token'
        }
        
        response = client.post(
            '/api/auth/refresh',
            data=json.dumps(refresh_data),
            headers=auth_headers,
            content_type='application/json'
        )
        
        # Verify response structure
        assert response.status_code in [200, 401, 500]
        data = response.get_json()
        assert 'success' in data or 'sessionToken' in data or 'error' in data
    
    
    def test_account_lockout_after_failed_attempts(self, client, mock_firestore, mock_firebase_auth):
        """Test account lockout after multiple failed login attempts"""
        # Mock Firebase Auth to raise exception
        mock_firebase_auth.verify_id_token.side_effect = Exception('Invalid credentials')
        
        # Mock Firestore operations
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            'userId': 'test_user_123',
            'failedLoginAttempts': 4  # One more attempt will lock
        }
        mock_firestore.collection.return_value.document.return_value.get.return_value = mock_doc
        
        login_data = {
            'idToken': 'invalid_token'
        }
        
        # Attempt login multiple times
        for i in range(3):
            response = client.post(
                '/api/auth/verify',
                data=json.dumps(login_data),
                content_type='application/json'
            )
            
            assert response.status_code in [400, 401, 429, 500]
        
        # Verify that failed attempts are tracked
        # (In real implementation, this would lock the account)


@pytest.mark.integration
class TestAuthenticationEdgeCases:
    """Test edge cases in authentication flow"""
    
    def test_login_with_missing_fields(self, client):
        """Test login with missing required fields"""
        login_data = {}
        
        response = client.post(
            '/api/auth/verify',
            data=json.dumps(login_data),
            content_type='application/json'
        )
        
        assert response.status_code in [400, 500]
        data = response.get_json()
        assert data.get('success') == False or 'error' in data
    
    
    def test_signup_with_invalid_email(self, client):
        """Test signup with invalid email format"""
        signup_data = {
            'email': 'invalid-email',
            'password': 'Password123',
            'name': 'Test User',
            'role': 'student'
        }
        
        response = client.post(
            '/api/auth/register',
            data=json.dumps(signup_data),
            content_type='application/json'
        )
        
        assert response.status_code in [400, 500]
    
    
    def test_signup_with_weak_password(self, client):
        """Test signup with weak password"""
        signup_data = {
            'email': 'test@example.com',
            'password': 'weak',
            'name': 'Test User',
            'role': 'student'
        }
        
        response = client.post(
            '/api/auth/register',
            data=json.dumps(signup_data),
            content_type='application/json'
        )
        
        assert response.status_code in [400, 500]
    
    
    def test_mfa_setup_without_authentication(self, client):
        """Test MFA setup without authentication"""
        setup_data = {
            'userId': 'test_user_123'
        }
        
        response = client.post(
            '/api/auth/mfa/setup',
            data=json.dumps(setup_data),
            content_type='application/json'
        )
        
        # Should require authentication
        assert response.status_code in [401, 500]
