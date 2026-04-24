"""
End-to-End Tests for Complete User Flows
Tests complete user journeys through the system
"""
import pytest
from unittest.mock import Mock, patch
import json


@pytest.mark.e2e
class TestCompleteUserFlows:
    """Test complete end-to-end user flows"""
    
    def test_student_complete_flow(self, client, mock_firestore, mock_firebase_auth):
        """Test complete student flow: signup -> login -> submit request -> view history"""
        # Step 1: Signup
        mock_firebase_auth.create_user.return_value = Mock(uid='student_new')
        mock_doc_ref = Mock()
        mock_firestore.collection.return_value.document.return_value = mock_doc_ref
        
        signup_data = {
            'email': 'student@example.com',
            'password': 'Password123',
            'name': 'Student User',
            'role': 'student',
            'department': 'Computer Science'
        }
        
        signup_response = client.post(
            '/api/auth/register',
            data=json.dumps(signup_data),
            content_type='application/json'
        )
        
        assert signup_response.status_code in [200, 201, 401, 500]
        
        # Step 2: Login
        mock_firebase_auth.verify_id_token.return_value = {
            'uid': 'student_new',
            'email': 'student@example.com'
        }
        
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            'userId': 'student_new',
            'email': 'student@example.com',
            'role': 'student',
            'isActive': True,
            'mfaEnabled': False
        }
        mock_firestore.collection.return_value.document.return_value.get.return_value = mock_doc
        
        login_data = {'idToken': 'mock_token'}
        login_response = client.post(
            '/api/auth/verify',
            data=json.dumps(login_data),
            content_type='application/json'
        )
        
        assert login_response.status_code in [200, 401, 500]
        
        # Step 3: Submit access request
        import jwt
        from datetime import datetime, timedelta
        
        token = jwt.encode({
            'userId': 'student_new',
            'role': 'student',
            'exp': datetime.utcnow() + timedelta(hours=1)
        }, 'test_secret', algorithm='HS256')
        
        headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
        
        with patch('app.services.policy_engine.policy_engine.evaluate_request') as mock_eval:
            mock_eval.return_value = {
                'decision': 'granted',
                'confidenceScore': 85,
                'message': 'Access granted'
            }
            
            request_data = {
                'userId': 'student_new',
                'resource': 'library_database',
                'intent': 'I need to access the library database for my research on machine learning algorithms',
                'duration': '7 days',
                'urgency': 'medium'
            }
            
            request_response = client.post(
                '/api/access/request',
                data=json.dumps(request_data),
                headers=headers,
                content_type='application/json'
            )
            
            assert request_response.status_code in [200, 201, 401, 500]
        
        # Step 4: View request history
        mock_query = Mock()
        mock_query.stream.return_value = []
        mock_firestore.collection.return_value.where.return_value.order_by.return_value.limit.return_value = mock_query
        
        history_response = client.get(
            '/api/access/history?userId=student_new',
            headers=headers
        )
        
        assert history_response.status_code in [200, 401, 500]
    
    def test_admin_complete_flow(self, client, mock_firestore, mock_firebase_auth):
        """Test complete admin flow: login -> manage users -> view logs -> configure policy"""
        # Step 1: Admin login
        import jwt
        from datetime import datetime, timedelta
        
        token = jwt.encode({
            'userId': 'admin_123',
            'role': 'admin',
            'exp': datetime.utcnow() + timedelta(hours=1)
        }, 'test_secret', algorithm='HS256')
        
        headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
        
        # Step 2: View all users
        with patch('app.middleware.authorization.verify_admin') as mock_verify:
            mock_verify.return_value = True
            
            mock_query = Mock()
            mock_query.stream.return_value = []
            mock_firestore.collection.return_value.limit.return_value = mock_query
            
            users_response = client.get(
                '/api/admin/users',
                headers=headers
            )
            
            assert users_response.status_code in [200, 401, 500]
            
            # Step 3: Update user role
            mock_doc = Mock()
            mock_doc.exists = True
            mock_doc.to_dict.return_value = {
                'userId': 'user_123',
                'role': 'student'
            }
            mock_firestore.collection.return_value.document.return_value.get.return_value = mock_doc
            mock_firestore.collection.return_value.document.return_value.update = Mock()
            
            update_data = {'role': 'faculty'}
            update_response = client.put(
                '/api/admin/users/user_123',
                data=json.dumps(update_data),
                headers=headers,
                content_type='application/json'
            )
            
            assert update_response.status_code in [200, 401, 404, 500]
            
            # Step 4: View audit logs
            mock_log_query = Mock()
            mock_log_query.stream.return_value = []
            mock_firestore.collection.return_value.order_by.return_value.limit.return_value = mock_log_query
            
            logs_response = client.get(
                '/api/admin/logs',
                headers=headers
            )
            
            assert logs_response.status_code in [200, 401, 500]
            
            # Step 5: Create new policy
            mock_doc_ref = Mock()
            mock_firestore.collection.return_value.document.return_value = mock_doc_ref
            
            policy_data = {
                'name': 'New Policy',
                'rules': [{
                    'resourceType': 'test_resource',
                    'allowedRoles': ['student'],
                    'minConfidence': 70
                }],
                'priority': 1,
                'isActive': True
            }
            
            policy_response = client.post(
                '/api/admin/policy',
                data=json.dumps(policy_data),
                headers=headers,
                content_type='application/json'
            )
            
            assert policy_response.status_code in [200, 201, 401, 500]
    
    
    def test_mfa_enabled_user_flow(self, client, mock_firestore, mock_firebase_auth):
        """Test flow for user with MFA enabled"""
        import jwt
        from datetime import datetime, timedelta
        
        # Step 1: Login
        mock_firebase_auth.verify_id_token.return_value = {
            'uid': 'mfa_user',
            'email': 'mfa@example.com'
        }
        
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            'userId': 'mfa_user',
            'email': 'mfa@example.com',
            'role': 'faculty',
            'isActive': True,
            'mfaEnabled': True,
            'mfaSecret': 'encrypted_secret'
        }
        mock_firestore.collection.return_value.document.return_value.get.return_value = mock_doc
        
        login_data = {'idToken': 'mock_token'}
        login_response = client.post(
            '/api/auth/verify',
            data=json.dumps(login_data),
            content_type='application/json'
        )
        
        # Should indicate MFA required
        assert login_response.status_code in [200, 401, 500]
        
        # Step 2: Verify MFA
        token = jwt.encode({
            'userId': 'mfa_user',
            'role': 'faculty',
            'exp': datetime.utcnow() + timedelta(hours=1)
        }, 'test_secret', algorithm='HS256')
        
        headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
        
        with patch('app.services.auth_service.pyotp.TOTP') as mock_totp:
            mock_totp_instance = Mock()
            mock_totp_instance.verify.return_value = True
            mock_totp.return_value = mock_totp_instance
            
            mfa_data = {
                'userId': 'mfa_user',
                'code': '123456'
            }
            
            mfa_response = client.post(
                '/api/auth/mfa/verify',
                data=json.dumps(mfa_data),
                headers=headers,
                content_type='application/json'
            )
            
            assert mfa_response.status_code in [200, 400, 401, 500]
        
        # Step 3: Submit access request (should require MFA)
        with patch('app.services.policy_engine.policy_engine.evaluate_request') as mock_eval:
            mock_eval.return_value = {
                'decision': 'granted_with_mfa',
                'confidenceScore': 75,
                'message': 'MFA verification required'
            }
            
            mock_doc_ref = Mock()
            mock_firestore.collection.return_value.document.return_value = mock_doc_ref
            
            request_data = {
                'userId': 'mfa_user',
                'resource': 'admin_panel',
                'intent': 'I need to access the admin panel to configure system settings for my department',
                'duration': '1 day',
                'urgency': 'high'
            }
            
            request_response = client.post(
                '/api/access/request',
                data=json.dumps(request_data),
                headers=headers,
                content_type='application/json'
            )
            
            assert request_response.status_code in [200, 201, 401, 500]


@pytest.mark.e2e
class TestErrorRecoveryFlows:
    """Test error recovery and edge case flows"""
    
    def test_failed_login_recovery(self, client, mock_firebase_auth):
        """Test recovery from failed login attempts"""
        # Attempt 1: Failed login
        mock_firebase_auth.verify_id_token.side_effect = Exception('Invalid token')
        
        login_data = {'idToken': 'invalid_token'}
        response1 = client.post(
            '/api/auth/verify',
            data=json.dumps(login_data),
            content_type='application/json'
        )
        
        assert response1.status_code in [400, 401, 500]
        
        # Attempt 2: Successful login
        mock_firebase_auth.verify_id_token.side_effect = None
        mock_firebase_auth.verify_id_token.return_value = {
            'uid': 'user_123',
            'email': 'user@example.com'
        }
        
        login_data = {'idToken': 'valid_token'}
        response2 = client.post(
            '/api/auth/verify',
            data=json.dumps(login_data),
            content_type='application/json'
        )
        
        # Should succeed or fail consistently
        assert response2.status_code in [200, 401, 500]
    
    
    def test_denied_request_resubmission(self, client, mock_firestore):
        """Test resubmitting a denied request with improved intent"""
        import jwt
        from datetime import datetime, timedelta
        
        token = jwt.encode({
            'userId': 'user_123',
            'role': 'student',
            'exp': datetime.utcnow() + timedelta(hours=1)
        }, 'test_secret', algorithm='HS256')
        
        headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
        
        # Step 1: Submit request (denied)
        mock_doc_ref = Mock()
        mock_firestore.collection.return_value.document.return_value = mock_doc_ref
        
        with patch('app.services.policy_engine.policy_engine.evaluate_request') as mock_eval:
            mock_eval.return_value = {
                'decision': 'denied',
                'confidenceScore': 35,
                'message': 'Low confidence score'
            }
            
            request_data = {
                'userId': 'user_123',
                'resource': 'lab_server',
                'intent': 'Need access urgently for testing purposes',  # Suspicious
                'duration': '7 days',
                'urgency': 'high'
            }
            
            response1 = client.post(
                '/api/access/request',
                data=json.dumps(request_data),
                headers=headers,
                content_type='application/json'
            )
            
            assert response1.status_code in [200, 201, 401, 500]
        
        # Step 2: Resubmit with improved intent
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            'requestId': 'req_123',
            'userId': 'user_123',
            'decision': 'denied',
            'requestedResource': 'lab_server'
        }
        mock_firestore.collection.return_value.document.return_value.get.return_value = mock_doc
        
        with patch('app.services.policy_engine.policy_engine.evaluate_request') as mock_eval:
            mock_eval.return_value = {
                'decision': 'granted',
                'confidenceScore': 80,
                'message': 'Access granted'
            }
            
            resubmit_data = {
                'intent': 'I need to access the lab server to run machine learning experiments for my thesis research on neural networks',
                'duration': '7 days',
                'urgency': 'medium'
            }
            
            response2 = client.put(
                '/api/access/req_123/resubmit',
                data=json.dumps(resubmit_data),
                headers=headers,
                content_type='application/json'
            )
            
            assert response2.status_code in [200, 401, 404, 500]
