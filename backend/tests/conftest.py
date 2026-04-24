"""
Pytest configuration and fixtures for integration tests
"""
import pytest
import sys
import os
from unittest.mock import Mock, patch
import firebase_admin
from firebase_admin import credentials

# Patch firestore client before it's used
@pytest.fixture(scope='session', autouse=True)
def mock_firestore_client():
    with patch('firebase_admin.firestore.client') as mock_client:
        mock_client.return_value = Mock()
        yield

# Add the backend directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app

@pytest.fixture
def app():
    """Create and configure a test Flask application"""
    app = create_app()
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    return app


@pytest.fixture
def client(app):
    """Create a test client for the Flask application"""
    return app.test_client()


@pytest.fixture
def mock_firestore():
    """Mock Firestore client for testing"""
    with patch('app.firebase_config.get_firestore_client') as mock:
        mock_db = Mock()
        mock.return_value = mock_db
        yield mock_db


@pytest.fixture
def mock_firebase_auth():
    """Mock Firebase Auth for testing"""
    with patch('app.services.auth_service.auth') as mock:
        yield mock


@pytest.fixture
def test_user():
    """Sample test user data"""
    return {
        'userId': 'test_user_123',
        'email': 'test@example.com',
        'role': 'student',
        'name': 'Test User',
        'department': 'Computer Science',
        'isActive': True,
        'mfaEnabled': False
    }


@pytest.fixture
def test_admin():
    """Sample test admin user data"""
    return {
        'userId': 'admin_123',
        'email': 'admin@example.com',
        'role': 'admin',
        'name': 'Admin User',
        'department': 'IT',
        'isActive': True,
        'mfaEnabled': True
    }


@pytest.fixture
def test_access_request():
    """Sample test access request data"""
    return {
        'userId': 'test_user_123',
        'resource': 'lab_server',
        'intent': 'I need to access the lab server to run machine learning experiments for my thesis research project',
        'duration': '7 days',
        'urgency': 'medium'
    }


@pytest.fixture
def test_policy():
    """Sample test policy data"""
    return {
        'name': 'Lab Server Access',
        'description': 'Policy for lab server access',
        'rules': [{
            'resourceType': 'lab_server',
            'allowedRoles': ['faculty', 'admin'],
            'minConfidence': 70,
            'mfaRequired': True,
            'timeRestrictions': {
                'startHour': 6,
                'endHour': 22
            }
        }],
        'priority': 1,
        'isActive': True
    }


@pytest.fixture
def mock_jwt_token():
    """Generate a mock JWT token for testing"""
    import jwt
    from datetime import datetime, timedelta
    
    payload = {
        'userId': 'test_user_123',
        'email': 'test@example.com',
        'role': 'student',
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    
    token = jwt.encode(payload, 'test_secret', algorithm='HS256')
    return token


@pytest.fixture
def auth_headers(mock_jwt_token):
    """Generate authorization headers for testing"""
    return {
        'Authorization': f'Bearer {mock_jwt_token}',
        'Content-Type': 'application/json'
    }
