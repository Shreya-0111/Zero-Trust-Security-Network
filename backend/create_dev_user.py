#!/usr/bin/env python3
"""
Create Development User - Works without network
This creates a user directly in Firestore for development testing
"""

import os
import sys
from datetime import datetime

def create_dev_user():
    """Create a development user directly in Firestore"""
    
    try:
        # Initialize Firebase
        import firebase_admin
        from firebase_admin import credentials, firestore
        
        # Check if already initialized
        try:
            firebase_admin.get_app()
            print("✅ Firebase already initialized")
        except ValueError:
            # Initialize Firebase
            cred_path = './firebase-credentials.json'
            if not os.path.exists(cred_path):
                print(f"❌ Firebase credentials not found at {cred_path}")
                return False
                
            cred = credentials.Certificate(cred_path)
            firebase_admin.initialize_app(cred)
            print("✅ Firebase initialized")
        
        # Development user data
        dev_user = {
            'uid': 'dev_user_12345678',
            'email': 'dev@example.com',
            'name': 'Development User',
            'role': 'admin',
            'created_at': datetime.utcnow(),
            'last_login': datetime.utcnow(),
            'email_verified': True,
            'is_dev_user': True
        }
        
        print(f"👤 Creating development user: {dev_user['email']}")
        
        # Create user document in Firestore
        db = firestore.client()
        db.collection('users').document(dev_user['uid']).set(dev_user)
        print(f"✅ Development user created in Firestore")
        
        return True
        
    except Exception as e:
        print(f"❌ Error creating development user: {e}")
        return False

def main():
    """Main function"""
    print("🚀 Creating Development User (Network-Independent)")
    print("=" * 55)
    
    success = create_dev_user()
    
    if success:
        print("\n🎉 Development user created successfully!")
        print("\n📝 Development Mode:")
        print("   - Backend will bypass Firebase network verification")
        print("   - Any Firebase ID token will work in development")
        print("   - User will be mapped to dev@example.com")
        print("\n🔗 You can now test at: http://localhost:3000")
        print("\n💡 Use any email/password in the frontend - it will work!")
    else:
        print("\n❌ Failed to create development user")

if __name__ == "__main__":
    main()