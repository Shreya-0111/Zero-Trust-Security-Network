#!/usr/bin/env python3
"""
Test script to check user role
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.firebase_config import get_firestore_client

def test_user_role():
    print("🔍 Testing user role...")
    
    try:
        db = get_firestore_client()
        
        # Check user role for sneha07@gmail.com
        email = "sneha07@gmail.com"
        users_ref = db.collection('users')
        query = users_ref.where('email', '==', email).limit(1)
        docs = query.get()
        
        if docs:
            user_doc = docs[0]
            user_data = user_doc.to_dict()
            print(f"👤 User: {email}")
            print(f"   Role: {user_data.get('role', 'Not set')}")
            print(f"   Name: {user_data.get('name', 'Not set')}")
            print(f"   Active: {user_data.get('isActive', 'Not set')}")
        else:
            print(f"❌ User {email} not found in database")
            
        print("\n✅ User role test completed!")
        
    except Exception as e:
        print(f"❌ Error testing user role: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_user_role()