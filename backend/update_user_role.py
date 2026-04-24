#!/usr/bin/env python3
"""
Update user role script
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.firebase_config import get_firestore_client

def update_user_role():
    print("🔧 Updating user role...")
    
    try:
        db = get_firestore_client()
        
        # Update user role for sneha07@gmail.com
        email = "sneha07@gmail.com"
        users_ref = db.collection('users')
        query = users_ref.where('email', '==', email).limit(1)
        docs = query.get()
        
        if docs:
            user_doc = docs[0]
            user_data = user_doc.to_dict()
            print(f"👤 Found user: {email}")
            print(f"   Current role: {user_data.get('role', 'Not set')}")
            
            # Update role to faculty
            user_doc.reference.update({
                'role': 'faculty',
                'isActive': True  # Also ensure user is active
            })
            
            print(f"✅ Updated role to: faculty")
            print(f"✅ Set isActive to: True")
        else:
            print(f"❌ User {email} not found in database")
            
        print("\n✅ User role update completed!")
        
    except Exception as e:
        print(f"❌ Error updating user role: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    update_user_role()