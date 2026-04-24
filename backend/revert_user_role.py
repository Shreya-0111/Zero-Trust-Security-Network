#!/usr/bin/env python3
"""
Revert user role back to original
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.firebase_config import get_firestore_client

def revert_user_role():
    print("🔄 Reverting user role...")
    
    try:
        db = get_firestore_client()
        
        # Revert user role for sneha07@gmail.com back to "user"
        email = "sneha07@gmail.com"
        users_ref = db.collection('users')
        query = users_ref.where('email', '==', email).limit(1)
        docs = query.get()
        
        if docs:
            user_doc = docs[0]
            user_data = user_doc.to_dict()
            print(f"👤 Found user: {email}")
            print(f"   Current role: {user_data.get('role', 'Not set')}")
            
            # Revert role back to user
            user_doc.reference.update({
                'role': 'user',
                'isActive': True  # Keep user active
            })
            
            print(f"✅ Reverted role to: user")
            print(f"✅ Kept isActive as: True")
        else:
            print(f"❌ User {email} not found in database")
            
        print("\n✅ User role revert completed!")
        
    except Exception as e:
        print(f"❌ Error reverting user role: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    revert_user_role()