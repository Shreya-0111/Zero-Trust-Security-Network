#!/usr/bin/env python3
"""
Update resource segments to include 'user' role
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.firebase_config import get_firestore_client

def update_resource_segments():
    print("🔧 Updating resource segments to include 'user' role...")
    
    try:
        db = get_firestore_client()
        
        # Get all resource segments
        segments_ref = db.collection('resourceSegments')
        segments = segments_ref.get()
        
        print(f"📋 Found {len(segments)} resource segments")
        
        updates_made = 0
        
        for segment_doc in segments:
            segment_data = segment_doc.to_dict()
            segment_name = segment_data.get('name', 'Unknown')
            current_roles = segment_data.get('allowedRoles', [])
            
            print(f"\n🔒 {segment_name}")
            print(f"   Current roles: {current_roles}")
            
            # Add 'user' role to segments that should be accessible to regular users
            # Let's add 'user' to segments that students can access, plus some faculty ones
            should_add_user = False
            
            if segment_name in [
                'Library Management System',  # Basic access
                'Email System Administration',  # Regular user access
                'Student Records System',  # Users should be able to request JIT access
                'Research Data Repository'  # Users should be able to request JIT access
            ]:
                should_add_user = True
            
            if should_add_user and 'user' not in current_roles:
                new_roles = current_roles + ['user']
                segment_doc.reference.update({
                    'allowedRoles': new_roles
                })
                print(f"   ✅ Added 'user' role. New roles: {new_roles}")
                updates_made += 1
            else:
                print(f"   ⏭️  No update needed")
        
        print(f"\n✅ Updated {updates_made} resource segments")
        print("✅ Resource segments update completed!")
        
    except Exception as e:
        print(f"❌ Error updating resource segments: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    update_resource_segments()