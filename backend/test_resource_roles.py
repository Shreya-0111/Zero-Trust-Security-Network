#!/usr/bin/env python3
"""
Test script to check resource segment roles
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.firebase_config import get_firestore_client
from app.models.resource_segment import get_all_resource_segments

def test_resource_roles():
    print("🔍 Testing resource segment roles...")
    
    try:
        db = get_firestore_client()
        
        # Get all segments and show their allowed roles
        all_segments = get_all_resource_segments(db)
        print(f"\n📋 Found {len(all_segments)} resource segments:")
        
        for segment in all_segments:
            print(f"\n🔒 {segment.name}")
            print(f"   Security Level: {segment.security_level}")
            print(f"   Requires JIT: {segment.requires_jit}")
            print(f"   Allowed Roles: {segment.allowed_roles}")
        
        # Test access for different roles
        print(f"\n🧪 Testing access for different roles:")
        
        role_clearance = {
            'student': 1,
            'visitor': 1,
            'user': 3,      # Updated to level 3 (same as faculty)
            'faculty': 3,
            'admin': 5
        }
        
        test_roles = ['user', 'student', 'faculty', 'admin']
        for role in test_roles:
            clearance = role_clearance.get(role, 1)
            print(f"\n👤 Role: {role} (Clearance: {clearance})")
            accessible_segments = []
            jit_segments = []
            
            for segment in all_segments:
                can_access, reason = segment.can_user_access(role, clearance)
                if can_access:
                    accessible_segments.append(segment.name)
                    if segment.requires_jit:
                        jit_segments.append(segment.name)
                else:
                    print(f"     ❌ {segment.name}: {reason}")
            
            print(f"   ✅ Can access: {len(accessible_segments)} segments")
            for seg in accessible_segments:
                print(f"     - {seg}")
            print(f"   🔑 JIT segments: {len(jit_segments)} segments")
            for seg in jit_segments:
                print(f"     - {seg}")
            
        print("\n✅ Resource roles test completed!")
        
    except Exception as e:
        print(f"❌ Error testing resource roles: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_resource_roles()