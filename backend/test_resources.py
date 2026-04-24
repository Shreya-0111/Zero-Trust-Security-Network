#!/usr/bin/env python3
"""
Test script to check resource segments
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.firebase_config import get_firestore_client
from app.models.resource_segment import get_segments_by_role, get_all_resource_segments

def test_resources():
    print("🔍 Testing resource segments...")
    
    try:
        db = get_firestore_client()
        
        # Test getting all segments
        print("\n📋 Getting all resource segments:")
        all_segments = get_all_resource_segments(db)
        print(f"Found {len(all_segments)} total segments")
        
        for segment in all_segments:
            print(f"  - {segment.name} (Level: {segment.security_level}, JIT: {segment.requires_jit})")
        
        # Test getting segments by role
        print("\n👤 Getting segments for 'student' role:")
        student_segments = get_segments_by_role(db, 'student')
        print(f"Found {len(student_segments)} segments for students")
        
        for segment in student_segments:
            print(f"  - {segment.name}")
        
        print("\n👨‍🏫 Getting segments for 'faculty' role:")
        faculty_segments = get_segments_by_role(db, 'faculty')
        print(f"Found {len(faculty_segments)} segments for faculty")
        
        for segment in faculty_segments:
            print(f"  - {segment.name}")
            
        print("\n✅ Resource segments test completed successfully!")
        
    except Exception as e:
        print(f"❌ Error testing resources: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_resources()