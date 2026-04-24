#!/usr/bin/env python3
"""
Create default resource segments for the Zero Trust Security Framework
"""

import sys
import os
sys.path.append('.')

from app.firebase_config import initialize_firebase
from app.models.resource_segment import create_resource_segment

def create_default_resource_segments():
    """Create default resource segments for testing and demo purposes"""
    
    # Initialize Firebase
    db = initialize_firebase()
    if not db:
        print("❌ Failed to initialize Firebase")
        return False
    
    print("🔧 Creating default resource segments...")
    
    # Default resource segments
    default_segments = [
        {
            'name': 'Student Records System',
            'description': 'Access to student academic records and personal information',
            'security_level': 3,
            'category': 'academic',
            'created_by': 'system',
            'allowed_roles': ['faculty', 'admin'],
            'requires_jit': True,
            'max_access_duration': 4
        },
        {
            'name': 'Financial Systems',
            'description': 'Access to financial data, payroll, and accounting systems',
            'security_level': 4,
            'category': 'administrative',
            'created_by': 'system',
            'allowed_roles': ['admin'],
            'requires_jit': True,
            'requires_dual_approval': True,
            'max_access_duration': 2
        },
        {
            'name': 'Research Data Repository',
            'description': 'Access to research data and intellectual property',
            'security_level': 3,
            'category': 'research',
            'created_by': 'system',
            'allowed_roles': ['faculty', 'admin'],
            'requires_jit': True,
            'max_access_duration': 8
        },
        {
            'name': 'Network Infrastructure',
            'description': 'Access to network configuration and monitoring systems',
            'security_level': 5,
            'category': 'infrastructure',
            'created_by': 'system',
            'allowed_roles': ['admin'],
            'requires_jit': True,
            'requires_dual_approval': True,
            'max_access_duration': 1
        },
        {
            'name': 'Email System Administration',
            'description': 'Administrative access to email servers and user accounts',
            'security_level': 2,
            'category': 'administrative',
            'created_by': 'system',
            'allowed_roles': ['faculty', 'admin'],
            'requires_jit': False,
            'max_access_duration': 24
        },
        {
            'name': 'Library Management System',
            'description': 'Access to library catalog and circulation systems',
            'security_level': 1,
            'category': 'academic',
            'created_by': 'system',
            'allowed_roles': ['student', 'faculty', 'admin'],
            'requires_jit': False,
            'max_access_duration': 24
        },
        {
            'name': 'Emergency Communication System',
            'description': 'Access to campus emergency notification and communication systems',
            'security_level': 4,
            'category': 'emergency',
            'created_by': 'system',
            'allowed_roles': ['admin'],
            'requires_jit': True,
            'requires_dual_approval': True,
            'max_access_duration': 1
        },
        {
            'name': 'Security Camera System',
            'description': 'Access to campus security cameras and surveillance systems',
            'security_level': 3,
            'category': 'infrastructure',
            'created_by': 'system',
            'allowed_roles': ['admin'],
            'requires_jit': True,
            'max_access_duration': 2
        }
    ]
    
    created_count = 0
    
    for segment_data in default_segments:
        try:
            # Check if segment already exists
            segments_ref = db.collection('resourceSegments')
            existing_query = segments_ref.where('name', '==', segment_data['name']).limit(1)
            existing_docs = list(existing_query.stream())
            
            if existing_docs:
                print(f"⚠️  Resource segment '{segment_data['name']}' already exists, skipping...")
                continue
            
            # Create the segment
            segment = create_resource_segment(db, **segment_data)
            print(f"✅ Created resource segment: {segment.name} (Level {segment.security_level})")
            created_count += 1
            
        except Exception as e:
            print(f"❌ Failed to create resource segment '{segment_data['name']}': {str(e)}")
    
    print(f"\n🎉 Created {created_count} new resource segments")
    return True

if __name__ == "__main__":
    success = create_default_resource_segments()
    if success:
        print("✅ Default resource segments created successfully!")
    else:
        print("❌ Failed to create default resource segments")
        sys.exit(1)