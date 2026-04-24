"""
Firestore Setup Utilities
Helper functions for configuring Firestore collections and indexes
"""

from datetime import datetime, timedelta
from app.firebase_config import get_firestore_client


def setup_audit_log_ttl():
    """
    Set up TTL (Time To Live) policy for audit logs
    
    Note: Firestore doesn't have built-in TTL like some other databases.
    This function provides a cleanup mechanism to delete logs older than 90 days.
    In production, this should be run as a scheduled Cloud Function or cron job.
    """
    db = get_firestore_client()
    
    if not db:
        print("Firestore client not initialized")
        return
    
    try:
        # Calculate cutoff date (90 days ago)
        cutoff_date = datetime.utcnow() - timedelta(days=90)
        
        # Query for old logs
        logs_ref = db.collection('auditLogs')
        old_logs_query = logs_ref.where('timestamp', '<', cutoff_date)
        
        # Delete old logs in batches
        batch = db.batch()
        deleted_count = 0
        
        for doc in old_logs_query.stream():
            batch.delete(doc.reference)
            deleted_count += 1
            
            # Firestore batch limit is 500 operations
            if deleted_count % 500 == 0:
                batch.commit()
                batch = db.batch()
        
        # Commit remaining deletions
        if deleted_count % 500 != 0:
            batch.commit()
        
        print(f"Deleted {deleted_count} audit logs older than 90 days")
        return deleted_count
    except Exception as e:
        print(f"Error setting up audit log TTL: {str(e)}")
        return 0


def create_audit_log_indexes():
    """
    Create composite indexes for audit logs
    
    Note: Firestore indexes must be created through the Firebase Console or
    firebase CLI. This function documents the required indexes.
    
    Required indexes for auditLogs collection:
    1. userId (Ascending) + timestamp (Descending)
    2. eventType (Ascending) + timestamp (Descending)
    3. severity (Ascending) + timestamp (Descending)
    4. result (Ascending) + timestamp (Descending)
    
    To create these indexes, run:
    firebase deploy --only firestore:indexes
    
    Or create them manually in the Firebase Console under Firestore > Indexes
    """
    print("""
    Required Firestore Indexes for Audit Logs:
    
    Collection: auditLogs
    
    1. Composite Index:
       - userId (Ascending)
       - timestamp (Descending)
    
    2. Composite Index:
       - eventType (Ascending)
       - timestamp (Descending)
    
    3. Composite Index:
       - severity (Ascending)
       - timestamp (Descending)
    
    4. Composite Index:
       - result (Ascending)
       - timestamp (Descending)
    
    To create these indexes:
    1. Go to Firebase Console > Firestore > Indexes
    2. Click "Add Index"
    3. Select "auditLogs" collection
    4. Add the fields as specified above
    
    Or use Firebase CLI:
    firebase deploy --only firestore:indexes
    """)


def setup_firestore_security_rules():
    """
    Document Firestore security rules for audit logs
    
    Note: Security rules must be deployed through Firebase CLI.
    This function documents the required rules.
    
    To deploy rules:
    firebase deploy --only firestore:rules
    """
    print("""
    Required Firestore Security Rules for Audit Logs:
    
    rules_version = '2';
    service cloud.firestore {
      match /databases/{database}/documents {
        
        // Audit Logs - Admin read-only
        match /auditLogs/{logId} {
          allow read: if request.auth != null && 
                         get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin';
          allow write: if false; // Only backend can write
        }
        
        // Users collection
        match /users/{userId} {
          allow read: if request.auth != null && 
                         (request.auth.uid == userId || 
                          get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin');
          allow write: if request.auth != null && 
                          get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin';
        }
        
        // Access Requests
        match /accessRequests/{requestId} {
          allow read: if request.auth != null && 
                         (resource.data.userId == request.auth.uid || 
                          get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin');
          allow write: if false; // Only backend can write
        }
        
        // Policies - Admin read/write, others read-only
        match /policies/{policyId} {
          allow read: if request.auth != null;
          allow write: if request.auth != null && 
                          get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin';
        }
      }
    }
    
    To deploy these rules:
    1. Save the rules to firestore.rules file in your project root
    2. Run: firebase deploy --only firestore:rules
    """)


if __name__ == "__main__":
    print("Firestore Setup Utilities")
    print("=" * 50)
    print("\n1. Creating audit log indexes documentation...")
    create_audit_log_indexes()
    print("\n2. Security rules documentation...")
    setup_firestore_security_rules()
    print("\n3. Running audit log TTL cleanup...")
    setup_audit_log_ttl()
