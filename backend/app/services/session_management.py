"""Intelligent Session Management"""
from datetime import datetime, timedelta
from app.firebase_config import db

class SessionManagement:
    def create_session_with_risk(self, user_id, risk_score):
        """Create session with risk-based duration"""
        if risk_score > 80:
            duration_minutes = 15
        elif risk_score > 60:
            duration_minutes = 30
        elif risk_score > 30:
            duration_minutes = 120
        else:
            duration_minutes = 480
        
        session = {
            'user_id': user_id,
            'risk_score': risk_score,
            'duration_minutes': duration_minutes,
            'created_at': datetime.utcnow(),
            'expires_at': datetime.utcnow() + timedelta(minutes=duration_minutes),
            'active': True
        }
        
        doc_ref = db.collection('active_sessions').document()
        session['session_id'] = doc_ref.id
        doc_ref.set(session)
        return session
    
    def monitor_session_risk(self, session_id):
        """Monitor and adjust session based on risk"""
        doc_ref = db.collection('active_sessions').document(session_id)
        session = doc_ref.get()
        
        if not session.exists:
            return None
        
        data = session.to_dict()
        # Reassess risk (would integrate with behavioral biometrics)
        new_risk = 50  # Placeholder
        
        if new_risk > 70:
            # Force re-authentication
            doc_ref.update({'requires_reauth': True, 'risk_score': new_risk})
        
        return data
    
    def detect_concurrent_sessions(self, user_id):
        """Detect suspicious concurrent sessions"""
        query = db.collection('active_sessions').where('user_id', '==', user_id).where('active', '==', True)
        sessions = list(query.stream())
        
        if len(sessions) > 1:
            # Check locations
            suspicious = []
            for i in range(len(sessions)):
                for j in range(i+1, len(sessions)):
                    # Would calculate distance between locations
                    suspicious.append({
                        'session1': sessions[i].id,
                        'session2': sessions[j].id,
                        'reason': 'Multiple active sessions detected'
                    })
            return suspicious
        return []

session_management = SessionManagement()
