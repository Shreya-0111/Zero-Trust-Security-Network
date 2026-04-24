# Behavioral Session Model Stub
# This is a placeholder since the behavioral session functionality is not being used

class BehavioralSession:
    """Placeholder for BehavioralSession model"""
    def __init__(self, **kwargs):
        self.keystroke_data = []
        self.mouse_data = []
        self.navigation_data = []
        pass
    
    @classmethod
    def get_by_user_id(cls, user_id, limit=100):
        """Stub method"""
        return []
    
    @classmethod
    def get_by_session_id(cls, session_id):
        """Stub method"""
        return None
    
    @classmethod
    def get_expired_sessions(cls, cutoff_time):
        """Stub method"""
        return []
    
    @classmethod
    def delete_old_data(cls, cutoff_date):
        """Stub method"""
        return 0