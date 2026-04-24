"""
Behavioral Biometrics Service
Handles feature extraction, model training, and risk scoring
"""

import numpy as np
import os
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import pickle
import json

from app.models.behavioral_session import BehavioralSession

# ML imports
try:
    from sklearn.preprocessing import StandardScaler
    from sklearn.ensemble import IsolationForest
    import torch
    import torch.nn as nn
    import torch.optim as optim
    SKLEARN_AVAILABLE = True
    TORCH_AVAILABLE = True
except ImportError as e:
    print(f"Warning: ML libraries not available: {e}")
    SKLEARN_AVAILABLE = False
    TORCH_AVAILABLE = False


class LSTMBehavioralModel(nn.Module):
    """LSTM model for behavioral biometric authentication"""
    
    def __init__(self, input_size=35, hidden_size_1=128, hidden_size_2=64, output_size=1, dropout=0.3):
        super(LSTMBehavioralModel, self).__init__()
        
        self.hidden_size_1 = hidden_size_1
        self.hidden_size_2 = hidden_size_2
        
        # First LSTM layer
        self.lstm1 = nn.LSTM(input_size, hidden_size_1, batch_first=True, dropout=dropout)
        
        # Second LSTM layer
        self.lstm2 = nn.LSTM(hidden_size_1, hidden_size_2, batch_first=True, dropout=dropout)
        
        # Fully connected layer
        self.fc = nn.Linear(hidden_size_2, output_size)
        
        # Sigmoid activation for binary classification
        self.sigmoid = nn.Sigmoid()
    
    def forward(self, x):
        # LSTM layers
        lstm1_out, _ = self.lstm1(x)
        lstm2_out, _ = self.lstm2(lstm1_out)
        
        # Take the last output
        last_output = lstm2_out[:, -1, :]
        
        # Fully connected layer
        out = self.fc(last_output)
        out = self.sigmoid(out)
        
        return out


class BehavioralBiometricsService:
    """Service for behavioral biometric analysis"""
    
    def __init__(self):
        self.models_path = os.getenv('ML_MODELS_PATH', './ml_models')
        self.training_days = int(os.getenv('BEHAVIORAL_MODEL_TRAINING_DAYS', '14'))
        self.scaler = StandardScaler() if SKLEARN_AVAILABLE else None
        
        # Ensure models directory exists
        os.makedirs(self.models_path, exist_ok=True)
    
    # ==================== Feature Extraction ====================
    
    def extract_keystroke_features(self, keystroke_data: List[Dict]) -> Dict[str, float]:
        """
        Extract 15 keystroke features from raw data
        
        Features:
        1. Average inter-key timing
        2. Std dev of inter-key timing
        3. Average hold duration
        4. Std dev of hold duration
        5. Typing speed (keys per minute)
        6. Error rate (backspace/delete ratio)
        7. Average time between key pairs
        8. Shift key usage frequency
        9. Ctrl key usage frequency
        10. Alt key usage frequency
        11. Average time for common digraphs
        12. Typing rhythm consistency
        13. Pause frequency (>1s gaps)
        14. Burst typing frequency (<100ms gaps)
        15. Key repetition rate
        """
        if not keystroke_data or len(keystroke_data) < 2:
            return self._get_default_keystroke_features()
        
        # Separate keydown and keyup events
        keydown_events = [k for k in keystroke_data if k.get('eventType') == 'keydown']
        keyup_events = [k for k in keystroke_data if k.get('eventType') == 'keyup']
        
        if len(keydown_events) < 2:
            return self._get_default_keystroke_features()
        
        # Calculate inter-key timings
        inter_key_times = []
        for i in range(1, len(keydown_events)):
            time_diff = keydown_events[i]['timestamp'] - keydown_events[i-1]['timestamp']
            inter_key_times.append(time_diff)
        
        # Calculate hold durations
        hold_durations = []
        for down_event in keydown_events:
            matching_up = next((u for u in keyup_events 
                              if u['code'] == down_event['code'] 
                              and u['timestamp'] > down_event['timestamp']), None)
            if matching_up:
                hold_durations.append(matching_up['timestamp'] - down_event['timestamp'])
        
        # Calculate features
        features = {
            'avg_inter_key_time': np.mean(inter_key_times) if inter_key_times else 0,
            'std_inter_key_time': np.std(inter_key_times) if inter_key_times else 0,
            'avg_hold_duration': np.mean(hold_durations) if hold_durations else 0,
            'std_hold_duration': np.std(hold_durations) if hold_durations else 0,
            'typing_speed': (len(keydown_events) / (keydown_events[-1]['timestamp'] - keydown_events[0]['timestamp'])) * 60000 if len(keydown_events) > 1 else 0,
            'error_rate': sum(1 for k in keydown_events if k.get('key') in ['Backspace', 'Delete']) / len(keydown_events) if keydown_events else 0,
            'avg_key_pair_time': np.mean(inter_key_times[:10]) if len(inter_key_times) >= 10 else np.mean(inter_key_times) if inter_key_times else 0,
            'shift_usage': sum(1 for k in keydown_events if k.get('shiftKey')) / len(keydown_events) if keydown_events else 0,
            'ctrl_usage': sum(1 for k in keydown_events if k.get('ctrlKey')) / len(keydown_events) if keydown_events else 0,
            'alt_usage': sum(1 for k in keydown_events if k.get('altKey')) / len(keydown_events) if keydown_events else 0,
            'common_digraph_time': np.mean([t for t in inter_key_times if 50 < t < 200]) if any(50 < t < 200 for t in inter_key_times) else 0,
            'rhythm_consistency': 1 / (np.std(inter_key_times) + 1) if inter_key_times else 0,
            'pause_frequency': sum(1 for t in inter_key_times if t > 1000) / len(inter_key_times) if inter_key_times else 0,
            'burst_frequency': sum(1 for t in inter_key_times if t < 100) / len(inter_key_times) if inter_key_times else 0,
            'key_repetition_rate': len([k for k in keydown_events if keydown_events.count(k) > 1]) / len(keydown_events) if keydown_events else 0
        }
        
        return features
    
    def extract_mouse_features(self, mouse_data: List[Dict]) -> Dict[str, float]:
        """
        Extract 12 mouse features from raw data
        
        Features:
        1. Average velocity
        2. Std dev of velocity
        3. Average acceleration
        4. Max velocity
        5. Average movement angle change
        6. Movement straightness
        7. Idle time ratio
        8. Average distance per movement
        9. Movement frequency
        10. Jitter (small movements)
        11. Smooth movement ratio
        12. Direction change frequency
        """
        if not mouse_data or len(mouse_data) < 3:
            return self._get_default_mouse_features()
        
        velocities = [m.get('velocity', 0) for m in mouse_data]
        
        # Calculate accelerations
        accelerations = []
        for i in range(1, len(velocities)):
            time_delta = mouse_data[i].get('timeDelta', 1)
            if time_delta > 0:
                accel = (velocities[i] - velocities[i-1]) / time_delta
                accelerations.append(abs(accel))
        
        # Calculate distances
        distances = []
        for i in range(1, len(mouse_data)):
            dx = mouse_data[i]['x'] - mouse_data[i-1]['x']
            dy = mouse_data[i]['y'] - mouse_data[i-1]['y']
            distance = np.sqrt(dx*dx + dy*dy)
            distances.append(distance)
        
        # Calculate angles
        angles = []
        for i in range(2, len(mouse_data)):
            dx1 = mouse_data[i-1]['x'] - mouse_data[i-2]['x']
            dy1 = mouse_data[i-1]['y'] - mouse_data[i-2]['y']
            dx2 = mouse_data[i]['x'] - mouse_data[i-1]['x']
            dy2 = mouse_data[i]['y'] - mouse_data[i-1]['y']
            
            angle1 = np.arctan2(dy1, dx1)
            angle2 = np.arctan2(dy2, dx2)
            angle_change = abs(angle2 - angle1)
            angles.append(angle_change)
        
        features = {
            'avg_velocity': np.mean(velocities) if velocities else 0,
            'std_velocity': np.std(velocities) if velocities else 0,
            'avg_acceleration': np.mean(accelerations) if accelerations else 0,
            'max_velocity': np.max(velocities) if velocities else 0,
            'avg_angle_change': np.mean(angles) if angles else 0,
            'movement_straightness': 1 / (np.mean(angles) + 1) if angles else 0,
            'idle_time_ratio': sum(1 for v in velocities if v < 0.1) / len(velocities) if velocities else 0,
            'avg_distance': np.mean(distances) if distances else 0,
            'movement_frequency': len(mouse_data) / ((mouse_data[-1]['timestamp'] - mouse_data[0]['timestamp']) / 1000) if len(mouse_data) > 1 else 0,
            'jitter': sum(1 for d in distances if d < 5) / len(distances) if distances else 0,
            'smooth_movement_ratio': sum(1 for a in accelerations if a < 0.5) / len(accelerations) if accelerations else 0,
            'direction_change_freq': sum(1 for a in angles if a > np.pi/4) / len(angles) if angles else 0
        }
        
        return features
    
    def extract_navigation_features(self, navigation_data: List[Dict], click_data: List[Dict], scroll_data: List[Dict]) -> Dict[str, float]:
        """
        Extract 8 navigation features
        
        Features:
        1. Page visit frequency
        2. Average dwell time per page
        3. Navigation speed
        4. Back/forward usage
        5. Scroll frequency
        6. Average scroll distance
        7. Click frequency
        8. Click-to-navigation ratio
        """
        if not navigation_data:
            return self._get_default_navigation_features()
        
        # Calculate dwell times
        dwell_times = []
        for i in range(1, len(navigation_data)):
            dwell_time = navigation_data[i]['timestamp'] - navigation_data[i-1]['timestamp']
            dwell_times.append(dwell_time)
        
        # Calculate scroll distances
        scroll_distances = []
        for i in range(1, len(scroll_data)):
            distance = abs(scroll_data[i]['scrollY'] - scroll_data[i-1]['scrollY'])
            scroll_distances.append(distance)
        
        total_time = navigation_data[-1]['timestamp'] - navigation_data[0]['timestamp'] if len(navigation_data) > 1 else 1
        
        features = {
            'page_visit_frequency': len(navigation_data) / (total_time / 60000) if total_time > 0 else 0,
            'avg_dwell_time': np.mean(dwell_times) if dwell_times else 0,
            'navigation_speed': len(navigation_data) / (total_time / 1000) if total_time > 0 else 0,
            'back_forward_usage': 0,  # Would need browser history API
            'scroll_frequency': len(scroll_data) / (total_time / 1000) if total_time > 0 else 0,
            'avg_scroll_distance': np.mean(scroll_distances) if scroll_distances else 0,
            'click_frequency': len(click_data) / (total_time / 1000) if total_time > 0 else 0,
            'click_to_nav_ratio': len(click_data) / len(navigation_data) if navigation_data else 0
        }
        
        return features
    
    def _get_default_keystroke_features(self) -> Dict[str, float]:
        """Return default keystroke features"""
        return {f'keystroke_feature_{i}': 0.0 for i in range(15)}
    
    def _get_default_mouse_features(self) -> Dict[str, float]:
        """Return default mouse features"""
        return {f'mouse_feature_{i}': 0.0 for i in range(12)}
    
    def _get_default_navigation_features(self) -> Dict[str, float]:
        """Return default navigation features"""
        return {f'navigation_feature_{i}': 0.0 for i in range(8)}
    
    def extract_all_features(self, session: BehavioralSession) -> np.ndarray:
        """Extract all 35 features from a behavioral session"""
        keystroke_features = self.extract_keystroke_features(session.keystroke_data)
        mouse_features = self.extract_mouse_features(session.mouse_data)
        navigation_features = self.extract_navigation_features(
            session.navigation_data,
            session.click_data,
            session.scroll_data
        )
        
        # Combine all features into a single array
        all_features = []
        all_features.extend(keystroke_features.values())
        all_features.extend(mouse_features.values())
        all_features.extend(navigation_features.values())
        
        return np.array(all_features, dtype=np.float32)
    
    # ==================== Model Training ====================
    
    def train_user_model(self, user_id: str) -> bool:
        """
        Train LSTM model for a specific user after collecting baseline data
        
        Returns:
            bool: True if training successful, False otherwise
        """
        if not TORCH_AVAILABLE or not SKLEARN_AVAILABLE:
            print("ML libraries not available")
            return False
        
        try:
            # Get user's behavioral sessions from the past training_days
            cutoff_date = datetime.utcnow() - timedelta(days=self.training_days)
            sessions = BehavioralSession.get_by_user_id(user_id, limit=100)
            
            # Filter sessions within training period
            training_sessions = [s for s in sessions if s.session_start >= cutoff_date]
            
            if len(training_sessions) < 5:
                print(f"Not enough training data for user {user_id}: {len(training_sessions)} sessions")
                return False
            
            # Extract features from all sessions
            feature_sequences = []
            for session in training_sessions:
                features = self.extract_all_features(session)
                feature_sequences.append(features)
            
            # Convert to numpy array
            X = np.array(feature_sequences)
            
            # Normalize features
            X_normalized = self.scaler.fit_transform(X)
            
            # Reshape for LSTM (samples, timesteps, features)
            X_reshaped = X_normalized.reshape(X_normalized.shape[0], 1, X_normalized.shape[1])
            
            # Convert to PyTorch tensors
            X_tensor = torch.FloatTensor(X_reshaped)
            y_tensor = torch.ones(X_tensor.shape[0], 1)  # All training data is legitimate user
            
            # Initialize model
            model = LSTMBehavioralModel(input_size=35)
            criterion = nn.BCELoss()
            optimizer = optim.Adam(model.parameters(), lr=0.001)
            
            # Training loop
            epochs = 50
            batch_size = min(32, len(X_tensor))
            
            model.train()
            for epoch in range(epochs):
                total_loss = 0
                for i in range(0, len(X_tensor), batch_size):
                    batch_X = X_tensor[i:i+batch_size]
                    batch_y = y_tensor[i:i+batch_size]
                    
                    # Forward pass
                    outputs = model(batch_X)
                    loss = criterion(outputs, batch_y)
                    
                    # Backward pass
                    optimizer.zero_grad()
                    loss.backward()
                    optimizer.step()
                    
                    total_loss += loss.item()
                
                if (epoch + 1) % 10 == 0:
                    print(f'Epoch [{epoch+1}/{epochs}], Loss: {total_loss/len(X_tensor):.4f}')
            
            # Save model and scaler
            model_path = os.path.join(self.models_path, f'behavioral_model_{user_id}.pth')
            scaler_path = os.path.join(self.models_path, f'behavioral_scaler_{user_id}.pkl')
            
            torch.save(model.state_dict(), model_path)
            with open(scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)
            
            # Update user profile
            profile = BehavioralProfile.get_by_user_id(user_id)
            if profile:
                profile.baseline_established = True
                profile.save()
            
            print(f"Model trained successfully for user {user_id}")
            return True
            
        except Exception as e:
            print(f"Error training model for user {user_id}: {e}")
            return False
    
    def load_user_model(self, user_id: str) -> Optional[Tuple]:
        """Load trained model and scaler for a user"""
        if not TORCH_AVAILABLE:
            return None
        
        try:
            model_path = os.path.join(self.models_path, f'behavioral_model_{user_id}.pth')
            scaler_path = os.path.join(self.models_path, f'behavioral_scaler_{user_id}.pkl')
            
            if not os.path.exists(model_path) or not os.path.exists(scaler_path):
                return None
            
            # Load model
            model = LSTMBehavioralModel(input_size=35)
            model.load_state_dict(torch.load(model_path))
            model.eval()
            
            # Load scaler
            with open(scaler_path, 'rb') as f:
                scaler = pickle.load(f)
            
            return model, scaler
            
        except Exception as e:
            print(f"Error loading model for user {user_id}: {e}")
            return None


    # ==================== Risk Scoring ====================
    
    def calculate_risk_score(self, user_id: str, session: BehavioralSession) -> Dict:
        """
        Calculate weighted risk score comparing current behavior to baseline
        
        Weights:
        - Keystroke: 35%
        - Mouse: 30%
        - Navigation: 20%
        - Time: 15%
        
        Returns:
            Dict with risk_score (0-100), risk_level, and component scores
        """
        try:
            # Check if user has a trained model
            model_data = self.load_user_model(user_id)
            
            if not model_data:
                # No baseline yet, return neutral score
                return {
                    'risk_score': 50,
                    'risk_level': 'unknown',
                    'baseline_available': False,
                    'message': 'Baseline not established yet'
                }
            
            model, scaler = model_data
            
            # Extract features from current session
            features = self.extract_all_features(session)
            
            # Normalize features
            features_normalized = scaler.transform(features.reshape(1, -1))
            
            # Reshape for LSTM
            features_reshaped = features_normalized.reshape(1, 1, -1)
            
            # Convert to tensor
            features_tensor = torch.FloatTensor(features_reshaped)
            
            # Get prediction (probability of being legitimate user)
            with torch.no_grad():
                prediction = model(features_tensor)
                legitimacy_score = prediction.item()
            
            # Convert to risk score (inverse of legitimacy)
            risk_score = (1 - legitimacy_score) * 100
            
            # Calculate component scores
            keystroke_features = self.extract_keystroke_features(session.keystroke_data)
            mouse_features = self.extract_mouse_features(session.mouse_data)
            navigation_features = self.extract_navigation_features(
                session.navigation_data,
                session.click_data,
                session.scroll_data
            )
            
            # Simple anomaly detection for components
            keystroke_risk = self._calculate_component_risk(keystroke_features)
            mouse_risk = self._calculate_component_risk(mouse_features)
            navigation_risk = self._calculate_component_risk(navigation_features)
            time_risk = self._calculate_time_risk(session)
            
            # Weighted risk score
            weighted_risk = (
                keystroke_risk * 0.35 +
                mouse_risk * 0.30 +
                navigation_risk * 0.20 +
                time_risk * 0.15
            )
            
            # Determine risk level
            if weighted_risk >= 80:
                risk_level = 'critical'
            elif weighted_risk >= 61:
                risk_level = 'high'
            elif weighted_risk >= 31:
                risk_level = 'medium'
            else:
                risk_level = 'low'
            
            return {
                'risk_score': round(weighted_risk, 2),
                'risk_level': risk_level,
                'baseline_available': True,
                'component_scores': {
                    'keystroke': round(keystroke_risk, 2),
                    'mouse': round(mouse_risk, 2),
                    'navigation': round(navigation_risk, 2),
                    'time': round(time_risk, 2)
                },
                'ml_prediction': round(risk_score, 2),
                'legitimacy_score': round(legitimacy_score * 100, 2)
            }
            
        except Exception as e:
            print(f"Error calculating risk score: {e}")
            return {
                'risk_score': 50,
                'risk_level': 'unknown',
                'baseline_available': False,
                'error': str(e)
            }
    
    def _calculate_component_risk(self, features: Dict[str, float]) -> float:
        """Calculate risk score for a component based on feature values"""
        # Simple heuristic: check if features are within normal ranges
        risk_indicators = 0
        total_features = len(features)
        
        for key, value in features.items():
            # Check for extreme values (simplified)
            if value == 0 or value > 1000:
                risk_indicators += 1
        
        return (risk_indicators / total_features) * 100 if total_features > 0 else 0
    
    def _calculate_time_risk(self, session: BehavioralSession) -> float:
        """Calculate time-based risk (unusual hours, session duration)"""
        now = datetime.utcnow()
        hour = now.hour
        
        # Higher risk for unusual hours (2 AM - 6 AM)
        if 2 <= hour < 6:
            time_risk = 60
        elif 22 <= hour or hour < 2:
            time_risk = 40
        else:
            time_risk = 10
        
        # Check session duration
        duration = session.get_session_duration()
        if duration > 14400:  # > 4 hours
            time_risk += 20
        elif duration < 60:  # < 1 minute
            time_risk += 30
        
        return min(time_risk, 100)
    
    def detect_anomaly(self, user_id: str, session: BehavioralSession) -> Dict:
        """
        Detect behavioral anomalies and deviations from baseline
        
        Returns:
            Dict with anomaly detection results
        """
        try:
            risk_data = self.calculate_risk_score(user_id, session)
            
            anomalies = []
            
            # Check component scores for anomalies
            if risk_data.get('baseline_available'):
                component_scores = risk_data.get('component_scores', {})
                
                if component_scores.get('keystroke', 0) > 70:
                    anomalies.append({
                        'type': 'keystroke_anomaly',
                        'severity': 'high',
                        'description': 'Keystroke patterns deviate significantly from baseline',
                        'score': component_scores['keystroke']
                    })
                
                if component_scores.get('mouse', 0) > 70:
                    anomalies.append({
                        'type': 'mouse_anomaly',
                        'severity': 'high',
                        'description': 'Mouse movement patterns deviate significantly from baseline',
                        'score': component_scores['mouse']
                    })
                
                if component_scores.get('navigation', 0) > 70:
                    anomalies.append({
                        'type': 'navigation_anomaly',
                        'severity': 'medium',
                        'description': 'Navigation patterns deviate from typical behavior',
                        'score': component_scores['navigation']
                    })
                
                if component_scores.get('time', 0) > 70:
                    anomalies.append({
                        'type': 'temporal_anomaly',
                        'severity': 'medium',
                        'description': 'Access at unusual time or unusual session duration',
                        'score': component_scores['time']
                    })
            
            return {
                'anomalies_detected': len(anomalies) > 0,
                'anomaly_count': len(anomalies),
                'anomalies': anomalies,
                'overall_risk': risk_data.get('risk_score', 50),
                'risk_level': risk_data.get('risk_level', 'unknown')
            }
            
        except Exception as e:
            print(f"Error detecting anomalies: {e}")
            return {
                'anomalies_detected': False,
                'anomaly_count': 0,
                'anomalies': [],
                'error': str(e)
            }


# Create BehavioralAnomaly model
class BehavioralAnomaly:
    """Model for storing detected behavioral anomalies"""
    
    def __init__(self, user_id, session_id, anomaly_type, severity, description, 
                 deviation_score, timestamp=None):
        self.user_id = user_id
        self.session_id = session_id
        self.anomaly_type = anomaly_type
        self.severity = severity
        self.description = description
        self.deviation_score = deviation_score
        self.timestamp = timestamp or datetime.utcnow()
    
    def to_dict(self):
        return {
            'user_id': self.user_id,
            'session_id': self.session_id,
            'anomaly_type': self.anomaly_type,
            'severity': self.severity,
            'description': self.description,
            'deviation_score': self.deviation_score,
            'timestamp': self.timestamp
        }


# Global service instance
behavioral_service = BehavioralBiometricsService()
