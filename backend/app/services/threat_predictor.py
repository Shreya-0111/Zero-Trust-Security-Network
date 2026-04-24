"""
Threat Prediction Service
Analyzes patterns and predicts potential security threats using ML
"""

import numpy as np
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import pickle
import json

# ML imports
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    print("Warning: scikit-learn not available")
    SKLEARN_AVAILABLE = False

from app.firebase_config import db


class ThreatPredictor:
    """Service for threat prediction and pattern analysis"""
    
    def __init__(self):
        self.models_path = os.getenv('ML_MODELS_PATH', './ml_models')
        self.lookback_days = int(os.getenv('THREAT_PREDICTION_LOOKBACK_DAYS', '30'))
        self.confidence_threshold = float(os.getenv('THREAT_PREDICTION_CONFIDENCE_THRESHOLD', '0.70'))
        self.scaler = StandardScaler() if SKLEARN_AVAILABLE else None
        self.model = None
        
        # Ensure models directory exists
        os.makedirs(self.models_path, exist_ok=True)
    
    # ==================== Feature Extraction ====================
    
    def extract_threat_features(self, user_id: str, access_history: List[Dict]) -> np.ndarray:
        """
        Extract 7 threat indicator features from access history
        
        Features:
        1. Failed login attempts (last 24 hours)
        2. Unusual time access (2-6 AM)
        3. Scope deviation (requests outside normal scope)
        4. Frequency change (sudden increase in requests)
        5. Geographic anomaly (access from unusual location)
        6. Device changes (multiple devices in short time)
        7. Denial ratio (denied requests / total requests)
        """
        if not access_history:
            return np.zeros(7)
        
        now = datetime.utcnow()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)
        
        # Filter recent history
        recent_history = [h for h in access_history if h.get('timestamp', now) >= last_24h]
        week_history = [h for h in access_history if h.get('timestamp', now) >= last_7d]
        
        # Feature 1: Failed login attempts
        failed_attempts = sum(1 for h in recent_history 
                            if h.get('action') == 'login' and h.get('result') == 'failure')
        
        # Feature 2: Unusual time access
        unusual_time_count = sum(1 for h in recent_history 
                                if 2 <= h.get('timestamp', now).hour < 6)
        unusual_time_ratio = unusual_time_count / len(recent_history) if recent_history else 0
        
        # Feature 3: Scope deviation
        # Get user's typical resource types
        typical_resources = set()
        for h in week_history:
            if h.get('result') == 'success':
                typical_resources.add(h.get('resource_type', 'unknown'))
        
        scope_deviations = sum(1 for h in recent_history 
                              if h.get('resource_type') not in typical_resources)
        scope_deviation_ratio = scope_deviations / len(recent_history) if recent_history else 0
        
        # Feature 4: Frequency change
        current_freq = len(recent_history)
        avg_daily_freq = len(week_history) / 7 if week_history else 0
        frequency_change = (current_freq - avg_daily_freq) / (avg_daily_freq + 1)
        
        # Feature 5: Geographic anomaly
        # Get typical locations
        typical_locations = set()
        for h in week_history:
            if h.get('result') == 'success' and h.get('location'):
                typical_locations.add(h.get('location'))
        
        geo_anomalies = sum(1 for h in recent_history 
                           if h.get('location') and h.get('location') not in typical_locations)
        geo_anomaly_ratio = geo_anomalies / len(recent_history) if recent_history else 0
        
        # Feature 6: Device changes
        devices_24h = set(h.get('device_id') for h in recent_history if h.get('device_id'))
        device_change_count = len(devices_24h)
        
        # Feature 7: Denial ratio
        denied_count = sum(1 for h in recent_history if h.get('result') == 'denied')
        denial_ratio = denied_count / len(recent_history) if recent_history else 0
        
        features = np.array([
            failed_attempts,
            unusual_time_ratio,
            scope_deviation_ratio,
            frequency_change,
            geo_anomaly_ratio,
            device_change_count,
            denial_ratio
        ], dtype=np.float32)
        
        return features
    
    # ==================== Pattern Analysis ====================
    
    def analyze_patterns(self, user_id: str) -> Dict:
        """
        Analyze user access patterns for threat indicators
        
        Returns:
            Dict with pattern analysis results
        """
        try:
            # Get user's access history
            access_history = self._get_user_access_history(user_id, days=self.lookback_days)
            
            if not access_history:
                return {
                    'patterns_found': False,
                    'message': 'No access history available',
                    'indicators': []
                }
            
            # Extract features
            features = self.extract_threat_features(user_id, access_history)
            
            # Analyze each feature for threats
            indicators = []
            
            # Failed attempts
            if features[0] >= 5:
                indicators.append({
                    'type': 'excessive_failed_attempts',
                    'severity': 'high' if features[0] >= 10 else 'medium',
                    'value': int(features[0]),
                    'description': f'{int(features[0])} failed login attempts in last 24 hours'
                })
            
            # Unusual time access
            if features[1] > 0.3:
                indicators.append({
                    'type': 'unusual_time_access',
                    'severity': 'medium',
                    'value': round(features[1], 2),
                    'description': f'{round(features[1]*100, 1)}% of access during unusual hours (2-6 AM)'
                })
            
            # Scope deviation
            if features[2] > 0.4:
                indicators.append({
                    'type': 'scope_deviation',
                    'severity': 'high',
                    'value': round(features[2], 2),
                    'description': f'{round(features[2]*100, 1)}% of requests outside normal scope'
                })
            
            # Frequency change
            if features[3] > 2.0:
                indicators.append({
                    'type': 'frequency_spike',
                    'severity': 'medium',
                    'value': round(features[3], 2),
                    'description': f'Request frequency increased by {round(features[3]*100, 1)}%'
                })
            
            # Geographic anomaly
            if features[4] > 0.3:
                indicators.append({
                    'type': 'geographic_anomaly',
                    'severity': 'high',
                    'value': round(features[4], 2),
                    'description': f'{round(features[4]*100, 1)}% of access from unusual locations'
                })
            
            # Device changes
            if features[5] >= 3:
                indicators.append({
                    'type': 'multiple_devices',
                    'severity': 'medium',
                    'value': int(features[5]),
                    'description': f'Access from {int(features[5])} different devices in 24 hours'
                })
            
            # Denial ratio
            if features[6] > 0.5:
                indicators.append({
                    'type': 'high_denial_rate',
                    'severity': 'high',
                    'value': round(features[6], 2),
                    'description': f'{round(features[6]*100, 1)}% of requests denied'
                })
            
            return {
                'patterns_found': len(indicators) > 0,
                'indicator_count': len(indicators),
                'indicators': indicators,
                'features': features.tolist(),
                'analysis_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            print(f"Error analyzing patterns: {e}")
            return {
                'patterns_found': False,
                'error': str(e)
            }
    
    # ==================== Threat Prediction ====================
    
    def predict_threats(self, user_id: str = None) -> List[Dict]:
        """
        Generate threat predictions with confidence > threshold
        
        Args:
            user_id: Optional user ID to predict for specific user
            
        Returns:
            List of threat predictions
        """
        try:
            predictions = []
            
            if user_id:
                # Predict for specific user
                prediction = self._predict_user_threat(user_id)
                if prediction:
                    predictions.append(prediction)
            else:
                # Predict for all users with suspicious patterns
                users = self._get_users_with_suspicious_activity()
                for uid in users:
                    prediction = self._predict_user_threat(uid)
                    if prediction:
                        predictions.append(prediction)
            
            # Filter by confidence threshold
            high_confidence_predictions = [
                p for p in predictions 
                if p.get('confidence', 0) >= self.confidence_threshold
            ]
            
            return high_confidence_predictions
            
        except Exception as e:
            print(f"Error predicting threats: {e}")
            return []
    
    def _predict_user_threat(self, user_id: str) -> Optional[Dict]:
        """Predict threat for a specific user"""
        try:
            # Analyze patterns
            pattern_analysis = self.analyze_patterns(user_id)
            
            if not pattern_analysis.get('patterns_found'):
                return None
            
            indicators = pattern_analysis.get('indicators', [])
            
            # Calculate threat score based on indicators
            threat_score = 0
            severity_weights = {'low': 1, 'medium': 2, 'high': 3}
            
            for indicator in indicators:
                severity = indicator.get('severity', 'low')
                threat_score += severity_weights.get(severity, 1)
            
            # Normalize to 0-1 range
            max_possible_score = len(indicators) * 3
            confidence = min(threat_score / max_possible_score, 1.0) if max_possible_score > 0 else 0
            
            # Determine threat type
            threat_types = [ind.get('type') for ind in indicators]
            
            if 'excessive_failed_attempts' in threat_types:
                primary_threat = 'brute_force_attack'
            elif 'scope_deviation' in threat_types:
                primary_threat = 'privilege_escalation'
            elif 'geographic_anomaly' in threat_types:
                primary_threat = 'account_compromise'
            elif 'frequency_spike' in threat_types:
                primary_threat = 'automated_attack'
            else:
                primary_threat = 'suspicious_activity'
            
            # Generate preventive measures
            preventive_measures = self._generate_preventive_measures(threat_types)
            
            prediction = {
                'user_id': user_id,
                'threat_type': primary_threat,
                'confidence': round(confidence, 2),
                'threat_score': threat_score,
                'indicators': indicators,
                'preventive_measures': preventive_measures,
                'predicted_at': datetime.utcnow().isoformat(),
                'status': 'pending'
            }
            
            # Save prediction
            self._save_prediction(prediction)
            
            return prediction
            
        except Exception as e:
            print(f"Error predicting threat for user {user_id}: {e}")
            return None
    
    def _generate_preventive_measures(self, threat_types: List[str]) -> List[str]:
        """Generate preventive measure recommendations"""
        measures = []
        
        if 'excessive_failed_attempts' in threat_types:
            measures.append('Implement account lockout after failed attempts')
            measures.append('Enable CAPTCHA for login attempts')
            measures.append('Monitor IP addresses for brute force patterns')
        
        if 'scope_deviation' in threat_types:
            measures.append('Review and restrict user permissions')
            measures.append('Enable step-up authentication for sensitive resources')
            measures.append('Audit recent access requests')
        
        if 'geographic_anomaly' in threat_types:
            measures.append('Verify user identity through secondary channel')
            measures.append('Enable geographic access restrictions')
            measures.append('Review recent login locations')
        
        if 'frequency_spike' in threat_types:
            measures.append('Implement rate limiting')
            measures.append('Review automated access patterns')
            measures.append('Enable anomaly detection alerts')
        
        if 'high_denial_rate' in threat_types:
            measures.append('Investigate denied access attempts')
            measures.append('Review access policies')
            measures.append('Check for policy misconfigurations')
        
        return measures
    
    # ==================== Model Training ====================
    
    def train_threat_model(self) -> bool:
        """
        Train Random Forest classifier on historical threat data
        
        Returns:
            bool: True if training successful
        """
        if not SKLEARN_AVAILABLE:
            print("scikit-learn not available")
            return False
        
        try:
            # Get historical data
            training_data = self._get_training_data()
            
            if len(training_data) < 100:
                print(f"Not enough training data: {len(training_data)} samples")
                return False
            
            # Prepare features and labels
            X = np.array([d['features'] for d in training_data])
            y = np.array([d['label'] for d in training_data])
            
            # Normalize features
            X_normalized = self.scaler.fit_transform(X)
            
            # Train Random Forest
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42
            )
            
            self.model.fit(X_normalized, y)
            
            # Calculate accuracy
            accuracy = self.model.score(X_normalized, y)
            print(f"Model trained with accuracy: {accuracy:.2%}")
            
            # Save model
            model_path = os.path.join(self.models_path, 'threat_prediction_model.pkl')
            scaler_path = os.path.join(self.models_path, 'threat_prediction_scaler.pkl')
            
            with open(model_path, 'wb') as f:
                pickle.dump(self.model, f)
            
            with open(scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)
            
            print("Threat prediction model saved successfully")
            return True
            
        except Exception as e:
            print(f"Error training threat model: {e}")
            return False
    
    def load_threat_model(self) -> bool:
        """Load trained threat prediction model"""
        if not SKLEARN_AVAILABLE:
            return False
        
        try:
            model_path = os.path.join(self.models_path, 'threat_prediction_model.pkl')
            scaler_path = os.path.join(self.models_path, 'threat_prediction_scaler.pkl')
            
            if not os.path.exists(model_path) or not os.path.exists(scaler_path):
                return False
            
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            
            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
            
            return True
            
        except Exception as e:
            print(f"Error loading threat model: {e}")
            return False
    
    # ==================== Helper Methods ====================
    
    def _get_user_access_history(self, user_id: str, days: int = 30) -> List[Dict]:
        """Get user's access history from audit logs"""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Query audit logs
            query = db.collection('audit_logs')\
                     .where('user_id', '==', user_id)\
                     .where('timestamp', '>=', cutoff_date)\
                     .order_by('timestamp', direction='DESCENDING')\
                     .limit(1000)
            
            docs = query.stream()
            history = []
            
            for doc in docs:
                data = doc.to_dict()
                history.append(data)
            
            return history
            
        except Exception as e:
            print(f"Error getting access history: {e}")
            return []
    
    def _get_users_with_suspicious_activity(self) -> List[str]:
        """Get list of users with suspicious activity patterns"""
        try:
            # Query recent audit logs for suspicious patterns
            cutoff_date = datetime.utcnow() - timedelta(hours=24)
            
            query = db.collection('audit_logs')\
                     .where('timestamp', '>=', cutoff_date)\
                     .where('result', '==', 'failure')
            
            docs = query.stream()
            
            # Count failures per user
            user_failures = {}
            for doc in docs:
                data = doc.to_dict()
                user_id = data.get('user_id')
                if user_id:
                    user_failures[user_id] = user_failures.get(user_id, 0) + 1
            
            # Return users with >= 3 failures
            suspicious_users = [uid for uid, count in user_failures.items() if count >= 3]
            
            return suspicious_users
            
        except Exception as e:
            print(f"Error getting suspicious users: {e}")
            return []
    
    def _save_prediction(self, prediction: Dict):
        """Save threat prediction to Firestore"""
        try:
            doc_ref = db.collection('threat_predictions').document()
            prediction['prediction_id'] = doc_ref.id
            doc_ref.set(prediction)
            
        except Exception as e:
            print(f"Error saving prediction: {e}")
    
    def _get_training_data(self) -> List[Dict]:
        """Get historical data for model training"""
        # This would query historical threat data
        # For now, return empty list (would be populated with real data)
        return []
    
    # ==================== Threat Detection Algorithms ====================
    
    def detect_brute_force(self, user_id: str = None, ip_address: str = None) -> Optional[Dict]:
        """
        Detect brute force attacks
        Criteria: 10+ failed attempts from same IP in 1 hour
        
        Args:
            user_id: Optional user ID to check
            ip_address: Optional IP address to check
            
        Returns:
            Dict with detection results or None
        """
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=1)
            
            # Query failed login attempts
            query = db.collection('audit_logs')\
                     .where('action', '==', 'login')\
                     .where('result', '==', 'failure')\
                     .where('timestamp', '>=', cutoff_time)
            
            if user_id:
                query = query.where('user_id', '==', user_id)
            
            docs = query.stream()
            
            # Group by IP address
            ip_failures = {}
            user_failures = {}
            
            for doc in docs:
                data = doc.to_dict()
                ip = data.get('ip_address', 'unknown')
                uid = data.get('user_id', 'unknown')
                
                ip_failures[ip] = ip_failures.get(ip, 0) + 1
                user_failures[uid] = user_failures.get(uid, 0) + 1
            
            # Check for brute force patterns
            brute_force_detected = False
            details = []
            
            for ip, count in ip_failures.items():
                if count >= 10:
                    brute_force_detected = True
                    details.append({
                        'ip_address': ip,
                        'failed_attempts': count,
                        'timeframe': '1 hour'
                    })
            
            if brute_force_detected:
                return {
                    'detected': True,
                    'threat_type': 'brute_force_attack',
                    'severity': 'high',
                    'details': details,
                    'detected_at': datetime.utcnow().isoformat(),
                    'recommended_action': 'Block IP addresses and enable account lockout'
                }
            
            return None
            
        except Exception as e:
            print(f"Error detecting brute force: {e}")
            return None
    
    def detect_privilege_escalation(self, user_id: str) -> Optional[Dict]:
        """
        Detect privilege escalation attempts
        Criteria: Requests outside normal scope or role
        
        Args:
            user_id: User ID to check
            
        Returns:
            Dict with detection results or None
        """
        try:
            # Get user's typical access patterns
            history = self._get_user_access_history(user_id, days=7)
            
            if not history:
                return None
            
            # Get user's role and typical resources
            typical_resources = set()
            typical_actions = set()
            
            for h in history:
                if h.get('result') == 'success':
                    typical_resources.add(h.get('resource_type', 'unknown'))
                    typical_actions.add(h.get('action', 'unknown'))
            
            # Check recent requests for escalation attempts
            recent_history = history[:20]  # Last 20 requests
            
            escalation_attempts = []
            for h in recent_history:
                resource = h.get('resource_type')
                action = h.get('action')
                result = h.get('result')
                
                # Check if accessing unusual resources
                if resource not in typical_resources and result == 'denied':
                    escalation_attempts.append({
                        'resource_type': resource,
                        'action': action,
                        'timestamp': h.get('timestamp'),
                        'reason': 'Access to unusual resource type'
                    })
                
                # Check for admin actions by non-admin
                if action in ['create_user', 'delete_user', 'modify_policy'] and result == 'denied':
                    escalation_attempts.append({
                        'resource_type': resource,
                        'action': action,
                        'timestamp': h.get('timestamp'),
                        'reason': 'Attempted administrative action'
                    })
            
            if len(escalation_attempts) >= 3:
                return {
                    'detected': True,
                    'threat_type': 'privilege_escalation',
                    'severity': 'high',
                    'user_id': user_id,
                    'attempts': escalation_attempts,
                    'attempt_count': len(escalation_attempts),
                    'detected_at': datetime.utcnow().isoformat(),
                    'recommended_action': 'Review user permissions and investigate intent'
                }
            
            return None
            
        except Exception as e:
            print(f"Error detecting privilege escalation: {e}")
            return None
    
    def detect_coordinated_attack(self) -> Optional[Dict]:
        """
        Detect coordinated attacks across multiple users
        Criteria: Similar attack patterns from multiple accounts
        
        Returns:
            Dict with detection results or None
        """
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=1)
            
            # Get recent suspicious activity
            query = db.collection('audit_logs')\
                     .where('result', 'in', ['failure', 'denied'])\
                     .where('timestamp', '>=', cutoff_time)\
                     .limit(500)
            
            docs = query.stream()
            
            # Group by resource and action
            attack_patterns = {}
            
            for doc in docs:
                data = doc.to_dict()
                resource = data.get('resource_type', 'unknown')
                action = data.get('action', 'unknown')
                user_id = data.get('user_id', 'unknown')
                
                pattern_key = f"{resource}:{action}"
                
                if pattern_key not in attack_patterns:
                    attack_patterns[pattern_key] = {
                        'users': set(),
                        'count': 0,
                        'resource': resource,
                        'action': action
                    }
                
                attack_patterns[pattern_key]['users'].add(user_id)
                attack_patterns[pattern_key]['count'] += 1
            
            # Check for coordinated patterns
            coordinated_attacks = []
            
            for pattern_key, data in attack_patterns.items():
                # If 3+ users targeting same resource/action
                if len(data['users']) >= 3 and data['count'] >= 10:
                    coordinated_attacks.append({
                        'resource_type': data['resource'],
                        'action': data['action'],
                        'user_count': len(data['users']),
                        'attempt_count': data['count'],
                        'users': list(data['users'])
                    })
            
            if coordinated_attacks:
                return {
                    'detected': True,
                    'threat_type': 'coordinated_attack',
                    'severity': 'critical',
                    'patterns': coordinated_attacks,
                    'detected_at': datetime.utcnow().isoformat(),
                    'recommended_action': 'Investigate user accounts and implement network-level blocks'
                }
            
            return None
            
        except Exception as e:
            print(f"Error detecting coordinated attack: {e}")
            return None
    
    def run_all_detections(self, user_id: str = None) -> List[Dict]:
        """
        Run all threat detection algorithms
        
        Args:
            user_id: Optional user ID to focus detection
            
        Returns:
            List of detected threats
        """
        detections = []
        
        # Brute force detection
        brute_force = self.detect_brute_force(user_id=user_id)
        if brute_force:
            detections.append(brute_force)
        
        # Privilege escalation detection
        if user_id:
            priv_esc = self.detect_privilege_escalation(user_id)
            if priv_esc:
                detections.append(priv_esc)
        
        # Coordinated attack detection
        if not user_id:  # Only run for system-wide checks
            coordinated = self.detect_coordinated_attack()
            if coordinated:
                detections.append(coordinated)
        
        return detections
    
    # ==================== Prediction Tracking & Accuracy ====================
    
    def track_prediction_outcome(self, prediction_id: str, outcome: str, 
                                notes: str = None) -> bool:
        """
        Track the outcome of a threat prediction
        
        Args:
            prediction_id: ID of the prediction
            outcome: 'confirmed', 'false_positive', or 'prevented'
            notes: Optional notes about the outcome
            
        Returns:
            bool: True if successful
        """
        try:
            from app.models.threat_prediction import ThreatPrediction
            
            prediction = ThreatPrediction.get_by_id(prediction_id)
            
            if not prediction:
                print(f"Prediction {prediction_id} not found")
                return False
            
            # Update outcome
            prediction.update_outcome(outcome)
            
            # Log the outcome
            from app.services.audit_logger import log_audit_event
            log_audit_event(
                user_id=prediction.user_id,
                action='threat_prediction_outcome',
                resource_type='threat_prediction',
                resource_id=prediction_id,
                details={
                    'threat_type': prediction.threat_type,
                    'confidence': prediction.confidence,
                    'outcome': outcome,
                    'notes': notes
                }
            )
            
            print(f"Prediction {prediction_id} outcome tracked: {outcome}")
            return True
            
        except Exception as e:
            print(f"Error tracking prediction outcome: {e}")
            return False
    
    def calculate_prediction_accuracy(self, days: int = 30) -> Dict:
        """
        Calculate prediction accuracy over a time period
        
        Args:
            days: Number of days to analyze
            
        Returns:
            Dict with accuracy metrics
        """
        try:
            from app.models.threat_prediction import ThreatPrediction
            
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Get all predictions with outcomes
            query = db.collection('threat_predictions')\
                     .where('predicted_at', '>=', cutoff_date)\
                     .where('status', 'in', ['confirmed', 'false_positive', 'prevented'])
            
            docs = query.stream()
            
            total_predictions = 0
            confirmed = 0
            false_positives = 0
            prevented = 0
            
            confidence_sum = 0
            
            for doc in docs:
                data = doc.to_dict()
                total_predictions += 1
                confidence_sum += data.get('confidence', 0)
                
                status = data.get('status')
                if status == 'confirmed':
                    confirmed += 1
                elif status == 'false_positive':
                    false_positives += 1
                elif status == 'prevented':
                    prevented += 1
            
            if total_predictions == 0:
                return {
                    'accuracy': 0,
                    'total_predictions': 0,
                    'message': 'No predictions with outcomes in the specified period'
                }
            
            # Calculate accuracy (confirmed + prevented) / total
            accurate_predictions = confirmed + prevented
            accuracy = (accurate_predictions / total_predictions) * 100
            
            # Calculate average confidence
            avg_confidence = confidence_sum / total_predictions
            
            # Calculate false positive rate
            false_positive_rate = (false_positives / total_predictions) * 100
            
            return {
                'accuracy': round(accuracy, 2),
                'total_predictions': total_predictions,
                'confirmed': confirmed,
                'prevented': prevented,
                'false_positives': false_positives,
                'false_positive_rate': round(false_positive_rate, 2),
                'average_confidence': round(avg_confidence, 2),
                'period_days': days,
                'calculated_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            print(f"Error calculating prediction accuracy: {e}")
            return {
                'accuracy': 0,
                'error': str(e)
            }
    
    def generate_preventive_recommendations(self, prediction_id: str) -> List[str]:
        """
        Generate preventive measure recommendations for a prediction
        
        Args:
            prediction_id: ID of the prediction
            
        Returns:
            List of recommended preventive measures
        """
        try:
            from app.models.threat_prediction import ThreatPrediction
            
            prediction = ThreatPrediction.get_by_id(prediction_id)
            
            if not prediction:
                return []
            
            # Return stored preventive measures
            return prediction.preventive_measures
            
        except Exception as e:
            print(f"Error generating recommendations: {e}")
            return []
    
    def send_admin_alert(self, prediction: Dict) -> bool:
        """
        Send alert to administrators for high-confidence predictions
        
        Args:
            prediction: Prediction dictionary
            
        Returns:
            bool: True if alert sent successfully
        """
        try:
            from app.models.notification import create_notification
            from app.models.threat_prediction import ThreatPrediction
            
            confidence = prediction.get('confidence', 0)
            
            # Only alert for high confidence (>80%)
            if confidence < 0.80:
                return False
            
            # Get all admin users
            admin_query = db.collection('users').where('role', '==', 'admin')
            admin_docs = admin_query.stream()
            
            alert_sent = False
            
            for admin_doc in admin_docs:
                admin_data = admin_doc.to_dict()
                admin_id = admin_data.get('uid')
                
                if admin_id:
                    # Create notification
                    create_notification(
                        user_id=admin_id,
                        title=f'High Confidence Threat Detected',
                        message=f"Threat type: {prediction.get('threat_type')} | "
                               f"Confidence: {round(confidence * 100, 1)}% | "
                               f"Target: {prediction.get('user_id')}",
                        notification_type='security_alert',
                        priority='high',
                        metadata={
                            'prediction_id': prediction.get('prediction_id'),
                            'threat_type': prediction.get('threat_type'),
                            'confidence': confidence
                        }
                    )
                    alert_sent = True
            
            # Mark prediction as admin notified
            if alert_sent and prediction.get('prediction_id'):
                pred_obj = ThreatPrediction.get_by_id(prediction['prediction_id'])
                if pred_obj:
                    pred_obj.mark_admin_notified()
            
            return alert_sent
            
        except Exception as e:
            print(f"Error sending admin alert: {e}")
            return False
    
    def get_prediction_statistics(self) -> Dict:
        """
        Get overall prediction statistics
        
        Returns:
            Dict with prediction statistics
        """
        try:
            from app.models.threat_prediction import ThreatPrediction
            
            # Get pending predictions
            pending = ThreatPrediction.get_pending_predictions(limit=1000)
            
            # Get high confidence predictions
            high_confidence = ThreatPrediction.get_high_confidence_predictions(
                confidence_threshold=0.80,
                limit=1000
            )
            
            # Calculate accuracy for last 30 days
            accuracy_30d = self.calculate_prediction_accuracy(days=30)
            
            # Group by threat type
            threat_types = {}
            for pred in pending:
                threat_type = pred.threat_type
                threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
            
            return {
                'total_pending': len(pending),
                'high_confidence_count': len(high_confidence),
                'accuracy_30_days': accuracy_30d.get('accuracy', 0),
                'false_positive_rate': accuracy_30d.get('false_positive_rate', 0),
                'threat_type_distribution': threat_types,
                'generated_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            print(f"Error getting prediction statistics: {e}")
            return {}


# Global service instance
threat_predictor = ThreatPredictor()
