"""
Enhanced Policy Engine with Machine Learning Integration
Implements advanced policy evaluation using scikit-learn models for confidence prediction,
anomaly detection, and peer behavior analysis.
"""

import os
import pickle
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.cluster import KMeans
import joblib
import logging

from app.firebase_config import get_firestore_client
from app.services.device_fingerprint_service import DeviceFingerprintService
from app.services.enhanced_audit_service import EnhancedAuditService

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EnhancedPolicyEngine:
    """
    Enhanced Policy Engine with Machine Learning capabilities
    
    Features:
    - Confidence prediction using historical approval/denial data
    - Anomaly detection using unsupervised learning
    - Peer behavior analysis for contextual decision making
    - Temporal access modeling
    """
    
    def __init__(self):
        self.db = get_firestore_client()
        self.device_service = DeviceFingerprintService()
        self.audit_service = EnhancedAuditService()
        
        # ML Models
        self.confidence_model = None
        self.anomaly_detector = None
        self.peer_analyzer = None
        self.scaler = StandardScaler()
        self.label_encoders = {}
        
        # Model paths
        self.model_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'ml_models')
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Load existing models if available
        self._load_models()
        
        # Feature importance tracking
        self.feature_names = [
            'user_role_encoded', 'resource_type_encoded', 'time_of_day', 'day_of_week',
            'device_trust_score', 'historical_approval_rate', 'recent_access_count',
            'peer_approval_rate', 'request_frequency', 'urgency_level',
            'justification_length', 'ip_reputation_score', 'location_consistency'
        ]
    
    def evaluate_enhanced_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive request evaluation with ML integration
        
        Args:
            request_data (dict): Access request data containing:
                - userId: User ID
                - userRole: User role
                - requestedResource: Resource type
                - justification: Request justification
                - duration: Requested duration
                - urgency: Urgency level
                - deviceId: Device fingerprint ID
                - ipAddress: Client IP address
                - timestamp: Request timestamp
        
        Returns:
            dict: Enhanced evaluation result with ML predictions
        """
        try:
            user_id = request_data.get('userId')
            user_role = request_data.get('userRole')
            resource_type = request_data.get('requestedResource')
            
            # Extract features for ML models
            features = self._extract_features(request_data)
            
            # Get ML predictions
            ml_predictions = self.apply_machine_learning_models(features)
            
            # Analyze peer behavior
            peer_analysis = self.analyze_peer_behavior(user_id, resource_type)
            
            # Calculate contextual confidence
            contextual_confidence = self.calculate_contextual_confidence(
                request_data, ml_predictions, peer_analysis
            )
            
            # Make final decision
            decision_result = self._make_enhanced_decision(
                contextual_confidence, ml_predictions, peer_analysis
            )
            
            # Log evaluation for continuous learning
            self._log_evaluation(request_data, decision_result, ml_predictions)
            
            return {
                'decision': decision_result['decision'],
                'confidenceScore': contextual_confidence,
                'mlPredictions': ml_predictions,
                'peerAnalysis': peer_analysis,
                'message': decision_result['message'],
                'mfaRequired': decision_result.get('mfaRequired', False),
                'riskFactors': decision_result.get('riskFactors', []),
                'featureImportance': self._get_feature_importance(),
                'evaluationId': decision_result.get('evaluationId')
            }
            
        except Exception as e:
            logger.error(f"Error in enhanced request evaluation: {str(e)}")
            return {
                'decision': 'denied',
                'confidenceScore': 0,
                'message': f'Evaluation error: {str(e)}',
                'mlPredictions': {},
                'peerAnalysis': {},
                'riskFactors': ['system_error']
            }
    
    def apply_machine_learning_models(self, request_features: np.ndarray) -> Dict[str, Any]:
        """
        Apply trained ML models for decision support
        
        Args:
            request_features (np.ndarray): Extracted feature vector
        
        Returns:
            dict: ML model predictions and scores
        """
        try:
            predictions = {}
            
            # Confidence prediction
            if self.confidence_model is not None:
                # Scale features
                scaled_features = self.scaler.transform([request_features])
                
                # Predict confidence
                confidence_prediction = self.confidence_model.predict_proba(scaled_features)[0]
                predicted_class = self.confidence_model.predict(scaled_features)[0]
                
                predictions['ml_confidence'] = float(confidence_prediction[1] * 100)  # Probability of approval
                predictions['predicted_approval'] = bool(predicted_class)
                
                # Get feature importance
                if hasattr(self.confidence_model, 'feature_importances_'):
                    feature_importance = dict(zip(
                        self.feature_names, 
                        self.confidence_model.feature_importances_
                    ))
                    predictions['feature_importance'] = feature_importance
            
            # Anomaly detection
            if self.anomaly_detector is not None:
                scaled_features = self.scaler.transform([request_features])
                anomaly_score = self.anomaly_detector.decision_function(scaled_features)[0]
                is_anomaly = self.anomaly_detector.predict(scaled_features)[0] == -1
                
                predictions['anomaly_score'] = float(anomaly_score)
                predictions['is_anomaly'] = bool(is_anomaly)
                predictions['anomaly_risk'] = 'high' if is_anomaly else 'low'
            
            # Risk assessment based on ML outputs
            risk_level = self._calculate_ml_risk_level(predictions)
            predictions['overall_risk'] = risk_level
            
            return predictions
            
        except Exception as e:
            logger.error(f"Error applying ML models: {str(e)}")
            return {
                'ml_confidence': 50.0,
                'predicted_approval': False,
                'anomaly_score': 0.0,
                'is_anomaly': False,
                'overall_risk': 'medium',
                'error': str(e)
            }
    
    def analyze_peer_behavior(self, user_id: str, request_type: str) -> Dict[str, Any]:
        """
        Compare user behavior against similar users (peer analysis)
        
        Args:
            user_id (str): User ID
            request_type (str): Type of access request
        
        Returns:
            dict: Peer behavior analysis results
        """
        try:
            # Get user profile
            user_profile = self._get_user_profile(user_id)
            user_role = user_profile.get('role', 'unknown')
            user_department = user_profile.get('department', 'unknown')
            
            # Find peer users (same role and department)
            peer_users = self._find_peer_users(user_role, user_department, exclude_user=user_id)
            
            if not peer_users:
                return {
                    'peer_count': 0,
                    'peer_approval_rate': 0.5,
                    'user_vs_peer_score': 50.0,
                    'peer_risk_level': 'medium'
                }
            
            # Analyze peer access patterns
            peer_stats = self._analyze_peer_access_patterns(peer_users, request_type)
            
            # Compare user against peers
            user_stats = self._get_user_access_stats(user_id, request_type)
            comparison = self._compare_user_to_peers(user_stats, peer_stats)
            
            return {
                'peer_count': len(peer_users),
                'peer_approval_rate': peer_stats.get('approval_rate', 0.5),
                'peer_avg_requests_per_month': peer_stats.get('avg_requests_per_month', 0),
                'user_vs_peer_score': comparison.get('similarity_score', 50.0),
                'peer_risk_level': comparison.get('risk_level', 'medium'),
                'deviation_factors': comparison.get('deviation_factors', [])
            }
            
        except Exception as e:
            logger.error(f"Error in peer behavior analysis: {str(e)}")
            return {
                'peer_count': 0,
                'peer_approval_rate': 0.5,
                'user_vs_peer_score': 50.0,
                'peer_risk_level': 'medium',
                'error': str(e)
            }
    
    def calculate_contextual_confidence(
        self, 
        request_data: Dict[str, Any],
        ml_predictions: Dict[str, Any],
        peer_analysis: Dict[str, Any]
    ) -> float:
        """
        Calculate enhanced confidence score using ML and contextual analysis
        
        Args:
            request_data (dict): Original request data
            ml_predictions (dict): ML model predictions
            peer_analysis (dict): Peer behavior analysis
        
        Returns:
            float: Enhanced confidence score (0-100)
        """
        try:
            # Base weights for different factors
            weights = {
                'ml_confidence': 0.35,
                'peer_similarity': 0.25,
                'device_trust': 0.15,
                'temporal_context': 0.15,
                'anomaly_penalty': 0.10
            }
            
            # ML confidence component
            ml_confidence = ml_predictions.get('ml_confidence', 50.0)
            
            # Peer similarity component
            peer_score = peer_analysis.get('user_vs_peer_score', 50.0)
            
            # Device trust component
            device_trust = self._get_device_trust_score(request_data.get('deviceId'))
            
            # Temporal context component
            temporal_score = self._evaluate_temporal_context(request_data)
            
            # Anomaly penalty
            anomaly_penalty = 0
            if ml_predictions.get('is_anomaly', False):
                anomaly_penalty = 30  # Significant penalty for anomalous behavior
            
            # Calculate weighted score
            confidence_score = (
                ml_confidence * weights['ml_confidence'] +
                peer_score * weights['peer_similarity'] +
                device_trust * weights['device_trust'] +
                temporal_score * weights['temporal_context']
            ) - anomaly_penalty
            
            # Ensure score is within bounds
            confidence_score = max(0, min(100, confidence_score))
            
            return round(confidence_score, 2)
            
        except Exception as e:
            logger.error(f"Error calculating contextual confidence: {str(e)}")
            return 50.0  # Return neutral score on error
    
    def train_confidence_model(self, training_data: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Train confidence prediction model using historical approval/denial data
        
        Args:
            training_data (list, optional): Training data. If None, fetches from database
        
        Returns:
            dict: Training results and model performance metrics
        """
        try:
            # Get training data
            if training_data is None:
                training_data = self._fetch_historical_data()
            
            if len(training_data) < 50:
                logger.warning("Insufficient training data. Need at least 50 samples.")
                return {'success': False, 'message': 'Insufficient training data'}
            
            # Prepare features and labels
            X, y = self._prepare_training_data(training_data)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train Random Forest model
            self.confidence_model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                class_weight='balanced'
            )
            
            self.confidence_model.fit(X_train_scaled, y_train)
            
            # Evaluate model
            y_pred = self.confidence_model.predict(X_test_scaled)
            accuracy = accuracy_score(y_test, y_pred)
            
            # Save model
            self._save_models()
            
            logger.info(f"Confidence model trained with accuracy: {accuracy:.3f}")
            
            return {
                'success': True,
                'accuracy': accuracy,
                'training_samples': len(training_data),
                'feature_importance': dict(zip(
                    self.feature_names, 
                    self.confidence_model.feature_importances_
                ))
            }
            
        except Exception as e:
            logger.error(f"Error training confidence model: {str(e)}")
            return {'success': False, 'message': str(e)}
    
    def train_anomaly_detector(self, training_data: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Train anomaly detection model using unsupervised learning
        
        Args:
            training_data (list, optional): Training data. If None, fetches from database
        
        Returns:
            dict: Training results
        """
        try:
            # Get training data (only approved requests for normal behavior)
            if training_data is None:
                training_data = self._fetch_historical_data(approved_only=True)
            
            if len(training_data) < 30:
                logger.warning("Insufficient training data for anomaly detection.")
                return {'success': False, 'message': 'Insufficient training data'}
            
            # Prepare features (only approved requests to learn normal patterns)
            X, _ = self._prepare_training_data(training_data)
            X_scaled = self.scaler.fit_transform(X)
            
            # Train Isolation Forest
            self.anomaly_detector = IsolationForest(
                contamination=0.1,  # Expect 10% anomalies
                random_state=42,
                n_estimators=100
            )
            
            self.anomaly_detector.fit(X_scaled)
            
            # Save model
            self._save_models()
            
            logger.info(f"Anomaly detector trained with {len(training_data)} samples")
            
            return {
                'success': True,
                'training_samples': len(training_data),
                'contamination_rate': 0.1
            }
            
        except Exception as e:
            logger.error(f"Error training anomaly detector: {str(e)}")
            return {'success': False, 'message': str(e)}
    
    def update_ml_models(self, feedback_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Update ML models with new feedback data (continuous learning)
        
        Args:
            feedback_data (list): List of feedback records with actual outcomes
        
        Returns:
            dict: Update results
        """
        try:
            if not feedback_data:
                return {'success': False, 'message': 'No feedback data provided'}
            
            # Combine with existing training data
            existing_data = self._fetch_historical_data()
            combined_data = existing_data + feedback_data
            
            # Retrain models
            confidence_result = self.train_confidence_model(combined_data)
            anomaly_result = self.train_anomaly_detector(combined_data)
            
            logger.info(f"Models updated with {len(feedback_data)} new samples")
            
            return {
                'success': True,
                'feedback_samples': len(feedback_data),
                'confidence_model': confidence_result,
                'anomaly_model': anomaly_result
            }
            
        except Exception as e:
            logger.error(f"Error updating ML models: {str(e)}")
            return {'success': False, 'message': str(e)}
    
    def _extract_features(self, request_data: Dict[str, Any]) -> np.ndarray:
        """Extract feature vector from request data"""
        try:
            # Initialize feature vector
            features = np.zeros(len(self.feature_names))
            
            # Encode categorical features
            user_role = request_data.get('userRole', 'unknown')
            resource_type = request_data.get('requestedResource', 'unknown')
            
            # Use label encoders (create if not exists)
            if 'user_role' not in self.label_encoders:
                self.label_encoders['user_role'] = LabelEncoder()
                self.label_encoders['user_role'].fit(['student', 'faculty', 'admin', 'visitor', 'unknown'])
            
            if 'resource_type' not in self.label_encoders:
                self.label_encoders['resource_type'] = LabelEncoder()
                self.label_encoders['resource_type'].fit([
                    'academic_resources', 'administrative_systems', 'research_labs', 
                    'library_services', 'it_infrastructure', 'unknown'
                ])
            
            # Encode features
            try:
                features[0] = self.label_encoders['user_role'].transform([user_role])[0]
            except ValueError:
                features[0] = self.label_encoders['user_role'].transform(['unknown'])[0]
            
            try:
                features[1] = self.label_encoders['resource_type'].transform([resource_type])[0]
            except ValueError:
                features[1] = self.label_encoders['resource_type'].transform(['unknown'])[0]
            
            # Temporal features
            timestamp = request_data.get('timestamp', datetime.utcnow())
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            
            features[2] = timestamp.hour  # time_of_day
            features[3] = timestamp.weekday()  # day_of_week
            
            # Device trust score
            device_id = request_data.get('deviceId')
            features[4] = self._get_device_trust_score(device_id)
            
            # User historical data
            user_id = request_data.get('userId')
            user_stats = self._get_user_access_stats(user_id, resource_type)
            features[5] = user_stats.get('approval_rate', 0.5)
            features[6] = user_stats.get('recent_access_count', 0)
            
            # Peer comparison
            peer_analysis = self.analyze_peer_behavior(user_id, resource_type)
            features[7] = peer_analysis.get('peer_approval_rate', 0.5)
            
            # Request characteristics
            features[8] = user_stats.get('request_frequency', 1)  # requests per day
            
            urgency_map = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
            features[9] = urgency_map.get(request_data.get('urgency', 'medium'), 2)
            
            justification = request_data.get('justification', '')
            features[10] = len(justification) if justification else 0
            
            # Network features
            features[11] = self._get_ip_reputation_score(request_data.get('ipAddress'))
            features[12] = self._get_location_consistency_score(user_id, request_data.get('ipAddress'))
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features: {str(e)}")
            return np.zeros(len(self.feature_names))
    
    def _get_device_trust_score(self, device_id: Optional[str]) -> float:
        """Get device trust score from device fingerprint service"""
        if not device_id:
            return 0.0
        
        try:
            device_data = self.device_service.get_device_fingerprint(device_id)
            return device_data.get('trustScore', 50.0) if device_data else 0.0
        except:
            return 0.0
    
    def _get_user_profile(self, user_id: str) -> Dict[str, Any]:
        """Get user profile from database"""
        try:
            user_doc = self.db.collection('users').document(user_id).get()
            return user_doc.to_dict() if user_doc.exists else {}
        except:
            return {}
    
    def _find_peer_users(self, role: str, department: str, exclude_user: str) -> List[str]:
        """Find users with same role and department"""
        try:
            users_ref = self.db.collection('users')
            query = users_ref.where('role', '==', role).where('department', '==', department)
            
            peer_users = []
            for doc in query.stream():
                if doc.id != exclude_user:
                    peer_users.append(doc.id)
            
            return peer_users[:50]  # Limit to 50 peers for performance
        except:
            return []
    
    def _analyze_peer_access_patterns(self, peer_users: List[str], request_type: str) -> Dict[str, Any]:
        """Analyze access patterns of peer users"""
        try:
            if not peer_users:
                return {'approval_rate': 0.5, 'avg_requests_per_month': 0}
            
            # Get access requests for peer users
            requests_ref = self.db.collection('accessRequests')
            
            total_requests = 0
            approved_requests = 0
            monthly_requests = []
            
            for user_id in peer_users:
                query = requests_ref.where('userId', '==', user_id).limit(100)
                
                user_requests = 0
                for doc in query.stream():
                    request_data = doc.to_dict()
                    if request_data.get('requestedResource') == request_type:
                        total_requests += 1
                        user_requests += 1
                        
                        if request_data.get('decision') in ['granted', 'granted_with_mfa']:
                            approved_requests += 1
                
                monthly_requests.append(user_requests)
            
            approval_rate = approved_requests / total_requests if total_requests > 0 else 0.5
            avg_requests_per_month = np.mean(monthly_requests) if monthly_requests else 0
            
            return {
                'approval_rate': approval_rate,
                'avg_requests_per_month': avg_requests_per_month,
                'total_peer_requests': total_requests
            }
            
        except Exception as e:
            logger.error(f"Error analyzing peer access patterns: {str(e)}")
            return {'approval_rate': 0.5, 'avg_requests_per_month': 0}
    
    def _get_user_access_stats(self, user_id: str, resource_type: str) -> Dict[str, Any]:
        """Get user's access statistics"""
        try:
            requests_ref = self.db.collection('accessRequests')
            query = requests_ref.where('userId', '==', user_id).limit(100)
            
            total_requests = 0
            approved_requests = 0
            recent_requests = 0
            
            thirty_days_ago = datetime.utcnow() - timedelta(days=30)
            
            for doc in query.stream():
                request_data = doc.to_dict()
                
                if request_data.get('requestedResource') == resource_type:
                    total_requests += 1
                    
                    if request_data.get('decision') in ['granted', 'granted_with_mfa']:
                        approved_requests += 1
                    
                    # Check if recent
                    timestamp = request_data.get('timestamp')
                    if timestamp and isinstance(timestamp, str):
                        try:
                            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                            if timestamp > thirty_days_ago:
                                recent_requests += 1
                        except:
                            pass
            
            approval_rate = approved_requests / total_requests if total_requests > 0 else 0.5
            request_frequency = recent_requests / 30.0  # requests per day
            
            return {
                'approval_rate': approval_rate,
                'recent_access_count': recent_requests,
                'request_frequency': request_frequency,
                'total_requests': total_requests
            }
            
        except Exception as e:
            logger.error(f"Error getting user access stats: {str(e)}")
            return {'approval_rate': 0.5, 'recent_access_count': 0, 'request_frequency': 0}
    
    def _compare_user_to_peers(self, user_stats: Dict[str, Any], peer_stats: Dict[str, Any]) -> Dict[str, Any]:
        """Compare user behavior to peer behavior"""
        try:
            user_approval_rate = user_stats.get('approval_rate', 0.5)
            peer_approval_rate = peer_stats.get('approval_rate', 0.5)
            
            user_frequency = user_stats.get('request_frequency', 0)
            peer_frequency = peer_stats.get('avg_requests_per_month', 0) / 30.0
            
            # Calculate similarity score
            approval_diff = abs(user_approval_rate - peer_approval_rate)
            frequency_diff = abs(user_frequency - peer_frequency) / max(peer_frequency, 0.1)
            
            # Weighted similarity (approval rate is more important)
            similarity_score = 100 - (approval_diff * 60 + min(frequency_diff, 1.0) * 40)
            similarity_score = max(0, min(100, similarity_score))
            
            # Determine risk level
            deviation_factors = []
            risk_level = 'low'
            
            if approval_diff > 0.3:
                deviation_factors.append('approval_rate_deviation')
                risk_level = 'high'
            elif approval_diff > 0.15:
                risk_level = 'medium'
            
            if frequency_diff > 2.0:
                deviation_factors.append('request_frequency_deviation')
                risk_level = 'high'
            elif frequency_diff > 1.0 and risk_level == 'low':
                risk_level = 'medium'
            
            return {
                'similarity_score': similarity_score,
                'risk_level': risk_level,
                'deviation_factors': deviation_factors
            }
            
        except Exception as e:
            logger.error(f"Error comparing user to peers: {str(e)}")
            return {'similarity_score': 50.0, 'risk_level': 'medium', 'deviation_factors': []}
    
    def _evaluate_temporal_context(self, request_data: Dict[str, Any]) -> float:
        """Evaluate temporal context of the request"""
        try:
            timestamp = request_data.get('timestamp', datetime.utcnow())
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            
            score = 100  # Start with perfect score
            
            # Check business hours (8 AM - 6 PM)
            hour = timestamp.hour
            if hour < 8 or hour > 18:
                score -= 20  # Outside business hours
            
            # Check weekday vs weekend
            if timestamp.weekday() >= 5:  # Saturday or Sunday
                score -= 15  # Weekend access
            
            # Check for unusual timing patterns
            user_id = request_data.get('userId')
            if self._is_unusual_access_time(user_id, timestamp):
                score -= 25  # Unusual for this user
            
            return max(0, score)
            
        except Exception as e:
            logger.error(f"Error evaluating temporal context: {str(e)}")
            return 50.0
    
    def _is_unusual_access_time(self, user_id: str, timestamp: datetime) -> bool:
        """Check if access time is unusual for this user"""
        try:
            # Get user's historical access times
            requests_ref = self.db.collection('accessRequests')
            query = requests_ref.where('userId', '==', user_id).limit(50)
            
            access_hours = []
            for doc in query.stream():
                request_data = doc.to_dict()
                req_timestamp = request_data.get('timestamp')
                
                if req_timestamp and isinstance(req_timestamp, str):
                    try:
                        req_timestamp = datetime.fromisoformat(req_timestamp.replace('Z', '+00:00'))
                        access_hours.append(req_timestamp.hour)
                    except:
                        pass
            
            if len(access_hours) < 5:
                return False  # Not enough data
            
            # Check if current hour is within user's typical range
            current_hour = timestamp.hour
            typical_hours = set(access_hours)
            
            # If user has never accessed at this hour, it's unusual
            return current_hour not in typical_hours
            
        except:
            return False
    
    def _get_ip_reputation_score(self, ip_address: Optional[str]) -> float:
        """Get IP reputation score (simplified implementation)"""
        if not ip_address:
            return 50.0
        
        # In a real implementation, this would check against threat intelligence feeds
        # For now, return a neutral score
        return 75.0
    
    def _get_location_consistency_score(self, user_id: str, ip_address: Optional[str]) -> float:
        """Check location consistency for user"""
        if not ip_address:
            return 50.0
        
        try:
            # Get user's recent IP addresses
            requests_ref = self.db.collection('accessRequests')
            query = requests_ref.where('userId', '==', user_id).limit(20)
            
            recent_ips = set()
            for doc in query.stream():
                request_data = doc.to_dict()
                req_ip = request_data.get('ipAddress')
                if req_ip:
                    recent_ips.add(req_ip)
            
            if not recent_ips:
                return 50.0  # No history
            
            # Check if current IP is in recent set
            if ip_address in recent_ips:
                return 100.0  # Consistent location
            else:
                return 30.0  # New location
                
        except:
            return 50.0
    
    def _calculate_ml_risk_level(self, predictions: Dict[str, Any]) -> str:
        """Calculate overall risk level from ML predictions"""
        ml_confidence = predictions.get('ml_confidence', 50.0)
        is_anomaly = predictions.get('is_anomaly', False)
        
        if is_anomaly or ml_confidence < 30:
            return 'high'
        elif ml_confidence < 60:
            return 'medium'
        else:
            return 'low'
    
    def _make_enhanced_decision(
        self, 
        confidence_score: float,
        ml_predictions: Dict[str, Any],
        peer_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Make enhanced decision based on all factors"""
        try:
            # Decision thresholds
            AUTO_APPROVE_THRESHOLD = 85
            MFA_REQUIRED_THRESHOLD = 60
            
            risk_factors = []
            
            # Check ML predictions
            if ml_predictions.get('is_anomaly', False):
                risk_factors.append('anomalous_behavior_detected')
            
            if ml_predictions.get('overall_risk') == 'high':
                risk_factors.append('high_ml_risk_score')
            
            # Check peer analysis
            if peer_analysis.get('peer_risk_level') == 'high':
                risk_factors.append('deviates_from_peer_behavior')
            
            # Make decision
            if confidence_score >= AUTO_APPROVE_THRESHOLD and not risk_factors:
                decision = 'granted'
                message = 'Access granted based on high confidence and low risk'
                mfa_required = False
            
            elif confidence_score >= MFA_REQUIRED_THRESHOLD:
                decision = 'granted_with_mfa'
                message = 'Access granted with MFA verification required'
                mfa_required = True
            
            else:
                decision = 'denied'
                message = f'Access denied: confidence score {confidence_score} below threshold'
                mfa_required = False
            
            # Generate evaluation ID for tracking
            evaluation_id = f"eval_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{hash(str(confidence_score)) % 10000}"
            
            return {
                'decision': decision,
                'message': message,
                'mfaRequired': mfa_required,
                'riskFactors': risk_factors,
                'evaluationId': evaluation_id
            }
            
        except Exception as e:
            logger.error(f"Error making enhanced decision: {str(e)}")
            return {
                'decision': 'denied',
                'message': 'Error processing request',
                'mfaRequired': False,
                'riskFactors': ['system_error']
            }
    
    def _fetch_historical_data(self, approved_only: bool = False) -> List[Dict[str, Any]]:
        """Fetch historical access request data for training"""
        try:
            requests_ref = self.db.collection('accessRequests')
            query = requests_ref.limit(1000)  # Limit for performance
            
            historical_data = []
            for doc in query.stream():
                request_data = doc.to_dict()
                
                # Filter for approved only if requested
                if approved_only:
                    decision = request_data.get('decision')
                    if decision not in ['granted', 'granted_with_mfa']:
                        continue
                
                historical_data.append(request_data)
            
            return historical_data
            
        except Exception as e:
            logger.error(f"Error fetching historical data: {str(e)}")
            return []
    
    def _prepare_training_data(self, training_data: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training data for ML models"""
        try:
            X = []
            y = []
            
            for request in training_data:
                # Extract features
                features = self._extract_features(request)
                X.append(features)
                
                # Extract label (1 for approved, 0 for denied)
                decision = request.get('decision', 'denied')
                label = 1 if decision in ['granted', 'granted_with_mfa'] else 0
                y.append(label)
            
            return np.array(X), np.array(y)
            
        except Exception as e:
            logger.error(f"Error preparing training data: {str(e)}")
            return np.array([]), np.array([])
    
    def _save_models(self):
        """Save trained models to disk"""
        try:
            if self.confidence_model is not None:
                joblib.dump(self.confidence_model, os.path.join(self.model_dir, 'confidence_model.pkl'))
            
            if self.anomaly_detector is not None:
                joblib.dump(self.anomaly_detector, os.path.join(self.model_dir, 'anomaly_detector.pkl'))
            
            joblib.dump(self.scaler, os.path.join(self.model_dir, 'scaler.pkl'))
            joblib.dump(self.label_encoders, os.path.join(self.model_dir, 'label_encoders.pkl'))
            
            logger.info("Models saved successfully")
            
        except Exception as e:
            logger.error(f"Error saving models: {str(e)}")
    
    def _load_models(self):
        """Load trained models from disk"""
        try:
            confidence_path = os.path.join(self.model_dir, 'confidence_model.pkl')
            anomaly_path = os.path.join(self.model_dir, 'anomaly_detector.pkl')
            scaler_path = os.path.join(self.model_dir, 'scaler.pkl')
            encoders_path = os.path.join(self.model_dir, 'label_encoders.pkl')
            
            if os.path.exists(confidence_path):
                self.confidence_model = joblib.load(confidence_path)
                logger.info("Confidence model loaded")
            
            if os.path.exists(anomaly_path):
                self.anomaly_detector = joblib.load(anomaly_path)
                logger.info("Anomaly detector loaded")
            
            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
                logger.info("Scaler loaded")
            
            if os.path.exists(encoders_path):
                self.label_encoders = joblib.load(encoders_path)
                logger.info("Label encoders loaded")
                
        except Exception as e:
            logger.error(f"Error loading models: {str(e)}")
    
    def _get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance from trained model"""
        if self.confidence_model is not None and hasattr(self.confidence_model, 'feature_importances_'):
            return dict(zip(self.feature_names, self.confidence_model.feature_importances_))
        return {}
    
    def _log_evaluation(
        self, 
        request_data: Dict[str, Any], 
        decision_result: Dict[str, Any],
        ml_predictions: Dict[str, Any]
    ):
        """Log evaluation for continuous learning"""
        try:
            log_entry = {
                'evaluationId': decision_result.get('evaluationId'),
                'userId': request_data.get('userId'),
                'decision': decision_result.get('decision'),
                'confidenceScore': decision_result.get('confidenceScore'),
                'mlPredictions': ml_predictions,
                'timestamp': datetime.utcnow().isoformat(),
                'requestData': {
                    'userRole': request_data.get('userRole'),
                    'requestedResource': request_data.get('requestedResource'),
                    'urgency': request_data.get('urgency')
                }
            }
            
            # Store in audit logs
            self.audit_service.log_policy_evaluation(log_entry)
            
        except Exception as e:
            logger.error(f"Error logging evaluation: {str(e)}")


# Singleton instance
enhanced_policy_engine = EnhancedPolicyEngine()