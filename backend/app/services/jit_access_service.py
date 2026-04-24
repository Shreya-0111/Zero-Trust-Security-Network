"""
Just-in-Time (JIT) Access Service
Handles JIT access requests with enhanced ML-based policy evaluation
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
import uuid
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os

from ..models.resource_segment import get_resource_segment_by_id
from ..models.user import get_user_by_id
from ..models.audit_log import create_audit_log
from ..firebase_config import get_firestore_client
from .device_fingerprint_service import device_fingerprint_service
from .behavioral_biometrics import behavioral_service

logger = logging.getLogger(__name__)


class JITAccessStatus(Enum):
    """JIT access request status enumeration"""
    PENDING = "pending"
    GRANTED = "granted"
    DENIED = "denied"
    EXPIRED = "expired"
    REVOKED = "revoked"
    PENDING_APPROVAL = "pending_approval"


class JITAccessRequest:
    """JIT access request model"""
    
    def __init__(self, user_id: str, resource_segment_id: str, justification: str, 
                 duration_hours: int, urgency: str = 'medium'):
        self.request_id = str(uuid.uuid4())
        self.user_id = user_id
        self.resource_segment_id = resource_segment_id
        self.justification = justification
        self.duration_hours = duration_hours
        self.urgency = urgency
        self.requested_at = datetime.utcnow()
        self.status = JITAccessStatus.PENDING
        self.risk_assessment = {}
        self.ml_evaluation = {}
        self.confidence_score = 0
        self.approval_recommendations = []
        self.granted_at = None
        self.expires_at = None
        self.granted_by = None
        self.denial_reason = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Firestore storage"""
        return {
            'requestId': self.request_id,
            'userId': self.user_id,
            'resourceSegmentId': self.resource_segment_id,
            'justification': self.justification,
            'durationHours': self.duration_hours,
            'urgency': self.urgency,
            'requestedAt': self.requested_at,
            'status': self.status.value,
            'riskAssessment': self.risk_assessment,
            'mlEvaluation': self.ml_evaluation,
            'confidenceScore': self.confidence_score,
            'approvalRecommendations': self.approval_recommendations,
            'grantedAt': self.granted_at,
            'expiresAt': self.expires_at,
            'grantedBy': self.granted_by,
            'denialReason': self.denial_reason
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'JITAccessRequest':
        """Create from dictionary"""
        request = cls(
            data['userId'],
            data['resourceSegmentId'],
            data['justification'],
            data['durationHours'],
            data.get('urgency', 'medium')
        )
        request.request_id = data.get('requestId', request.request_id)
        request.requested_at = data.get('requestedAt', datetime.utcnow())
        request.status = JITAccessStatus(data.get('status', 'pending'))
        request.risk_assessment = data.get('riskAssessment', {})
        request.ml_evaluation = data.get('mlEvaluation', {})
        request.confidence_score = data.get('confidenceScore', 0)
        request.approval_recommendations = data.get('approvalRecommendations', [])
        request.granted_at = data.get('grantedAt')
        request.expires_at = data.get('expiresAt')
        request.granted_by = data.get('grantedBy')
        request.denial_reason = data.get('denialReason')
        return request


class JITAccessService:
    """Service for managing JIT access requests with ML-enhanced evaluation"""
    
    # Risk scoring weights
    WEIGHT_DEVICE_FINGERPRINT = 0.25
    WEIGHT_BEHAVIORAL_PATTERNS = 0.20
    WEIGHT_PEER_ANALYSIS = 0.15
    WEIGHT_TEMPORAL_MODELING = 0.15
    WEIGHT_HISTORICAL_PATTERNS = 0.15
    WEIGHT_JUSTIFICATION_QUALITY = 0.10
    
    # Decision thresholds
    AUTO_APPROVE_THRESHOLD = 85
    REQUIRE_APPROVAL_THRESHOLD = 60
    AUTO_DENY_THRESHOLD = 30
    
    def __init__(self, db):
        """
        Initialize JIT Access Service
        
        Args:
            db: Firestore client
        """
        self.db = db
        self.ml_models = self._load_ml_models()
        self.scaler = StandardScaler()
        self._initialize_models()
    
    def _load_ml_models(self) -> Dict[str, Any]:
        """Load pre-trained ML models"""
        models = {}
        model_dir = os.path.join(os.path.dirname(__file__), '../../ml_models')
        
        try:
            # Load confidence prediction model
            confidence_model_path = os.path.join(model_dir, 'jit_confidence_model.pkl')
            if os.path.exists(confidence_model_path):
                models['confidence'] = joblib.load(confidence_model_path)
            else:
                # Create default model if not exists
                models['confidence'] = RandomForestClassifier(n_estimators=100, random_state=42)
            
            # Load anomaly detection model
            anomaly_model_path = os.path.join(model_dir, 'jit_anomaly_model.pkl')
            if os.path.exists(anomaly_model_path):
                models['anomaly'] = joblib.load(anomaly_model_path)
            else:
                # Create default model if not exists
                models['anomaly'] = IsolationForest(contamination=0.1, random_state=42)
            
            # Load scaler
            scaler_path = os.path.join(model_dir, 'jit_scaler.pkl')
            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
            
        except Exception as e:
            logger.warning(f"Could not load ML models: {str(e)}. Using default models.")
            models['confidence'] = RandomForestClassifier(n_estimators=100, random_state=42)
            models['anomaly'] = IsolationForest(contamination=0.1, random_state=42)
        
        return models
    
    def _initialize_models(self):
        """Initialize ML models with sample data if they haven't been trained"""
        try:
            # Check if models need training (simple check)
            if not hasattr(self.ml_models['confidence'], 'n_features_in_'):
                self._train_default_models()
        except Exception as e:
            logger.warning(f"Could not initialize ML models: {str(e)}")
    
    def _train_default_models(self):
        """Train models with default/sample data"""
        try:
            # Generate sample training data (in production, use real historical data)
            n_samples = 1000
            n_features = 15
            
            # Create synthetic training data
            X = np.random.rand(n_samples, n_features)
            
            # Create synthetic labels for confidence model (0: deny, 1: approve)
            y_confidence = (X.sum(axis=1) > n_features * 0.5).astype(int)
            
            # Fit the scaler
            self.scaler.fit(X)
            X_scaled = self.scaler.transform(X)
            
            # Train confidence model
            self.ml_models['confidence'].fit(X_scaled, y_confidence)
            
            # Train anomaly detection model
            self.ml_models['anomaly'].fit(X_scaled)
            
            logger.info("ML models initialized with default training data")
            
        except Exception as e:
            logger.error(f"Failed to train default models: {str(e)}")
    
    async def evaluate_jit_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate JIT access request using enhanced ML-based policy evaluation
        
        Args:
            request_data (dict): JIT access request data containing:
                - userId: User ID
                - resourceSegmentId: Resource segment ID
                - justification: Access justification
                - durationHours: Requested duration
                - urgency: Urgency level
                - deviceInfo: Device information
                - ipAddress: Client IP address
                - timestamp: Request timestamp
        
        Returns:
            dict: Evaluation result with decision, confidence, and risk assessment
        """
        try:
            user_id = request_data.get('userId')
            resource_segment_id = request_data.get('resourceSegmentId')
            
            # Get user and resource segment
            user = get_user_by_id(self.db, user_id)
            segment = get_resource_segment_by_id(self.db, resource_segment_id)
            
            if not user:
                return self._create_denial_result("User not found")
            
            if not segment:
                return self._create_denial_result("Resource segment not found")
            
            if not segment.is_active:
                return self._create_denial_result("Resource segment is not active")
            
            # Check if user has permission for this segment
            can_access, access_reason = segment.can_user_access(
                user.role, 
                self._get_user_security_clearance(user)
            )
            
            is_dev = os.getenv('FLASK_ENV', 'development') == 'development'
            if not can_access:
                if is_dev:
                    logger.warning(f"Development override for JIT: {access_reason}")
                else:
                    return self._create_denial_result(access_reason)
            
            # Perform comprehensive risk assessment
            risk_assessment = await self._calculate_risk_score(request_data, user, segment)
            
            # Apply ML evaluation
            ml_evaluation = await self._apply_ml_evaluation(request_data, risk_assessment, user, segment)
            
            # Generate confidence score and decision
            confidence_score = self._calculate_confidence_score(risk_assessment, ml_evaluation)
            decision_result = self._make_jit_decision(confidence_score, segment, risk_assessment)
            
            is_dev = os.getenv('FLASK_ENV', 'development') == 'development'
            if is_dev and decision_result.get('decision') == 'denied':
                logger.warning("Development override: converting denied to granted for testing")
                confidence_score = max(confidence_score, 85)
                decision_result = {
                    'decision': 'granted' if not segment.requires_dual_approval else 'pending_approval',
                    'message': 'Development override',
                    'requiresApproval': segment.requires_dual_approval,
                    'mfaRequired': False
                }
            
            # Generate approval recommendations
            recommendations = self._generate_approval_recommendations(
                risk_assessment, ml_evaluation, segment
            )
            
            result = {
                'decision': decision_result['decision'],
                'confidenceScore': confidence_score,
                'message': decision_result['message'],
                'riskAssessment': risk_assessment,
                'mlEvaluation': ml_evaluation,
                'approvalRecommendations': recommendations,
                'requiresApproval': decision_result.get('requiresApproval', False),
                'mfaRequired': decision_result.get('mfaRequired', False)
            }
            
            # Add expiration time if granted
            if decision_result['decision'] == 'granted':
                expires_at = datetime.utcnow() + timedelta(hours=request_data.get('durationHours', 1))
                result['expiresAt'] = expires_at.isoformat()
            
            return result
            
        except Exception as e:
            logger.error(f"Error evaluating JIT request: {str(e)}")
            return self._create_denial_result(f"Evaluation error: {str(e)}")
    
    async def _calculate_risk_score(self, request_data: Dict[str, Any], user, segment) -> Dict[str, Any]:
        """Calculate comprehensive risk score using multiple factors"""
        try:
            user_id = request_data.get('userId')
            device_info = request_data.get('deviceInfo', {})
            ip_address = request_data.get('ipAddress')
            
            # Device fingerprint validation
            device_score = await self._evaluate_device_fingerprint(user_id, device_info)
            
            # Behavioral pattern analysis
            behavioral_score = await self._evaluate_behavioral_patterns(user_id, request_data)
            
            # Peer analysis
            peer_score = await self._evaluate_peer_analysis(user, segment, request_data)
            
            # Temporal access modeling
            temporal_score = await self._evaluate_temporal_patterns(user_id, request_data)
            
            # Historical pattern analysis
            historical_score = await self._evaluate_historical_patterns(user_id, segment.segment_id)
            
            # Justification quality analysis
            justification_score = self._evaluate_justification_quality(request_data.get('justification', ''))
            
            # Calculate weighted risk score
            risk_score = (
                device_score * self.WEIGHT_DEVICE_FINGERPRINT +
                behavioral_score * self.WEIGHT_BEHAVIORAL_PATTERNS +
                peer_score * self.WEIGHT_PEER_ANALYSIS +
                temporal_score * self.WEIGHT_TEMPORAL_MODELING +
                historical_score * self.WEIGHT_HISTORICAL_PATTERNS +
                justification_score * self.WEIGHT_JUSTIFICATION_QUALITY
            )
            
            return {
                'riskScore': round(risk_score, 2),
                'deviceFingerprint': round(device_score, 2),
                'behavioralPatterns': round(behavioral_score, 2),
                'peerAnalysis': round(peer_score, 2),
                'temporalModeling': round(temporal_score, 2),
                'historicalPatterns': round(historical_score, 2),
                'justificationQuality': round(justification_score, 2),
                'riskFactors': self._identify_risk_factors(
                    device_score, behavioral_score, peer_score, 
                    temporal_score, historical_score, justification_score
                )
            }
            
        except Exception as e:
            logger.error(f"Error calculating risk score: {str(e)}")
            return {
                'riskScore': 50.0,  # Neutral score on error
                'error': str(e)
            }
    
    async def _evaluate_device_fingerprint(self, user_id: str, device_info: Dict[str, Any]) -> float:
        """Evaluate device fingerprint consistency"""
        try:
            if not device_info:
                return 30.0  # Low score for missing device info
            
            # Use device fingerprint service to validate
            validation_result = device_fingerprint_service.validate_device_fingerprint(
                user_id, device_info
            )
            
            if validation_result.get('is_valid', False):
                trust_score = validation_result.get('trust_score', 70)
                return min(100, trust_score + 10)  # Bonus for valid device
            else:
                similarity = validation_result.get('similarity', 0)
                return max(20, similarity * 0.8)  # Reduced score for unrecognized device
                
        except Exception as e:
            logger.error(f"Error evaluating device fingerprint: {str(e)}")
            return 50.0  # Neutral score on error
    
    async def _evaluate_behavioral_patterns(self, user_id: str, request_data: Dict[str, Any]) -> float:
        """Evaluate behavioral patterns using behavioral biometrics"""
        try:
            # Use behavioral biometrics service
            behavioral_result = behavioral_service.analyze_request_behavior(
                user_id, request_data
            )
            
            if behavioral_result.get('is_consistent', True):
                confidence = behavioral_result.get('confidence', 70)
                return min(100, confidence + 5)  # Bonus for consistent behavior
            else:
                anomaly_score = behavioral_result.get('anomaly_score', 50)
                return max(10, 100 - anomaly_score)  # Invert anomaly score
                
        except Exception as e:
            logger.error(f"Error evaluating behavioral patterns: {str(e)}")
            return 70.0  # Neutral-positive score on error
    
    async def _evaluate_peer_analysis(self, user, segment, request_data: Dict[str, Any]) -> float:
        """Evaluate request against peer behavior patterns"""
        try:
            # Get similar users (same role and department)
            peers_ref = self.db.collection('users')
            query = peers_ref.where('role', '==', user.role).where('isActive', '==', True)
            
            if user.department:
                query = query.where('department', '==', user.department)
            
            peer_requests = []
            for peer_doc in query.limit(50).stream():
                peer_data = peer_doc.to_dict()
                if peer_data['userId'] != user.user_id:
                    # Get recent JIT requests for this peer
                    peer_jit_requests = self._get_user_jit_history(peer_data['userId'], limit=10)
                    peer_requests.extend(peer_jit_requests)
            
            if not peer_requests:
                return 60.0  # Neutral score if no peer data
            
            # Analyze peer patterns
            peer_score = self._analyze_peer_patterns(request_data, peer_requests, segment)
            return peer_score
            
        except Exception as e:
            logger.error(f"Error evaluating peer analysis: {str(e)}")
            return 60.0  # Neutral score on error
    
    async def _evaluate_temporal_patterns(self, user_id: str, request_data: Dict[str, Any]) -> float:
        """Evaluate temporal access patterns"""
        try:
            timestamp = request_data.get('timestamp', datetime.utcnow())
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            
            hour = timestamp.hour
            day_of_week = timestamp.weekday()  # 0 = Monday, 6 = Sunday
            
            # Get user's historical access patterns
            user_history = self._get_user_jit_history(user_id, limit=100)
            
            if not user_history:
                # No history - evaluate based on business hours
                if 8 <= hour <= 18 and day_of_week < 5:  # Business hours, weekday
                    return 80.0
                elif 6 <= hour <= 22:  # Extended hours
                    return 60.0
                else:  # Off hours
                    return 30.0
            
            # Analyze user's typical access times
            user_hours = [req.get('timestamp', datetime.utcnow()).hour for req in user_history if req.get('timestamp')]
            user_days = [req.get('timestamp', datetime.utcnow()).weekday() for req in user_history if req.get('timestamp')]
            
            # Calculate similarity to user's typical patterns
            hour_score = self._calculate_temporal_similarity(hour, user_hours)
            day_score = self._calculate_temporal_similarity(day_of_week, user_days)
            
            return (hour_score + day_score) / 2
            
        except Exception as e:
            logger.error(f"Error evaluating temporal patterns: {str(e)}")
            return 60.0  # Neutral score on error
    
    async def _evaluate_historical_patterns(self, user_id: str, segment_id: str) -> float:
        """Evaluate user's historical access patterns for this segment"""
        try:
            # Get user's history for this specific segment
            segment_history = self._get_user_segment_history(user_id, segment_id)
            
            if not segment_history:
                return 50.0  # Neutral score for new access
            
            # Calculate approval rate
            total_requests = len(segment_history)
            approved_requests = len([req for req in segment_history if req.get('status') in ['granted', 'completed']])
            
            approval_rate = approved_requests / total_requests if total_requests > 0 else 0.5
            
            # Calculate recency bonus (more recent successful access = higher score)
            recent_success = any(
                req.get('status') in ['granted', 'completed'] and 
                self._is_recent(req.get('grantedAt'), days=30)
                for req in segment_history[-5:]  # Last 5 requests
            )
            
            base_score = approval_rate * 80  # Up to 80 points for approval rate
            recency_bonus = 15 if recent_success else 0
            frequency_bonus = min(10, total_requests * 2)  # Up to 10 points for experience
            
            return min(100, base_score + recency_bonus + frequency_bonus)
            
        except Exception as e:
            logger.error(f"Error evaluating historical patterns: {str(e)}")
            return 50.0  # Neutral score on error
    
    def _evaluate_justification_quality(self, justification: str) -> float:
        """Evaluate the quality of the access justification"""
        try:
            if not justification or not justification.strip():
                return 0.0
            
            justification = justification.strip()
            
            # Basic metrics
            length_score = min(40, len(justification) / 5)  # Up to 40 points for length
            word_count = len(justification.split())
            word_score = min(20, word_count * 2)  # Up to 20 points for word count
            
            # Quality indicators
            quality_score = 0
            
            # Check for specific business terms
            business_terms = ['project', 'deadline', 'client', 'meeting', 'urgent', 'required', 'necessary', 'access', 'work', 'task']
            term_matches = sum(1 for term in business_terms if term.lower() in justification.lower())
            quality_score += min(20, term_matches * 3)  # Up to 20 points for business terms
            
            # Check for detailed explanation (sentences)
            sentence_count = justification.count('.') + justification.count('!') + justification.count('?')
            quality_score += min(10, sentence_count * 2)  # Up to 10 points for sentences
            
            # Penalty for very short or generic justifications
            if len(justification) < 20:
                quality_score *= 0.5
            
            generic_phrases = ['need access', 'please approve', 'urgent request']
            if any(phrase in justification.lower() for phrase in generic_phrases):
                quality_score *= 0.8
            
            total_score = length_score + word_score + quality_score
            return min(100, total_score)
            
        except Exception as e:
            logger.error(f"Error evaluating justification quality: {str(e)}")
            return 50.0  # Neutral score on error
    
    async def _apply_ml_evaluation(self, request_data: Dict[str, Any], risk_assessment: Dict[str, Any], 
                                 user, segment) -> Dict[str, Any]:
        """Apply machine learning models for enhanced evaluation"""
        try:
            # Extract features for ML models
            features = self._extract_ml_features(request_data, risk_assessment, user, segment)
            
            # Scale features
            features_scaled = self.scaler.transform([features])
            
            # Apply confidence prediction model
            confidence_prediction = self.ml_models['confidence'].predict_proba(features_scaled)[0]
            ml_confidence = confidence_prediction[1] * 100  # Probability of approval
            
            # Apply anomaly detection
            anomaly_score = self.ml_models['anomaly'].decision_function(features_scaled)[0]
            is_anomaly = bool(self.ml_models['anomaly'].predict(features_scaled)[0] == -1)
            
            # Get feature importance if available
            feature_importance = {}
            if hasattr(self.ml_models['confidence'], 'feature_importances_'):
                feature_names = self._get_feature_names()
                importance_values = self.ml_models['confidence'].feature_importances_
                feature_importance = {name: float(val) for name, val in zip(feature_names, importance_values)}
            
            return {
                'mlConfidence': round(ml_confidence, 2),
                'anomalyScore': round(anomaly_score, 4),
                'isAnomaly': is_anomaly,
                'featureImportance': feature_importance,
                'modelVersion': '1.0'
            }
            
        except Exception as e:
            logger.error(f"Error applying ML evaluation: {str(e)}")
            return {
                'mlConfidence': 70.0,  # Neutral confidence on error
                'anomalyScore': 0.0,
                'isAnomaly': False,
                'error': str(e)
            }
    
    def _extract_ml_features(self, request_data: Dict[str, Any], risk_assessment: Dict[str, Any], 
                           user, segment) -> List[float]:
        """Extract features for ML models"""
        features = []
        
        # Risk assessment features
        features.append(risk_assessment.get('riskScore', 50) / 100)
        features.append(risk_assessment.get('deviceFingerprint', 50) / 100)
        features.append(risk_assessment.get('behavioralPatterns', 50) / 100)
        features.append(risk_assessment.get('peerAnalysis', 50) / 100)
        features.append(risk_assessment.get('temporalModeling', 50) / 100)
        features.append(risk_assessment.get('historicalPatterns', 50) / 100)
        features.append(risk_assessment.get('justificationQuality', 50) / 100)
        
        # User features
        role_encoding = {'student': 0.2, 'faculty': 0.6, 'admin': 1.0}.get(user.role, 0.4)
        features.append(role_encoding)
        
        # Segment features
        features.append(segment.security_level / 5)
        features.append(1.0 if segment.requires_jit else 0.0)
        features.append(1.0 if segment.requires_dual_approval else 0.0)
        
        # Request features
        features.append(request_data.get('durationHours', 1) / 24)  # Normalized duration
        urgency_encoding = {'low': 0.3, 'medium': 0.6, 'high': 1.0}.get(request_data.get('urgency'), 0.6)
        features.append(urgency_encoding)
        
        # Temporal features
        timestamp = request_data.get('timestamp', datetime.utcnow())
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        
        features.append(timestamp.hour / 24)  # Hour of day
        features.append(timestamp.weekday() / 7)  # Day of week
        
        return features
    
    def _get_feature_names(self) -> List[str]:
        """Get feature names for ML models"""
        return [
            'risk_score', 'device_fingerprint', 'behavioral_patterns', 'peer_analysis',
            'temporal_modeling', 'historical_patterns', 'justification_quality',
            'user_role', 'security_level', 'requires_jit', 'requires_dual_approval',
            'duration', 'urgency', 'hour_of_day', 'day_of_week'
        ]
    
    def _calculate_confidence_score(self, risk_assessment: Dict[str, Any], 
                                  ml_evaluation: Dict[str, Any]) -> float:
        """Calculate overall confidence score"""
        try:
            risk_score = risk_assessment.get('riskScore', 50)
            ml_confidence = ml_evaluation.get('mlConfidence', 70)
            is_anomaly = ml_evaluation.get('isAnomaly', False)
            
            # Combine risk score and ML confidence
            base_confidence = (risk_score * 0.6) + (ml_confidence * 0.4)
            
            # Apply anomaly penalty
            if is_anomaly:
                base_confidence *= 0.7  # 30% penalty for anomalous requests
            
            return round(min(100, max(0, base_confidence)), 2)
            
        except Exception as e:
            logger.error(f"Error calculating confidence score: {str(e)}")
            return 50.0  # Neutral score on error
    
    def _make_jit_decision(self, confidence_score: float, segment, 
                          risk_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Make JIT access decision based on confidence score and policies"""
        try:
            # Check if dual approval is required for high-security segments
            if segment.requires_dual_approval:
                return {
                    'decision': 'pending_approval',
                    'message': f'Dual approval required for {segment.name} (Security Level {segment.security_level})',
                    'requiresApproval': True,
                    'mfaRequired': True
                }
            
            # Decision based on confidence thresholds
            if confidence_score >= self.AUTO_APPROVE_THRESHOLD:
                return {
                    'decision': 'granted',
                    'message': f'Access granted with high confidence ({confidence_score}%)',
                    'requiresApproval': False,
                    'mfaRequired': segment.security_level >= 3
                }
            elif confidence_score >= self.REQUIRE_APPROVAL_THRESHOLD:
                return {
                    'decision': 'pending_approval',
                    'message': f'Manual approval required (confidence: {confidence_score}%)',
                    'requiresApproval': True,
                    'mfaRequired': True
                }
            else:
                # Determine denial reason
                risk_factors = risk_assessment.get('riskFactors', [])
                if risk_factors:
                    reason = f"Access denied due to: {', '.join(risk_factors[:3])}"
                else:
                    reason = f"Access denied: confidence score {confidence_score}% below threshold"
                
                return {
                    'decision': 'denied',
                    'message': reason,
                    'requiresApproval': False,
                    'mfaRequired': False
                }
                
        except Exception as e:
            logger.error(f"Error making JIT decision: {str(e)}")
            return {
                'decision': 'denied',
                'message': f'Decision error: {str(e)}',
                'requiresApproval': False,
                'mfaRequired': False
            }
    
    def _generate_approval_recommendations(self, risk_assessment: Dict[str, Any], 
                                         ml_evaluation: Dict[str, Any], segment) -> List[str]:
        """Generate recommendations for approval decision"""
        recommendations = []
        
        try:
            risk_score = risk_assessment.get('riskScore', 50)
            ml_confidence = ml_evaluation.get('mlConfidence', 70)
            
            # Risk-based recommendations
            if risk_score >= 80:
                recommendations.append("Low risk profile - recommend approval")
            elif risk_score >= 60:
                recommendations.append("Medium risk - consider approval with monitoring")
            else:
                recommendations.append("High risk - recommend additional verification")
            
            # ML-based recommendations
            if ml_confidence >= 80:
                recommendations.append("ML model indicates high approval probability")
            elif ml_confidence < 40:
                recommendations.append("ML model indicates low approval probability")
            
            # Anomaly detection
            if ml_evaluation.get('isAnomaly', False):
                recommendations.append("Anomalous request pattern detected - review carefully")
            
            # Segment-specific recommendations
            if segment.security_level >= 4:
                recommendations.append("High-security segment - ensure proper justification")
            
            # Risk factor specific recommendations
            risk_factors = risk_assessment.get('riskFactors', [])
            if 'unrecognized_device' in risk_factors:
                recommendations.append("Unrecognized device - verify user identity")
            if 'unusual_time' in risk_factors:
                recommendations.append("Unusual access time - confirm legitimate need")
            if 'poor_justification' in risk_factors:
                recommendations.append("Weak justification - request more details")
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {str(e)}")
            recommendations.append("Error generating recommendations - manual review required")
        
        return recommendations[:5]  # Limit to top 5 recommendations
    
    # Helper methods
    
    def _create_denial_result(self, reason: str) -> Dict[str, Any]:
        """Create a denial result"""
        return {
            'decision': 'denied',
            'confidenceScore': 0,
            'message': reason,
            'riskAssessment': {'riskScore': 0},
            'mlEvaluation': {'mlConfidence': 0},
            'approvalRecommendations': [f"Denied: {reason}"],
            'requiresApproval': False,
            'mfaRequired': False
        }
    
    def _get_user_security_clearance(self, user) -> int:
        """Get user's security clearance level based on role"""
        role_clearance = {
            'student': 1,
            'visitor': 1,
            'faculty': 3,
            'admin': 5
        }
        return role_clearance.get(user.role, 1)
    
    def _get_user_jit_history(self, user_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get user's JIT access request history"""
        try:
            requests_ref = self.db.collection('jitAccessRequests')
            query = requests_ref.where('userId', '==', user_id).limit(limit)
            
            history = []
            for doc in query.stream():
                data = doc.to_dict()
                history.append(data)
            
            return history
        except Exception as e:
            logger.error(f"Error getting JIT history: {str(e)}")
            return []
    
    def _get_user_segment_history(self, user_id: str, segment_id: str) -> List[Dict[str, Any]]:
        """Get user's history for specific segment"""
        try:
            requests_ref = self.db.collection('jitAccessRequests')
            query = requests_ref.where('userId', '==', user_id).where('resourceSegmentId', '==', segment_id)
            
            history = []
            for doc in query.stream():
                data = doc.to_dict()
                history.append(data)
            
            return history
        except Exception as e:
            logger.error(f"Error getting segment history: {str(e)}")
            return []
    
    def _analyze_peer_patterns(self, request_data: Dict[str, Any], peer_requests: List[Dict[str, Any]], 
                             segment) -> float:
        """Analyze request against peer behavior patterns"""
        try:
            if not peer_requests:
                return 60.0
            
            # Analyze similar requests
            similar_requests = [
                req for req in peer_requests 
                if req.get('resourceSegmentId') == segment.segment_id
            ]
            
            if not similar_requests:
                return 50.0  # No peer data for this segment
            
            # Calculate peer approval rate
            approved = len([req for req in similar_requests if req.get('status') == 'granted'])
            approval_rate = approved / len(similar_requests)
            
            # Analyze request characteristics similarity
            duration = request_data.get('durationHours', 1)
            urgency = request_data.get('urgency', 'medium')
            
            similar_duration = [
                req for req in similar_requests 
                if abs(req.get('durationHours', 1) - duration) <= 2
            ]
            
            similar_urgency = [
                req for req in similar_requests 
                if req.get('urgency') == urgency
            ]
            
            # Calculate similarity scores
            duration_similarity = len(similar_duration) / len(similar_requests) if similar_requests else 0
            urgency_similarity = len(similar_urgency) / len(similar_requests) if similar_requests else 0
            
            # Combine scores
            peer_score = (
                approval_rate * 50 +  # Base score from peer approval rate
                duration_similarity * 25 +  # Bonus for similar duration patterns
                urgency_similarity * 25  # Bonus for similar urgency patterns
            )
            
            return min(100, peer_score)
            
        except Exception as e:
            logger.error(f"Error analyzing peer patterns: {str(e)}")
            return 60.0
    
    def _calculate_temporal_similarity(self, current_value: int, historical_values: List[int]) -> float:
        """Calculate similarity to historical temporal patterns"""
        if not historical_values:
            return 50.0
        
        # Calculate how often the current value appears in history
        matches = historical_values.count(current_value)
        similarity = (matches / len(historical_values)) * 100
        
        # Also consider nearby values (±1 for hours, ±1 for days)
        nearby_matches = sum(1 for val in historical_values if abs(val - current_value) <= 1)
        nearby_similarity = (nearby_matches / len(historical_values)) * 80  # Slightly lower weight
        
        return max(similarity, nearby_similarity)
    
    def _identify_risk_factors(self, device_score: float, behavioral_score: float, 
                             peer_score: float, temporal_score: float, 
                             historical_score: float, justification_score: float) -> List[str]:
        """Identify specific risk factors based on component scores"""
        risk_factors = []
        
        if device_score < 50:
            risk_factors.append('unrecognized_device')
        if behavioral_score < 40:
            risk_factors.append('unusual_behavior')
        if peer_score < 40:
            risk_factors.append('atypical_request')
        if temporal_score < 30:
            risk_factors.append('unusual_time')
        if historical_score < 30:
            risk_factors.append('poor_history')
        if justification_score < 40:
            risk_factors.append('poor_justification')
        
        return risk_factors
    
    def _is_recent(self, timestamp, days: int = 30) -> bool:
        """Check if timestamp is within specified days"""
        if not timestamp:
            return False
        
        try:
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            
            time_diff = datetime.utcnow() - timestamp
            return time_diff.total_seconds() < (days * 86400)
        except:
            return False


# Global service instance
jit_access_service = None


def get_jit_access_service(db):
    """
    Get or create the global JIT access service instance
    
    Args:
        db: Firestore client
        
    Returns:
        JITAccessService: Service instance
    """
    global jit_access_service
    if jit_access_service is None:
        jit_access_service = JITAccessService(db)
    return jit_access_service
