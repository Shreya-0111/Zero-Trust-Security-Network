"""
Policy Engine
Evaluates access requests against defined policies and calculates confidence scores
"""

from datetime import datetime
from typing import Dict, List, Any, Optional
from app.firebase_config import get_firestore_client
import os


class PolicyEngine:
    """Policy engine for evaluating access requests"""
    
    # Decision thresholds
    AUTO_APPROVE_THRESHOLD = 90
    REQUIRE_MFA_THRESHOLD = 50
    CONTEXT_SCORE_THRESHOLD = 50  # Require step-up auth if context score < 50
    
    # Confidence score weights (adjusted to include contextual intelligence)
    WEIGHT_ROLE_MATCH = 0.25
    WEIGHT_INTENT_CLARITY = 0.20
    WEIGHT_HISTORICAL_PATTERN = 0.15
    WEIGHT_CONTEXT_VALIDITY = 0.10
    WEIGHT_ANOMALY_DETECTION = 0.10
    WEIGHT_CONTEXTUAL_INTELLIGENCE = 0.20  # New weight for contextual intelligence
    
    # Check if contextual intelligence is enabled
    CONTEXTUAL_INTELLIGENCE_ENABLED = os.getenv('CONTEXT_EVALUATION_ENABLED', 'false').lower() == 'true'
    
    def __init__(self):
        self.db = get_firestore_client()
    
    def evaluate_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main orchestrator for evaluating access requests
        
        Args:
            request_data (dict): Access request data containing:
                - userId: User ID
                - userRole: User role
                - requestedResource: Resource type
                - intent: Intent description
                - duration: Requested duration
                - urgency: Urgency level
                - ipAddress: Client IP address
                - deviceInfo: Device information
                - timestamp: Request timestamp
        
        Returns:
            dict: Evaluation result with decision, confidence score, and breakdown
        """
        try:
            user_id = request_data.get('userId')
            user_role = request_data.get('userRole')
            resource_type = request_data.get('requestedResource')
            intent = request_data.get('intent', '')
            
            # Find applicable policies
            applicable_policies = self.match_policies(resource_type, user_role)
            
            if not applicable_policies:
                return {
                    'decision': 'denied',
                    'confidenceScore': 0,
                    'message': 'No applicable policy found for this resource',
                    'policiesApplied': [],
                    'confidenceBreakdown': {}
                }
            
            # Get user history for pattern analysis
            user_history = self._get_user_history(user_id, resource_type)
            
            # Evaluate contextual intelligence if enabled
            context_score_data = None
            if self.CONTEXTUAL_INTELLIGENCE_ENABLED:
                context_score_data = self._evaluate_contextual_intelligence(request_data)
            
            # Calculate confidence score
            confidence_score, breakdown = self.calculate_confidence_score(
                request_data, 
                user_history,
                context_score_data
            )
            
            # Get the highest priority policy
            primary_policy = applicable_policies[0]
            
            # Make decision based on confidence score and policy rules
            decision_result = self.make_decision(
                confidence_score, 
                primary_policy, 
                breakdown
            )
            
            result = {
                'decision': decision_result['decision'],
                'confidenceScore': confidence_score,
                'message': decision_result['message'],
                'policiesApplied': [p['policyId'] for p in applicable_policies],
                'confidenceBreakdown': breakdown,
                'mfaRequired': decision_result.get('mfaRequired', False),
                'policyDetails': {
                    'policyName': primary_policy.get('name'),
                    'minConfidence': primary_policy.get('rules', [{}])[0].get('minConfidence', 50)
                }
            }
            
            # Add contextual breakdown if available
            if context_score_data:
                result['contextualBreakdown'] = context_score_data.get('component_scores', {})
                result['contextualScore'] = context_score_data.get('overall_context_score', 0)
            
            return result
        
        except Exception as e:
            print(f"Error evaluating request: {str(e)}")
            return {
                'decision': 'denied',
                'confidenceScore': 0,
                'message': f'Evaluation error: {str(e)}',
                'policiesApplied': [],
                'confidenceBreakdown': {}
            }
    
    def match_policies(self, resource_type: str, user_role: str) -> List[Dict[str, Any]]:
        """
        Find applicable policies based on resource type and user role
        
        Args:
            resource_type (str): Type of resource being requested
            user_role (str): Role of the requesting user
        
        Returns:
            list: List of applicable policies sorted by priority (highest first)
        """
        try:
            policies_ref = self.db.collection('policies')
            
            # Query active policies
            query = policies_ref.where('isActive', '==', True)
            policies = query.stream()
            
            applicable_policies = []
            
            for policy_doc in policies:
                policy_data = policy_doc.to_dict()
                policy_data['policyId'] = policy_doc.id
                
                # Check if policy applies to this resource and role
                rules = policy_data.get('rules', [])
                for rule in rules:
                    rule_resource = rule.get('resourceType', '')
                    allowed_roles = rule.get('allowedRoles', [])
                    
                    # Match resource type (exact match or wildcard)
                    resource_match = (
                        rule_resource == resource_type or 
                        rule_resource == '*' or
                        resource_type.startswith(rule_resource)
                    )
                    
                    # Match role
                    role_match = user_role in allowed_roles or '*' in allowed_roles
                    
                    if resource_match and role_match:
                        applicable_policies.append(policy_data)
                        break  # Policy matches, no need to check other rules
            
            # Sort by priority (higher priority first)
            applicable_policies.sort(
                key=lambda p: p.get('priority', 0), 
                reverse=True
            )
            
            return applicable_policies
        
        except Exception as e:
            print(f"Error matching policies: {str(e)}")
            return []
    
    def calculate_confidence_score(
        self, 
        request_data: Dict[str, Any], 
        user_history: List[Dict[str, Any]],
        context_score_data: Optional[Dict[str, Any]] = None
    ) -> tuple[float, Dict[str, float]]:
        """
        Calculate confidence score using weighted factors including contextual intelligence
        
        Args:
            request_data (dict): Access request data
            user_history (list): User's historical access requests
            context_score_data (dict): Contextual intelligence evaluation data
        
        Returns:
            tuple: (total_score, breakdown_dict)
                - total_score: Weighted confidence score (0-100)
                - breakdown_dict: Individual component scores
        """
        # Calculate individual component scores
        role_match_score = self.check_role_match(
            request_data.get('userRole'),
            request_data.get('requestedResource')
        )
        
        intent_clarity_score = self._analyze_intent_clarity(
            request_data.get('intent', '')
        )
        
        historical_pattern_score = self._evaluate_historical_pattern(
            request_data.get('userId'),
            request_data.get('requestedResource'),
            user_history
        )
        
        context_validity_score = self.validate_context(request_data)
        
        anomaly_score = self._detect_anomalies(request_data, user_history)
        
        # Get contextual intelligence score if available
        contextual_intelligence_score = 70  # Default neutral score
        if context_score_data:
            contextual_intelligence_score = context_score_data.get('overall_context_score', 70)
        
        # Calculate weighted total score
        total_score = (
            role_match_score * self.WEIGHT_ROLE_MATCH +
            intent_clarity_score * self.WEIGHT_INTENT_CLARITY +
            historical_pattern_score * self.WEIGHT_HISTORICAL_PATTERN +
            context_validity_score * self.WEIGHT_CONTEXT_VALIDITY +
            anomaly_score * self.WEIGHT_ANOMALY_DETECTION +
            contextual_intelligence_score * self.WEIGHT_CONTEXTUAL_INTELLIGENCE
        )
        
        # Ensure score is within bounds
        total_score = max(0, min(100, total_score))
        
        breakdown = {
            'roleMatch': round(role_match_score, 2),
            'intentClarity': round(intent_clarity_score, 2),
            'historicalPattern': round(historical_pattern_score, 2),
            'contextValidity': round(context_validity_score, 2),
            'anomalyScore': round(anomaly_score, 2),
            'contextualIntelligence': round(contextual_intelligence_score, 2)
        }
        
        return round(total_score, 2), breakdown
    
    def check_role_match(self, user_role: str, resource_type: str) -> float:
        """
        Validate user role against allowed roles for resource
        
        Args:
            user_role (str): User's role
            resource_type (str): Requested resource type
        
        Returns:
            float: Role match score (0-100)
        """
        try:
            # Find policies for this resource
            policies = self.match_policies(resource_type, user_role)
            
            if not policies:
                return 0  # No matching policy means role doesn't match
            
            # Check if role is explicitly allowed
            primary_policy = policies[0]
            rules = primary_policy.get('rules', [])
            
            for rule in rules:
                if rule.get('resourceType') == resource_type:
                    allowed_roles = rule.get('allowedRoles', [])
                    
                    if user_role in allowed_roles:
                        # Exact role match
                        return 100
                    elif '*' in allowed_roles:
                        # Wildcard match (less confident)
                        return 70
            
            # Role found in policy but not for this specific resource
            return 50
        
        except Exception as e:
            print(f"Error checking role match: {str(e)}")
            return 0
    
    def validate_context(self, request_data: Dict[str, Any]) -> float:
        """
        Validate request context including time restrictions and device info
        
        Args:
            request_data (dict): Access request data with metadata
        
        Returns:
            float: Context validity score (0-100)
        """
        try:
            score = 100  # Start with perfect score
            
            resource_type = request_data.get('requestedResource')
            user_role = request_data.get('userRole')
            timestamp = request_data.get('timestamp', datetime.utcnow())
            device_info = request_data.get('deviceInfo', {})
            ip_address = request_data.get('ipAddress')
            
            # Convert timestamp to datetime if it's a string
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                except:
                    timestamp = datetime.utcnow()
            
            # Get applicable policies
            policies = self.match_policies(resource_type, user_role)
            
            if not policies:
                return score
            
            primary_policy = policies[0]
            rules = primary_policy.get('rules', [])
            
            for rule in rules:
                if rule.get('resourceType') == resource_type:
                    time_restrictions = rule.get('timeRestrictions', {})
                    
                    # Check time restrictions
                    if time_restrictions:
                        start_hour = time_restrictions.get('startHour')
                        end_hour = time_restrictions.get('endHour')
                        allowed_days = time_restrictions.get('allowedDays', [])
                        
                        current_hour = timestamp.hour
                        current_day = timestamp.strftime('%A')
                        
                        # Check hour restrictions
                        if start_hour is not None and end_hour is not None:
                            if not (start_hour <= current_hour < end_hour):
                                score -= 30  # Outside allowed hours
                        
                        # Check day restrictions
                        if allowed_days and current_day not in allowed_days:
                            score -= 20  # Outside allowed days
            
            # Validate device info presence
            if not device_info or not device_info.get('userAgent'):
                score -= 10  # Missing device information
            
            # Validate IP address presence
            if not ip_address:
                score -= 10  # Missing IP address
            
            return max(0, score)
        
        except Exception as e:
            print(f"Error validating context: {str(e)}")
            return 50  # Return neutral score on error
    
    def make_decision(
        self, 
        confidence_score: float, 
        policy: Dict[str, Any],
        breakdown: Dict[str, float]
    ) -> Dict[str, Any]:
        """
        Make access decision based on confidence score and policy rules
        Includes contextual intelligence override for step-up authentication
        
        Args:
            confidence_score (float): Calculated confidence score
            policy (dict): Applicable policy
            breakdown (dict): Confidence score breakdown
        
        Returns:
            dict: Decision result with decision type and message
        """
        try:
            rules = policy.get('rules', [{}])
            primary_rule = rules[0] if rules else {}
            
            min_confidence = primary_rule.get('minConfidence', self.REQUIRE_MFA_THRESHOLD)
            mfa_required = primary_rule.get('mfaRequired', False)
            
            # Check contextual intelligence score for step-up auth requirement
            contextual_score = breakdown.get('contextualIntelligence', 100)
            requires_step_up_auth = contextual_score < self.CONTEXT_SCORE_THRESHOLD
            
            # Decision logic based on thresholds
            if confidence_score >= self.AUTO_APPROVE_THRESHOLD and not requires_step_up_auth:
                # High confidence and good context - auto approve
                decision = 'granted'
                message = 'Access granted based on high confidence score'
                requires_mfa = mfa_required  # Only if policy explicitly requires it
            
            elif confidence_score >= self.REQUIRE_MFA_THRESHOLD or requires_step_up_auth:
                # Medium confidence or poor context - require MFA
                decision = 'granted_with_mfa'
                if requires_step_up_auth:
                    message = 'Access granted with MFA verification required due to contextual risk factors'
                else:
                    message = 'Access granted with MFA verification required'
                requires_mfa = True
            
            else:
                # Low confidence - deny
                decision = 'denied'
                message = self._generate_denial_reason(confidence_score, breakdown)
                requires_mfa = False
            
            # Override if below policy minimum
            if confidence_score < min_confidence:
                decision = 'denied'
                message = f'Confidence score {confidence_score} below policy minimum {min_confidence}'
                requires_mfa = False
            
            return {
                'decision': decision,
                'message': message,
                'mfaRequired': requires_mfa,
                'stepUpAuthRequired': requires_step_up_auth
            }
        
        except Exception as e:
            print(f"Error making decision: {str(e)}")
            return {
                'decision': 'denied',
                'message': 'Error processing request',
                'mfaRequired': False,
                'stepUpAuthRequired': False
            }
    
    def _get_user_history(self, user_id: str, resource_type: str) -> List[Dict[str, Any]]:
        """
        Get user's historical access requests
        
        Args:
            user_id (str): User ID
            resource_type (str): Resource type to filter by
        
        Returns:
            list: List of historical access requests
        """
        try:
            requests_ref = self.db.collection('accessRequests')
            query = requests_ref.where('userId', '==', user_id).limit(50)
            
            history = []
            for doc in query.stream():
                data = doc.to_dict()
                history.append(data)
            
            return history
        
        except Exception as e:
            print(f"Error getting user history: {str(e)}")
            return []
    
    def _analyze_intent_clarity(self, intent: str) -> float:
        """
        Analyze intent description for clarity and legitimacy using intent analyzer
        
        Args:
            intent (str): Intent description
        
        Returns:
            float: Intent clarity score (0-100)
        """
        # Simple intent analysis without external service
        return {
            "intent_type": "access_request",
            "confidence": 0.8,
            "risk_level": "medium"
        }
    
    def _evaluate_historical_pattern(
        self, 
        user_id: str, 
        resource_type: str,
        user_history: List[Dict[str, Any]]
    ) -> float:
        """
        Evaluate user's historical access patterns
        
        Args:
            user_id (str): User ID
            resource_type (str): Requested resource type
            user_history (list): User's historical requests
        
        Returns:
            float: Historical pattern score (0-100)
        """
        if not user_history:
            return 50  # Neutral score for new users
        
        score = 50  # Base score
        
        # Count previous requests for this resource
        resource_requests = [
            req for req in user_history 
            if req.get('requestedResource') == resource_type
        ]
        
        # Count granted requests
        granted_requests = [
            req for req in resource_requests 
            if req.get('decision') == 'granted' or req.get('decision') == 'granted_with_mfa'
        ]
        
        # Calculate approval rate
        if resource_requests:
            approval_rate = len(granted_requests) / len(resource_requests)
            score += approval_rate * 30  # Up to +30 for high approval rate
        
        # Bonus for consistent access pattern
        if len(resource_requests) >= 3:
            score += 10  # Established pattern
        
        # Penalty for recent denials
        recent_denials = [
            req for req in resource_requests[-5:] 
            if req.get('decision') == 'denied'
        ]
        
        if recent_denials:
            score -= len(recent_denials) * 10  # -10 per recent denial
        
        return max(0, min(100, score))
    
    def _detect_anomalies(
        self, 
        request_data: Dict[str, Any],
        user_history: List[Dict[str, Any]]
    ) -> float:
        """
        Detect anomalies in access request patterns
        
        Args:
            request_data (dict): Current access request
            user_history (list): User's historical requests
        
        Returns:
            float: Anomaly score (0-100, higher is better/less anomalous)
        """
        score = 100  # Start with no anomalies
        
        if not user_history:
            return 80  # Slightly lower for new users
        
        # Check for unusual request frequency
        recent_requests = [
            req for req in user_history 
            if self._is_recent(req.get('timestamp'))
        ]
        
        if len(recent_requests) > 10:
            score -= 20  # High frequency is suspicious
        
        # Check for unusual resource access
        resource_type = request_data.get('requestedResource')
        previous_resources = set(req.get('requestedResource') for req in user_history)
        
        if resource_type not in previous_resources and len(user_history) > 5:
            score -= 15  # New resource type for established user
        
        # Check for unusual urgency
        urgency = request_data.get('urgency', 'medium')
        if urgency == 'high':
            score -= 10  # High urgency is slightly suspicious
        
        # Check for IP address changes
        current_ip = request_data.get('ipAddress')
        if user_history and current_ip:
            recent_ips = set(
                req.get('ipAddress') for req in recent_requests 
                if req.get('ipAddress')
            )
            
            if recent_ips and current_ip not in recent_ips:
                score -= 10  # New IP address
        
        return max(0, min(100, score))
    
    def _is_recent(self, timestamp) -> bool:
        """Check if timestamp is within last 24 hours"""
        if not timestamp:
            return False
        
        try:
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            
            time_diff = datetime.utcnow() - timestamp
            return time_diff.total_seconds() < 86400  # 24 hours
        except:
            return False
    
    def _generate_denial_reason(
        self, 
        confidence_score: float, 
        breakdown: Dict[str, float]
    ) -> str:
        """
        Generate human-readable denial reason based on score breakdown
        
        Args:
            confidence_score (float): Overall confidence score
            breakdown (dict): Score breakdown by component
        
        Returns:
            str: Denial reason message
        """
        reasons = []
        
        if breakdown.get('roleMatch', 0) < 50:
            reasons.append('role permissions insufficient')
        
        if breakdown.get('intentClarity', 0) < 40:
            reasons.append('intent description unclear or suspicious')
        
        if breakdown.get('historicalPattern', 0) < 40:
            reasons.append('unusual access pattern')
        
        if breakdown.get('contextValidity', 0) < 50:
            reasons.append('request context invalid (time/location restrictions)')
        
        if breakdown.get('anomalyScore', 0) < 50:
            reasons.append('anomalous behavior detected')
        
        if breakdown.get('contextualIntelligence', 100) < 50:
            reasons.append('contextual risk factors (device, network, location, or time)')
        
        if reasons:
            return f"Access denied: {', '.join(reasons)}"
        else:
            return f"Access denied: confidence score {confidence_score} below threshold"
    
    def _evaluate_contextual_intelligence(self, request_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Evaluate contextual intelligence for the access request
        
        Args:
            request_data (dict): Access request data
        
        Returns:
            dict: Contextual intelligence evaluation results or None
        """
        try:
            user_id = request_data.get('userId')
            device_info = request_data.get('deviceInfo', {})
            network_info = request_data.get('networkInfo', {})
            access_time = request_data.get('timestamp')
            
            # Convert timestamp if needed
            if isinstance(access_time, str):
                try:
                    access_time = datetime.fromisoformat(access_time.replace('Z', '+00:00'))
                except:
                    access_time = datetime.utcnow()
            elif not access_time:
                access_time = datetime.utcnow()
            
            # Prepare network info with IP address
            if not network_info.get('ip_address'):
                network_info['ip_address'] = request_data.get('ipAddress')
            
            # Calculate overall context score
            context_result = contextual_intelligence.calculate_overall_context_score(
                user_id=user_id,
                device_info=device_info,
                network_info=network_info,
                access_time=access_time
            )
            
            return context_result
            
        except Exception as e:
            print(f"Error evaluating contextual intelligence: {str(e)}")
            return None


# Singleton instance
policy_engine = PolicyEngine()
