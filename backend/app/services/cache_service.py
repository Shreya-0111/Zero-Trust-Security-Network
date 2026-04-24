"""
Cache Service for AI Innovations
Provides caching for ML models, contextual scores, and threat predictions
Uses Redis with appropriate TTLs for each data type
"""

import json
import pickle
import base64
from datetime import datetime, timedelta
from redis_config import (
    get_redis_client,
    is_redis_available,
    cache_set,
    cache_get,
    cache_delete,
    cache_exists,
    cache_context_score,
    get_cached_context_score,
    cache_model,
    get_cached_model,
    session_set,
    session_get,
    session_delete,
    session_update_ttl
)


class CacheService:
    """
    Centralized cache service for AI innovations
    Handles caching with appropriate TTLs for different data types
    """
    
    # TTL constants (in seconds)
    TTL_BEHAVIORAL_MODEL = 3600  # 1 hour
    TTL_CONTEXT_SCORE = 300  # 5 minutes
    TTL_THREAT_PREDICTION = 1800  # 30 minutes
    TTL_SESSION_DATA = 3600  # 1 hour
    TTL_DEVICE_PROFILE = 7200  # 2 hours
    TTL_POLICY_PERFORMANCE = 1800  # 30 minutes
    
    @staticmethod
    def is_available():
        """Check if Redis is available"""
        return is_redis_available()
    
    # Behavioral Biometrics Caching
    
    @staticmethod
    def cache_behavioral_model(user_id, model_data, ttl=None):
        """
        Cache user's behavioral biometrics model
        
        Args:
            user_id: User identifier
            model_data: Model data (weights, parameters, baseline)
            ttl: Time to live (default: 1 hour)
            
        Returns:
            bool: Success status
        """
        if ttl is None:
            ttl = CacheService.TTL_BEHAVIORAL_MODEL
        
        key = f"behavioral_model:{user_id}"
        return cache_set(key, model_data, ttl)
    
    @staticmethod
    def get_behavioral_model(user_id):
        """
        Retrieve cached behavioral model
        
        Args:
            user_id: User identifier
            
        Returns:
            Model data or None
        """
        key = f"behavioral_model:{user_id}"
        return cache_get(key)
    
    @staticmethod
    def cache_behavioral_baseline(user_id, baseline_data, ttl=None):
        """
        Cache user's behavioral baseline profile
        
        Args:
            user_id: User identifier
            baseline_data: Baseline behavioral data
            ttl: Time to live (default: 1 hour)
            
        Returns:
            bool: Success status
        """
        # Behavioral profile caching disabled - service removed
        return False
    
    @staticmethod
    def get_behavioral_baseline(user_id):
        """
        Retrieve cached behavioral baseline
        
        Args:
            user_id: User identifier
            
        Returns:
            Baseline data or None
        """
        # Behavioral profile caching disabled - service removed
        return None
    
    # Contextual Intelligence Caching
    
    @staticmethod
    def cache_contextual_score(request_id, context_data, ttl=None):
        """
        Cache contextual intelligence score
        
        Args:
            request_id: Request identifier
            context_data: Context evaluation data
            ttl: Time to live (default: 5 minutes)
            
        Returns:
            bool: Success status
        """
        if ttl is None:
            ttl = CacheService.TTL_CONTEXT_SCORE
        
        return cache_context_score(request_id, context_data, ttl)
    
    @staticmethod
    def get_contextual_score(request_id):
        """
        Retrieve cached contextual score
        
        Args:
            request_id: Request identifier
            
        Returns:
            Context data or None
        """
        return get_cached_context_score(request_id)
    
    @staticmethod
    def cache_device_profile(device_id, profile_data, ttl=None):
        """
        Cache device profile and compliance data
        
        Args:
            device_id: Device identifier
            profile_data: Device profile data
            ttl: Time to live (default: 2 hours)
            
        Returns:
            bool: Success status
        """
        if ttl is None:
            ttl = CacheService.TTL_DEVICE_PROFILE
        
        key = f"device_profile:{device_id}"
        return cache_set(key, profile_data, ttl)
    
    @staticmethod
    def get_device_profile(device_id):
        """
        Retrieve cached device profile
        
        Args:
            device_id: Device identifier
            
        Returns:
            Device profile data or None
        """
        key = f"device_profile:{device_id}"
        return cache_get(key)
    
    # Threat Prediction Caching
    
    @staticmethod
    def cache_threat_predictions_list(predictions, ttl=None):
        """
        Cache list of threat predictions
        
        Args:
            predictions: List of threat predictions
            ttl: Time to live (default: 30 minutes)
            
        Returns:
            bool: Success status
        """
        # Threat prediction caching disabled - service removed
        return False
    
    @staticmethod
    def get_threat_predictions_list():
        """
        Retrieve cached threat predictions
        
        Returns:
            List of predictions or None
        """
        # Threat prediction caching disabled - service removed
        return None
    
    @staticmethod
    def cache_user_threat_score(user_id, threat_score, ttl=None):
        """
        Cache user's threat score
        
        Args:
            user_id: User identifier
            threat_score: Threat score data
            ttl: Time to live (default: 30 minutes)
            
        Returns:
            bool: Success status
        """
        if ttl is None:
            ttl = CacheService.TTL_THREAT_PREDICTION
        
        key = f"threat_score:{user_id}"
        return cache_set(key, threat_score, ttl)
    
    @staticmethod
    def get_user_threat_score(user_id):
        """
        Retrieve cached user threat score
        
        Args:
            user_id: User identifier
            
        Returns:
            Threat score data or None
        """
        key = f"threat_score:{user_id}"
        return cache_get(key)
    
    # Session Management Caching
    
    @staticmethod
    def cache_active_session(session_id, session_data, ttl=None):
        """
        Cache active session data
        
        Args:
            session_id: Session identifier
            session_data: Session data
            ttl: Time to live (default: 1 hour)
            
        Returns:
            bool: Success status
        """
        if ttl is None:
            ttl = CacheService.TTL_SESSION_DATA
        
        return session_set(session_id, session_data, ttl)
    
    @staticmethod
    def get_active_session(session_id):
        """
        Retrieve cached session data
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session data or None
        """
        return session_get(session_id)
    
    @staticmethod
    def delete_active_session(session_id):
        """
        Delete cached session data
        
        Args:
            session_id: Session identifier
            
        Returns:
            bool: Success status
        """
        return session_delete(session_id)
    
    @staticmethod
    def update_session_ttl(session_id, ttl=None):
        """
        Update session TTL
        
        Args:
            session_id: Session identifier
            ttl: New time to live (default: 1 hour)
            
        Returns:
            bool: Success status
        """
        if ttl is None:
            ttl = CacheService.TTL_SESSION_DATA
        
        return session_update_ttl(session_id, ttl)
    
    @staticmethod
    def cache_session_risk_score(session_id, risk_score, ttl=300):
        """
        Cache session risk score
        
        Args:
            session_id: Session identifier
            risk_score: Risk score data
            ttl: Time to live (default: 5 minutes)
            
        Returns:
            bool: Success status
        """
        key = f"session_risk:{session_id}"
        return cache_set(key, risk_score, ttl)
    
    @staticmethod
    def get_session_risk_score(session_id):
        """
        Retrieve cached session risk score
        
        Args:
            session_id: Session identifier
            
        Returns:
            Risk score data or None
        """
        key = f"session_risk:{session_id}"
        return cache_get(key)
    
    # Policy Performance Caching
    
    @staticmethod
    def cache_policy_performance(policy_id, performance_data, ttl=None):
        """
        Cache policy performance metrics
        
        Args:
            policy_id: Policy identifier
            performance_data: Performance metrics
            ttl: Time to live (default: 30 minutes)
            
        Returns:
            bool: Success status
        """
        if ttl is None:
            ttl = CacheService.TTL_POLICY_PERFORMANCE
        
        key = f"policy_performance:{policy_id}"
        return cache_set(key, performance_data, ttl)
    
    @staticmethod
    def get_policy_performance(policy_id):
        """
        Retrieve cached policy performance
        
        Args:
            policy_id: Policy identifier
            
        Returns:
            Performance data or None
        """
        key = f"policy_performance:{policy_id}"
        return cache_get(key)
    
    # Network Topology Caching
    
    @staticmethod
    def cache_network_topology(topology_data, ttl=60):
        """
        Cache network topology data
        
        Args:
            topology_data: Network topology data
            ttl: Time to live (default: 1 minute)
            
        Returns:
            bool: Success status
        """
        key = "network_topology:current"
        return cache_set(key, topology_data, ttl)
    
    @staticmethod
    def get_network_topology():
        """
        Retrieve cached network topology
        
        Returns:
            Topology data or None
        """
        key = "network_topology:current"
        return cache_get(key)
    
    # IP Reputation Caching
    
    @staticmethod
    def cache_ip_reputation(ip_address, reputation_data, ttl=3600):
        """
        Cache IP reputation data
        
        Args:
            ip_address: IP address
            reputation_data: Reputation data from external API
            ttl: Time to live (default: 1 hour)
            
        Returns:
            bool: Success status
        """
        key = f"ip_reputation:{ip_address}"
        return cache_set(key, reputation_data, ttl)
    
    @staticmethod
    def get_ip_reputation(ip_address):
        """
        Retrieve cached IP reputation
        
        Args:
            ip_address: IP address
            
        Returns:
            Reputation data or None
        """
        key = f"ip_reputation:{ip_address}"
        return cache_get(key)
    
    # Geolocation Caching
    
    @staticmethod
    def cache_geolocation(ip_address, geo_data, ttl=86400):
        """
        Cache geolocation data
        
        Args:
            ip_address: IP address
            geo_data: Geolocation data
            ttl: Time to live (default: 24 hours)
            
        Returns:
            bool: Success status
        """
        key = f"geolocation:{ip_address}"
        return cache_set(key, geo_data, ttl)
    
    @staticmethod
    def get_geolocation(ip_address):
        """
        Retrieve cached geolocation
        
        Args:
            ip_address: IP address
            
        Returns:
            Geolocation data or None
        """
        key = f"geolocation:{ip_address}"
        return cache_get(key)
    
    # Security Assistant Caching
    
    @staticmethod
    def cache_assistant_response(query_hash, response_data, ttl=3600):
        """
        Cache security assistant response
        
        Args:
            query_hash: Hash of the query
            response_data: Assistant response
            ttl: Time to live (default: 1 hour)
            
        Returns:
            bool: Success status
        """
        key = f"assistant_response:{query_hash}"
        return cache_set(key, response_data, ttl)
    
    @staticmethod
    def get_assistant_response(query_hash):
        """
        Retrieve cached assistant response
        
        Args:
            query_hash: Hash of the query
            
        Returns:
            Response data or None
        """
        key = f"assistant_response:{query_hash}"
        return cache_get(key)
    
    # Utility Methods
    
    @staticmethod
    def invalidate_user_cache(user_id):
        """
        Invalidate all cache entries for a user
        
        Args:
            user_id: User identifier
            
        Returns:
            int: Number of keys deleted
        """
        if not is_redis_available():
            return 0
        
        redis_client = get_redis_client()
        if not redis_client:
            return 0
        
        patterns = [
            f"behavioral_model:{user_id}",
            f"threat_score:{user_id}",
        ]
        
        deleted = 0
        for pattern in patterns:
            if cache_delete(pattern):
                deleted += 1
        
        return deleted
    
    @staticmethod
    def get_cache_stats():
        """
        Get cache statistics
        
        Returns:
            dict: Cache statistics
        """
        from redis_config import get_redis_stats
        return get_redis_stats()


# Export singleton instance
cache_service = CacheService()
