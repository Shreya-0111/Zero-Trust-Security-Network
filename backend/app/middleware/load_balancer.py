"""
Load Balancer Middleware
Integrates graceful degradation and load monitoring with Flask requests
"""

import time
import logging
from functools import wraps
from flask import request, jsonify, g
from app.services.load_balancer_service import graceful_degradation_service, auto_scaling_service

logger = logging.getLogger(__name__)

def load_balancer_middleware(f):
    """Middleware decorator for load balancing and graceful degradation"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        start_time = time.time()
        
        try:
            # Check if request should be rejected due to high load
            if graceful_degradation_service.should_reject_request():
                # Only allow essential endpoints during critical load
                essential_endpoints = [
                    '/api/auth/login',
                    '/api/auth/logout', 
                    '/api/emergency',
                    '/health',
                    '/api/system/status'
                ]
                
                if request.endpoint not in essential_endpoints:
                    return jsonify({
                        'success': False,
                        'error': {
                            'code': 'SYSTEM_OVERLOADED',
                            'message': 'System is currently overloaded. Please try again later.'
                        },
                        'retry_after': 60
                    }), 503
            
            # Store start time for response time calculation
            g.request_start_time = start_time
            
            # Execute the original function
            response = f(*args, **kwargs)
            
            # Record successful request
            response_time = (time.time() - start_time) * 1000  # Convert to milliseconds
            graceful_degradation_service.record_request(response_time, is_error=False)
            
            return response
            
        except Exception as e:
            # Record error request
            response_time = (time.time() - start_time) * 1000
            graceful_degradation_service.record_request(response_time, is_error=True)
            
            logger.error(f"Error in load balancer middleware: {e}")
            raise
    
    return decorated_function

def add_load_balancer_headers(response):
    """Add load balancer headers to response"""
    try:
        metrics = graceful_degradation_service.get_current_metrics()
        if metrics:
            response.headers['X-Load-Level'] = metrics.load_level.value
            response.headers['X-Overall-Load'] = str(round(metrics.overall_load, 1))
            
            if graceful_degradation_service.is_degradation_active():
                response.headers['X-Degradation-Active'] = 'true'
                response.headers['X-Degradation-Level'] = metrics.load_level.value
        
        # Add response time if available
        if hasattr(g, 'request_start_time'):
            response_time = (time.time() - g.request_start_time) * 1000
            response.headers['X-Response-Time'] = str(round(response_time, 2))
        
    except Exception as e:
        logger.error(f"Error adding load balancer headers: {e}")
    
    return response

def check_system_health():
    """Check system health for health endpoints"""
    try:
        health_status = graceful_degradation_service.get_health_status()
        scaling_recommendation = auto_scaling_service.get_scaling_recommendation()
        
        return {
            'system_health': health_status,
            'scaling_recommendation': scaling_recommendation,
            'timestamp': time.time()
        }
    except Exception as e:
        logger.error(f"Error checking system health: {e}")
        return {
            'system_health': {'status': 'error', 'message': str(e)},
            'scaling_recommendation': {'action': 'none', 'reason': 'Health check failed'},
            'timestamp': time.time()
        }