"""
Load Balancer and Graceful Degradation Service
Handles high-load scenarios with graceful degradation and auto-scaling support
"""

import logging
import time
import threading
# import psutil  # Temporarily disabled
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass
from enum import Enum
from app.services.cache_service import cache_service

logger = logging.getLogger(__name__)

class SystemLoadLevel(Enum):
    """System load levels for graceful degradation"""
    NORMAL = "normal"      # 0-60% load
    ELEVATED = "elevated"  # 60-80% load
    HIGH = "high"         # 80-90% load
    CRITICAL = "critical" # 90%+ load

@dataclass
class LoadMetrics:
    """System load metrics"""
    cpu_percent: float
    memory_percent: float
    active_connections: int
    request_rate: float
    response_time_avg: float
    error_rate: float
    timestamp: datetime
    
    @property
    def overall_load(self) -> float:
        """Calculate overall system load percentage"""
        # Weighted average of different metrics
        weights = {
            'cpu': 0.3,
            'memory': 0.25,
            'connections': 0.2,
            'response_time': 0.15,
            'error_rate': 0.1
        }
        
        # Normalize metrics to 0-100 scale
        normalized_connections = min((self.active_connections / 1000) * 100, 100)
        normalized_response_time = min((self.response_time_avg / 2000) * 100, 100)  # 2s = 100%
        normalized_error_rate = min(self.error_rate * 10, 100)  # 10% error = 100%
        
        overall = (
            self.cpu_percent * weights['cpu'] +
            self.memory_percent * weights['memory'] +
            normalized_connections * weights['connections'] +
            normalized_response_time * weights['response_time'] +
            normalized_error_rate * weights['error_rate']
        )
        
        return min(overall, 100)
    
    @property
    def load_level(self) -> SystemLoadLevel:
        """Determine current load level"""
        load = self.overall_load
        if load >= 90:
            return SystemLoadLevel.CRITICAL
        elif load >= 80:
            return SystemLoadLevel.HIGH
        elif load >= 60:
            return SystemLoadLevel.ELEVATED
        else:
            return SystemLoadLevel.NORMAL

class GracefulDegradationService:
    """Service for handling graceful degradation under high load"""
    
    def __init__(self):
        self.current_metrics = None
        self.degradation_active = False
        self.degradation_level = SystemLoadLevel.NORMAL
        self.monitoring_active = False
        self.request_count = 0
        self.response_times = []
        self.error_count = 0
        self.start_time = time.time()
        self._lock = threading.Lock()
        
        # Degradation strategies
        self.degradation_strategies = {
            SystemLoadLevel.ELEVATED: self._apply_elevated_degradation,
            SystemLoadLevel.HIGH: self._apply_high_degradation,
            SystemLoadLevel.CRITICAL: self._apply_critical_degradation
        }
        
        # Start monitoring thread
        self._start_monitoring()
    
    def _start_monitoring(self):
        """Start system monitoring thread"""
        def monitor():
            while self.monitoring_active:
                try:
                    self._collect_metrics()
                    self._evaluate_degradation()
                    time.sleep(5)  # Check every 5 seconds
                except Exception as e:
                    logger.error(f"Error in load monitoring: {e}")
                    time.sleep(10)  # Wait longer on error
        
        self.monitoring_active = True
        monitor_thread = threading.Thread(target=monitor, daemon=True)
        monitor_thread.start()
        logger.info("Load monitoring started")
    
    def _collect_metrics(self):
        """Collect current system metrics"""
        try:
            # System metrics - with fallback when psutil is not available
            try:
                # import psutil  # Temporarily disabled
                # cpu_percent = psutil.cpu_percent(interval=1)
                # memory = psutil.virtual_memory()
                # memory_percent = memory.percent
                
                # Fallback values when psutil is not available
                cpu_percent = 50.0  # Default moderate CPU usage
                memory_percent = 60.0  # Default moderate memory usage
            except:
                cpu_percent = 50.0
                memory_percent = 60.0
            
            # Application metrics
            with self._lock:
                current_time = time.time()
                time_window = current_time - self.start_time
                
                request_rate = self.request_count / max(time_window, 1) if time_window > 0 else 0
                response_time_avg = sum(self.response_times) / len(self.response_times) if self.response_times else 0
                error_rate = (self.error_count / max(self.request_count, 1)) * 100 if self.request_count > 0 else 0
                
                # Get active connections from connection pool
                from app.services.connection_pool_service import connection_pool_service
                pool_stats = connection_pool_service.get_all_stats()
                active_connections = (
                    pool_stats.get('firestore', {}).get('active_connections', 0) +
                    pool_stats.get('redis', {}).get('active_connections', 0)
                )
            
            self.current_metrics = LoadMetrics(
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                active_connections=active_connections,
                request_rate=request_rate,
                response_time_avg=response_time_avg,
                error_rate=error_rate,
                timestamp=datetime.utcnow()
            )
            
            # Cache metrics for monitoring dashboard
            cache_service.cache_device_profile(
                "system_metrics:current", 
                self.current_metrics.__dict__, 
                60  # 1 minute TTL
            )
            
        except Exception as e:
            logger.error(f"Error collecting metrics: {e}")
    
    def _evaluate_degradation(self):
        """Evaluate if degradation should be applied"""
        if not self.current_metrics:
            return
        
        new_level = self.current_metrics.load_level
        
        if new_level != self.degradation_level:
            logger.info(f"Load level changed: {self.degradation_level.value} -> {new_level.value}")
            self.degradation_level = new_level
            
            if new_level == SystemLoadLevel.NORMAL:
                self._disable_degradation()
            else:
                self._apply_degradation(new_level)
    
    def _apply_degradation(self, level: SystemLoadLevel):
        """Apply degradation strategies based on load level"""
        if level in self.degradation_strategies:
            self.degradation_strategies[level]()
            self.degradation_active = True
            logger.warning(f"Graceful degradation activated: {level.value}")
    
    def _disable_degradation(self):
        """Disable all degradation strategies"""
        if self.degradation_active:
            self.degradation_active = False
            logger.info("Graceful degradation disabled - system load normal")
    
    def _apply_elevated_degradation(self):
        """Apply degradation for elevated load (60-80%)"""
        # Reduce cache TTL to free memory
        cache_service.TTL_BEHAVIORAL_MODEL = 1800  # 30 minutes instead of 1 hour
        cache_service.TTL_CONTEXT_SCORE = 180      # 3 minutes instead of 5
        
        # Reduce continuous auth frequency
        self._set_continuous_auth_interval(10)  # 10 minutes instead of 5
        
        logger.info("Applied elevated load degradation strategies")
    
    def _apply_high_degradation(self):
        """Apply degradation for high load (80-90%)"""
        # Further reduce cache TTL
        cache_service.TTL_BEHAVIORAL_MODEL = 900   # 15 minutes
        cache_service.TTL_CONTEXT_SCORE = 120      # 2 minutes
        cache_service.TTL_DEVICE_PROFILE = 3600    # 1 hour instead of 2
        
        # Reduce continuous auth frequency more
        self._set_continuous_auth_interval(15)  # 15 minutes
        
        # Disable non-critical features
        self._disable_non_critical_features()
        
        logger.warning("Applied high load degradation strategies")
    
    def _apply_critical_degradation(self):
        """Apply degradation for critical load (90%+)"""
        # Minimal cache TTL
        cache_service.TTL_BEHAVIORAL_MODEL = 300   # 5 minutes
        cache_service.TTL_CONTEXT_SCORE = 60       # 1 minute
        cache_service.TTL_DEVICE_PROFILE = 1800    # 30 minutes
        
        # Minimal continuous auth
        self._set_continuous_auth_interval(30)  # 30 minutes
        
        # Disable all non-essential features
        self._disable_non_critical_features()
        self._enable_emergency_mode()
        
        logger.critical("Applied critical load degradation strategies")
    
    def _set_continuous_auth_interval(self, minutes: int):
        """Set continuous authentication check interval"""
        try:
            cache_service.cache_device_profile(
                "continuous_auth:interval", 
                {"interval_minutes": minutes}, 
                3600
            )
        except Exception as e:
            logger.error(f"Error setting continuous auth interval: {e}")
    
    def _disable_non_critical_features(self):
        """Disable non-critical features to reduce load"""
        try:
            # Disable real-time heatmap updates
            cache_service.cache_device_profile(
                "feature_flags:heatmap_realtime", 
                {"enabled": False}, 
                3600
            )
            
            # Disable detailed audit logging
            cache_service.cache_device_profile(
                "feature_flags:detailed_audit", 
                {"enabled": False}, 
                3600
            )
            
            # Disable ML model updates
            cache_service.cache_device_profile(
                "feature_flags:ml_updates", 
                {"enabled": False}, 
                3600
            )
            
            logger.info("Disabled non-critical features")
            
        except Exception as e:
            logger.error(f"Error disabling non-critical features: {e}")
    
    def _enable_emergency_mode(self):
        """Enable emergency mode with minimal functionality"""
        try:
            cache_service.cache_device_profile(
                "system_mode", 
                {"mode": "emergency", "enabled_at": datetime.utcnow().isoformat()}, 
                3600
            )
            logger.critical("Emergency mode enabled")
        except Exception as e:
            logger.error(f"Error enabling emergency mode: {e}")
    
    def record_request(self, response_time: float, is_error: bool = False):
        """Record request metrics"""
        with self._lock:
            self.request_count += 1
            self.response_times.append(response_time)
            
            # Keep only last 1000 response times for memory efficiency
            if len(self.response_times) > 1000:
                self.response_times = self.response_times[-1000:]
            
            if is_error:
                self.error_count += 1
    
    def get_current_metrics(self) -> Optional[LoadMetrics]:
        """Get current system metrics"""
        return self.current_metrics
    
    def is_degradation_active(self) -> bool:
        """Check if degradation is currently active"""
        return self.degradation_active
    
    def get_degradation_level(self) -> SystemLoadLevel:
        """Get current degradation level"""
        return self.degradation_level
    
    def should_reject_request(self) -> bool:
        """Determine if new requests should be rejected"""
        if not self.current_metrics:
            return False
        
        # Reject requests if system is in critical state
        if self.degradation_level == SystemLoadLevel.CRITICAL:
            # Allow only essential requests (authentication, emergency access)
            return True
        
        return False
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get system health status"""
        if not self.current_metrics:
            return {"status": "unknown", "message": "Metrics not available"}
        
        load_level = self.current_metrics.load_level
        
        if load_level == SystemLoadLevel.NORMAL:
            return {
                "status": "healthy",
                "load_level": load_level.value,
                "overall_load": self.current_metrics.overall_load,
                "degradation_active": self.degradation_active
            }
        elif load_level == SystemLoadLevel.ELEVATED:
            return {
                "status": "warning",
                "load_level": load_level.value,
                "overall_load": self.current_metrics.overall_load,
                "degradation_active": self.degradation_active,
                "message": "System under elevated load"
            }
        elif load_level == SystemLoadLevel.HIGH:
            return {
                "status": "degraded",
                "load_level": load_level.value,
                "overall_load": self.current_metrics.overall_load,
                "degradation_active": self.degradation_active,
                "message": "System under high load - some features disabled"
            }
        else:  # CRITICAL
            return {
                "status": "critical",
                "load_level": load_level.value,
                "overall_load": self.current_metrics.overall_load,
                "degradation_active": self.degradation_active,
                "message": "System in emergency mode - minimal functionality only"
            }

class AutoScalingService:
    """Service for auto-scaling recommendations and horizontal scaling support"""
    
    def __init__(self, degradation_service: GracefulDegradationService):
        self.degradation_service = degradation_service
        self.scaling_history = []
        self.max_history = 100
    
    def should_scale_up(self) -> bool:
        """Determine if system should scale up"""
        metrics = self.degradation_service.get_current_metrics()
        if not metrics:
            return False
        
        # Scale up if load is consistently high
        if metrics.load_level in [SystemLoadLevel.HIGH, SystemLoadLevel.CRITICAL]:
            return True
        
        # Scale up if response times are consistently slow
        if metrics.response_time_avg > 1500:  # 1.5 seconds
            return True
        
        return False
    
    def should_scale_down(self) -> bool:
        """Determine if system can scale down"""
        metrics = self.degradation_service.get_current_metrics()
        if not metrics:
            return False
        
        # Scale down if load is consistently low
        if metrics.load_level == SystemLoadLevel.NORMAL and metrics.overall_load < 30:
            return True
        
        return False
    
    def get_scaling_recommendation(self) -> Dict[str, Any]:
        """Get scaling recommendation"""
        metrics = self.degradation_service.get_current_metrics()
        if not metrics:
            return {"action": "none", "reason": "No metrics available"}
        
        if self.should_scale_up():
            return {
                "action": "scale_up",
                "reason": f"High load detected: {metrics.overall_load:.1f}%",
                "current_load": metrics.overall_load,
                "load_level": metrics.load_level.value,
                "recommended_instances": self._calculate_required_instances()
            }
        elif self.should_scale_down():
            return {
                "action": "scale_down",
                "reason": f"Low load detected: {metrics.overall_load:.1f}%",
                "current_load": metrics.overall_load,
                "load_level": metrics.load_level.value,
                "recommended_instances": max(1, self._calculate_required_instances() - 1)
            }
        else:
            return {
                "action": "none",
                "reason": "Load within acceptable range",
                "current_load": metrics.overall_load,
                "load_level": metrics.load_level.value
            }
    
    def _calculate_required_instances(self) -> int:
        """Calculate required number of instances based on load"""
        metrics = self.degradation_service.get_current_metrics()
        if not metrics:
            return 1
        
        # Simple calculation: 1 instance per 70% load
        required = max(1, int(metrics.overall_load / 70) + 1)
        return min(required, 10)  # Cap at 10 instances
    
    def record_scaling_event(self, action: str, reason: str):
        """Record scaling event"""
        event = {
            "timestamp": datetime.utcnow(),
            "action": action,
            "reason": reason,
            "metrics": self.degradation_service.get_current_metrics().__dict__ if self.degradation_service.get_current_metrics() else None
        }
        
        self.scaling_history.append(event)
        
        # Keep only recent history
        if len(self.scaling_history) > self.max_history:
            self.scaling_history = self.scaling_history[-self.max_history:]
        
        logger.info(f"Scaling event recorded: {action} - {reason}")

# Global service instances
graceful_degradation_service = GracefulDegradationService()
auto_scaling_service = AutoScalingService(graceful_degradation_service)