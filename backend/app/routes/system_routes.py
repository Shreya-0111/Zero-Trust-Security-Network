"""
System Status Routes
Provides system health, load metrics, and scaling information
"""

from flask import Blueprint, jsonify, request
from app.middleware.authorization import require_admin
from app.middleware.load_balancer import check_system_health
from app.services.load_balancer_service import graceful_degradation_service, auto_scaling_service
from app.services.connection_pool_service import connection_pool_service
from app.services.cache_service import cache_service

system_bp = Blueprint('system', __name__, url_prefix='/api/system')

@system_bp.route('/health', methods=['GET'])
def system_health():
    """Get comprehensive system health status"""
    try:
        health_data = check_system_health()
        
        # Add connection pool stats
        health_data['connection_pools'] = connection_pool_service.get_all_stats()
        
        # Add cache stats
        if cache_service.is_available():
            health_data['cache_stats'] = cache_service.get_cache_stats()
        
        return jsonify({
            'success': True,
            'data': health_data
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'HEALTH_CHECK_FAILED',
                'message': str(e)
            }
        }), 500

@system_bp.route('/metrics', methods=['GET'])
@require_admin
def system_metrics():
    """Get detailed system metrics (admin only)"""
    try:
        metrics = graceful_degradation_service.get_current_metrics()
        
        if not metrics:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'METRICS_NOT_AVAILABLE',
                    'message': 'System metrics not available'
                }
            }), 503
        
        return jsonify({
            'success': True,
            'data': {
                'metrics': {
                    'cpu_percent': metrics.cpu_percent,
                    'memory_percent': metrics.memory_percent,
                    'active_connections': metrics.active_connections,
                    'request_rate': metrics.request_rate,
                    'response_time_avg': metrics.response_time_avg,
                    'error_rate': metrics.error_rate,
                    'overall_load': metrics.overall_load,
                    'load_level': metrics.load_level.value,
                    'timestamp': metrics.timestamp.isoformat()
                },
                'degradation': {
                    'active': graceful_degradation_service.is_degradation_active(),
                    'level': graceful_degradation_service.get_degradation_level().value
                },
                'connection_pools': connection_pool_service.get_all_stats()
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'METRICS_ERROR',
                'message': str(e)
            }
        }), 500

@system_bp.route('/scaling', methods=['GET'])
@require_admin
def scaling_recommendation():
    """Get auto-scaling recommendations (admin only)"""
    try:
        recommendation = auto_scaling_service.get_scaling_recommendation()
        
        return jsonify({
            'success': True,
            'data': {
                'recommendation': recommendation,
                'current_metrics': graceful_degradation_service.get_current_metrics().__dict__ if graceful_degradation_service.get_current_metrics() else None
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'SCALING_ERROR',
                'message': str(e)
            }
        }), 500

@system_bp.route('/scaling/history', methods=['GET'])
@require_admin
def scaling_history():
    """Get scaling event history (admin only)"""
    try:
        history = auto_scaling_service.scaling_history
        
        # Convert datetime objects to ISO strings for JSON serialization
        serialized_history = []
        for event in history:
            serialized_event = {
                'timestamp': event['timestamp'].isoformat(),
                'action': event['action'],
                'reason': event['reason'],
                'metrics': event['metrics']
            }
            serialized_history.append(serialized_event)
        
        return jsonify({
            'success': True,
            'data': {
                'history': serialized_history,
                'total_events': len(serialized_history)
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'HISTORY_ERROR',
                'message': str(e)
            }
        }), 500

@system_bp.route('/status', methods=['GET'])
def system_status():
    """Get basic system status (public endpoint for load balancers)"""
    try:
        health_status = graceful_degradation_service.get_health_status()
        
        # Return appropriate HTTP status codes for load balancer health checks
        if health_status['status'] == 'healthy':
            status_code = 200
        elif health_status['status'] in ['warning', 'degraded']:
            status_code = 200  # Still accepting requests
        else:  # critical
            status_code = 503  # Service unavailable
        
        return jsonify({
            'status': health_status['status'],
            'load_level': health_status['load_level'],
            'degradation_active': health_status.get('degradation_active', False),
            'timestamp': graceful_degradation_service.get_current_metrics().timestamp.isoformat() if graceful_degradation_service.get_current_metrics() else None
        }), status_code
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@system_bp.route('/metrics/history', methods=['GET'])
@require_admin
def metrics_history():
    """Get historical metrics data (admin only)"""
    try:
        from app.services.performance_monitor_service import performance_monitor
        
        metric_name = request.args.get('metric', 'overall_load')
        hours = int(request.args.get('hours', 24))
        
        history = performance_monitor.get_metric_history(metric_name, hours)
        
        return jsonify({
            'success': True,
            'data': history,
            'metric_name': metric_name,
            'hours': hours
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'HISTORY_ERROR',
                'message': str(e)
            }
        }), 500

@system_bp.route('/performance/summary', methods=['GET'])
@require_admin
def performance_summary():
    """Get performance summary for dashboard (admin only)"""
    try:
        from app.services.performance_monitor_service import performance_monitor
        
        summary = performance_monitor.get_performance_summary()
        
        return jsonify({
            'success': True,
            'data': summary
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'PERFORMANCE_SUMMARY_ERROR',
                'message': str(e)
            }
        }), 500

@system_bp.route('/alerts', methods=['GET'])
@require_admin
def get_alerts():
    """Get active performance alerts (admin only)"""
    try:
        from app.services.performance_monitor_service import performance_monitor
        
        active_alerts = performance_monitor.get_active_alerts()
        
        return jsonify({
            'success': True,
            'data': {
                'active_alerts': active_alerts,
                'count': len(active_alerts)
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'ALERTS_ERROR',
                'message': str(e)
            }
        }), 500

@system_bp.route('/degradation/toggle', methods=['POST'])
@require_admin
def toggle_degradation():
    """Manually toggle degradation mode (admin only, for testing)"""
    try:
        data = request.get_json() or {}
        enable = data.get('enable', False)
        
        if enable:
            # Force degradation for testing
            graceful_degradation_service.degradation_active = True
            graceful_degradation_service.degradation_level = graceful_degradation_service.current_metrics.load_level if graceful_degradation_service.current_metrics else graceful_degradation_service.degradation_level
            message = "Degradation manually enabled"
        else:
            # Disable degradation
            graceful_degradation_service._disable_degradation()
            message = "Degradation manually disabled"
        
        return jsonify({
            'success': True,
            'message': message,
            'degradation_active': graceful_degradation_service.is_degradation_active(),
            'degradation_level': graceful_degradation_service.get_degradation_level().value
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'DEGRADATION_TOGGLE_ERROR',
                'message': str(e)
            }
        }), 500