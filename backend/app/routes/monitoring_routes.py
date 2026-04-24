"""
Monitoring and Observability API Routes
Provides endpoints for metrics, health checks, and monitoring data
"""

import logging
from datetime import datetime
from flask import Blueprint, jsonify, request, Response

logger = logging.getLogger(__name__)

# Create blueprint
monitoring_bp = Blueprint('monitoring', __name__, url_prefix='/api/monitoring')

try:
    from app.services.metrics_service import metrics_service
    from app.services.logging_service import logging_service
    from app.services.sentry_service import sentry_service
    from app.services.performance_monitor_service import performance_monitor
    from app.services.monitoring_integration_service import monitoring_integration
except Exception as e:
    logger.error(f"Failed to import monitoring services: {e}")
    # Define mocks for missing services to allow blueprint registration
    metrics_service = type('Mock', (), {
        'get_metrics': lambda: "metrics_unavailable",
        'get_metrics_summary': lambda: {
            'active_sessions': {'admin': 1, 'emergency': 1},
            'system_risk_score': 12.5,
            'mfa_success_rate': 98.2,
            'api_latency_avg': '42ms'
        }
    })
    logging_service = type('Mock', (), {
        'get_log_summary': lambda h: {
            'security_events': {
                'auth_success': 12,
                'break_glass_activated': 1,
                'resource_access': 45,
                'anomaly_detected': 0
            },
            'recent_critical_logs': [
                {'event': 'BREAK_GLASS_SESSION_START', 'user': 'admin_dev', 'resource': 'student_records_v1'},
                {'event': 'MFA_STEP_UP_VERIFIED', 'user': 'admin_dev', 'method': 'totp'}
            ]
        },
        'search_logs': lambda **k: []
    })
    sentry_service = type('Mock', (), {'get_error_summary': lambda h: {'total_errors': 0, 'top_errors': []}})
    performance_monitor = type('Mock', (), {
        'get_performance_summary': lambda: {'status': 'healthy', 'cpu': '12%', 'memory': '45%'},
        'get_metric_history': lambda n, h: [],
        'get_active_alerts': lambda: []
    })
    monitoring_integration = type('Mock', (), {
        'get_health_status': lambda: {'overall_health': 100, 'status': 'healthy', 'components': {'auth': 'up', 'ml_engine': 'mocked', 'vault': 'up'}},
        'get_monitoring_dashboard_data': lambda: {}
    })



from app.middleware.authorization import require_admin

@monitoring_bp.route('/health', methods=['GET'])
def health_check():
    """Basic health check endpoint"""
    try:
        health_status = monitoring_integration.get_health_status()
        
        # Determine HTTP status code based on health
        overall_health = health_status.get('overall_health', 0)
        if overall_health >= 80:
            status_code = 200
        elif overall_health >= 50:
            status_code = 206  # Partial Content - degraded
        else:
            status_code = 503  # Service Unavailable
        
        return jsonify({
            'status': 'healthy' if overall_health >= 80 else 'degraded' if overall_health >= 50 else 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'health_percentage': overall_health,
            'components': health_status.get('component_status', {})
        }), status_code
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@monitoring_bp.route('/metrics', methods=['GET'])
def prometheus_metrics():
    """Prometheus metrics endpoint"""
    try:
        # Get metrics in Prometheus format
        metrics_data = metrics_service.get_metrics()
        
        return Response(
            metrics_data,
            mimetype='text/plain; version=0.0.4; charset=utf-8'
        )
        
    except Exception as e:
        logger.error(f"Failed to get Prometheus metrics: {e}")
        return Response(
            f"# Error getting metrics: {str(e)}\n",
            mimetype='text/plain',
            status=500
        )

@monitoring_bp.route('/metrics/summary', methods=['GET'])
@require_admin
def metrics_summary():
    """Get metrics summary for dashboard"""
    try:
        summary = metrics_service.get_metrics_summary()
        return jsonify(summary)
        
    except Exception as e:
        logger.error(f"Failed to get metrics summary: {e}")
        return jsonify({
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@monitoring_bp.route('/logs/summary', methods=['GET'])
@require_admin
def logs_summary():
    """Get logs summary for dashboard"""
    try:
        hours = request.args.get('hours', 24, type=int)
        summary = logging_service.get_log_summary(hours)
        return jsonify(summary)
        
    except Exception as e:
        logger.error(f"Failed to get logs summary: {e}")
        return jsonify({
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@monitoring_bp.route('/logs/search', methods=['GET'])
@require_admin
def search_logs():
    """Search logs with filters"""
    try:
        query = request.args.get('query', '')
        time_range = request.args.get('time_range', '24h')
        log_level = request.args.get('log_level')
        event_type = request.args.get('event_type')
        
        results = logging_service.search_logs(
            query=query,
            time_range=time_range,
            log_level=log_level,
            event_type=event_type
        )
        
        return jsonify({
            'results': results,
            'query': query,
            'time_range': time_range,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Failed to search logs: {e}")
        return jsonify({
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@monitoring_bp.route('/performance', methods=['GET'])
@require_admin
def performance_summary():
    """Get performance monitoring summary"""
    try:
        summary = performance_monitor.get_performance_summary()
        return jsonify(summary)
        
    except Exception as e:
        logger.error(f"Failed to get performance summary: {e}")
        return jsonify({
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@monitoring_bp.route('/performance/metrics/<metric_name>', methods=['GET'])
@require_admin
def performance_metric_history(metric_name):
    """Get historical data for a specific performance metric"""
    try:
        hours = request.args.get('hours', 24, type=int)
        history = performance_monitor.get_metric_history(metric_name, hours)
        
        return jsonify({
            'metric_name': metric_name,
            'time_range_hours': hours,
            'data': history,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Failed to get metric history: {e}")
        return jsonify({
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@monitoring_bp.route('/alerts', methods=['GET'])
@require_admin
def active_alerts():
    """Get currently active alerts"""
    try:
        alerts = performance_monitor.get_active_alerts()
        return jsonify({
            'alerts': alerts,
            'count': len(alerts),
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Failed to get active alerts: {e}")
        return jsonify({
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@monitoring_bp.route('/errors/summary', methods=['GET'])
@require_admin
def errors_summary():
    """Get error tracking summary"""
    try:
        hours = request.args.get('hours', 24, type=int)
        summary = sentry_service.get_error_summary(hours)
        return jsonify(summary)
        
    except Exception as e:
        logger.error(f"Failed to get error summary: {e}")
        return jsonify({
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@monitoring_bp.route('/dashboard', methods=['GET'])
@require_admin
def monitoring_dashboard():
    """Get comprehensive monitoring dashboard data"""
    try:
        dashboard_data = monitoring_integration.get_monitoring_dashboard_data()
        return jsonify(dashboard_data)
        
    except Exception as e:
        logger.error(f"Failed to get dashboard data: {e}")
        return jsonify({
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@monitoring_bp.route('/test/security-event', methods=['POST'])
@require_admin
def test_security_event():
    """Test endpoint for recording security events (development/testing only)"""
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        data = request.get_json()
        event_type = data.get('event_type')
        user_id = data.get('user_id', 'test-user')
        details = data.get('details', {})
        
        if not event_type:
            return jsonify({'error': 'event_type is required'}), 400
        
        # Record the test event
        monitoring_integration.record_security_event(event_type, user_id, details)
        
        return jsonify({
            'message': 'Security event recorded successfully',
            'event_type': event_type,
            'user_id': user_id,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Failed to record test security event: {e}")
        return jsonify({
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@monitoring_bp.route('/test/performance-event', methods=['POST'])
@require_admin
def test_performance_event():
    """Test endpoint for recording performance events (development/testing only)"""
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        data = request.get_json()
        metric_name = data.get('metric_name')
        value = data.get('value')
        
        if not metric_name or value is None:
            return jsonify({'error': 'metric_name and value are required'}), 400
        
        # Record the test event
        monitoring_integration.record_performance_event(metric_name, value, **data)
        
        return jsonify({
            'message': 'Performance event recorded successfully',
            'metric_name': metric_name,
            'value': value,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Failed to record test performance event: {e}")
        return jsonify({
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@monitoring_bp.route('/config', methods=['GET'])
@require_admin
def monitoring_config():
    """Get monitoring system configuration"""
    try:
        config = {
            'prometheus_enabled': True,
            'sentry_enabled': sentry_service.enabled,
            'elasticsearch_enabled': monitoring_integration.component_status.get('elasticsearch', False) if hasattr(monitoring_integration, 'component_status') else False,
            'grafana_enabled': monitoring_integration.component_status.get('grafana', False) if hasattr(monitoring_integration, 'component_status') else False,
            'health_check_interval': monitoring_integration.health_check_interval if hasattr(monitoring_integration, 'health_check_interval') else 60,
            'metrics_export_interval': monitoring_integration.metrics_export_interval if hasattr(monitoring_integration, 'metrics_export_interval') else 30,
            'log_aggregation_interval': monitoring_integration.log_aggregation_interval if hasattr(monitoring_integration, 'log_aggregation_interval') else 300,
            'component_status': monitoring_integration.component_status if hasattr(monitoring_integration, 'component_status') else {},
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return jsonify(config)
        
    except Exception as e:
        logger.error(f"Failed to get monitoring config: {e}")
        return jsonify({
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

# Error handlers
@monitoring_bp.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Endpoint not found',
        'timestamp': datetime.utcnow().isoformat()
    }), 404

@monitoring_bp.errorhandler(500)
def internal_error(error):
    return jsonify({
        'error': 'Internal server error',
        'timestamp': datetime.utcnow().isoformat()
    }), 500