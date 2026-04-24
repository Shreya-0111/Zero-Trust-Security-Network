"""
Security Routes
API endpoints for security heatmap, real-time events, and security monitoring
"""

from flask import Blueprint, request, jsonify
from datetime import datetime
import logging

from app.middleware.authorization import require_auth, require_role
from app.services.realtime_event_service import realtime_event_processor
from app.services.audit_logger import audit_logger
from app.utils.error_handler import AppError

logger = logging.getLogger(__name__)

# Create blueprint
security_bp = Blueprint('security', __name__, url_prefix='/api/security')

@security_bp.route('/activity-map', methods=['GET'])
@require_auth
@require_role(['admin', 'faculty'])
def get_activity_map_data():
    """
    Get activity map data showing user locations, visitor routes, and security events
    
    Query Parameters:
        - mapType: Type of map ('logical', 'geographic')
        - userFilter: Filter by specific user ID
        - timeRange: Time range for data ('15m', '1h', '4h', '24h', '7d')
    
    Returns:
        JSON response with activity map data
    """
    try:
        user_id = request.user_id
        
        # Get query parameters
        map_type = request.args.get('mapType', 'logical')
        user_filter = request.args.get('userFilter')
        time_range = request.args.get('timeRange', '1h')
        
        # Validate parameters
        valid_map_types = ['logical', 'geographic']
        if map_type not in valid_map_types:
            raise AppError('INVALID_MAP_TYPE', f'Map type must be one of: {", ".join(valid_map_types)}')
        
        valid_ranges = ['15m', '1h', '4h', '24h', '7d']
        if time_range not in valid_ranges:
            raise AppError('INVALID_TIME_RANGE', f'Time range must be one of: {", ".join(valid_ranges)}')
        
        # Generate mock activity map data (in a real implementation, this would come from the database)
        import random
        from datetime import datetime, timedelta
        
        # Calculate time cutoff
        time_deltas = {
            '15m': timedelta(minutes=15),
            '1h': timedelta(hours=1),
            '4h': timedelta(hours=4),
            '24h': timedelta(hours=24),
            '7d': timedelta(days=7)
        }
        cutoff_time = datetime.utcnow() - time_deltas.get(time_range, timedelta(hours=1))
        
        # Generate sample data
        activity_data = {
            'users': [
                {
                    'userId': f'user_{i}',
                    'name': f'User {i}',
                    'role': random.choice(['student', 'faculty', 'admin']),
                    'x': random.randint(100, 700),
                    'y': random.randint(100, 500),
                    'isActive': random.choice([True, False]),
                    'riskScore': random.randint(0, 100),
                    'lastActivity': (datetime.utcnow() - timedelta(minutes=random.randint(1, 60))).isoformat(),
                    'currentZone': random.choice(['Academic Zone', 'Library Services', 'Administrative Zone'])
                }
                for i in range(random.randint(10, 25))
            ],
            'visitors': [
                {
                    'visitorId': f'visitor_{i}',
                    'name': f'Visitor {i}',
                    'hostName': f'Host {i}',
                    'visitPurpose': random.choice(['Meeting', 'Research', 'Conference', 'Interview']),
                    'x': random.randint(100, 700),
                    'y': random.randint(100, 500),
                    'routeCompliance': random.randint(70, 100),
                    'timeRemaining': f'{random.randint(1, 8)} hours',
                    'currentZone': random.choice(['Academic Zone', 'Library Services', 'Public Areas']),
                    'route': [
                        {'x': random.randint(100, 200), 'y': random.randint(100, 200)},
                        {'x': random.randint(200, 400), 'y': random.randint(200, 300)},
                        {'x': random.randint(400, 600), 'y': random.randint(300, 400)}
                    ]
                }
                for i in range(random.randint(3, 8))
            ],
            'accessPoints': [
                {
                    'id': f'ap_{i}',
                    'name': f'Access Point {i}',
                    'type': random.choice(['door', 'terminal', 'scanner']),
                    'status': random.choice(['active', 'inactive', 'maintenance']),
                    'x': random.randint(50, 750),
                    'y': random.randint(50, 550),
                    'activeUsers': random.randint(0, 10)
                }
                for i in range(random.randint(8, 15))
            ],
            'securityEvents': [
                {
                    'eventId': f'event_{i}',
                    'eventType': random.choice(['device_mismatch', 'route_deviation', 'risk_elevation']),
                    'severity': random.choice(['low', 'medium', 'high', 'critical']),
                    'timestamp': (datetime.utcnow() - timedelta(minutes=random.randint(1, 120))).isoformat(),
                    'userId': f'user_{random.randint(1, 20)}',
                    'x': random.randint(100, 700),
                    'y': random.randint(100, 500),
                    'description': f'Security event {i} detected'
                }
                for i in range(random.randint(5, 15))
            ]
        }
        
        # Apply user filter if specified
        if user_filter:
            activity_data['users'] = [u for u in activity_data['users'] if u['userId'] == user_filter]
            activity_data['securityEvents'] = [e for e in activity_data['securityEvents'] if e.get('userId') == user_filter]
        
        # Log audit event
        audit_logger.log_event(
            event_type='activity_map_access',
            user_id=user_id,
            action='get_activity_map_data',
            resource='activity_map',
            result='success',
            details={
                'map_type': map_type,
                'user_filter': user_filter,
                'time_range': time_range,
                'users_count': len(activity_data['users']),
                'visitors_count': len(activity_data['visitors']),
                'events_count': len(activity_data['securityEvents'])
            }
        )
        
        return jsonify({
            'success': True,
            'data': activity_data,
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except AppError:
        raise
    except Exception as e:
        logger.error(f"Error getting activity map data: {str(e)}")
        raise AppError('ACTIVITY_MAP_ERROR', 'Failed to retrieve activity map data')


@security_bp.route('/heatmap', methods=['GET'])
@require_auth
@require_role(['admin', 'faculty'])
def get_heatmap_data():
    """
    Get security heatmap data with filtering options
    
    Query Parameters:
        - timeRange: Time range for data ('15m', '1h', '4h', '24h', '7d')
        - userRole: Filter by user role ('student', 'faculty', 'admin', 'visitor')
        - severity: Filter by severity level ('low', 'medium', 'high', 'critical')
    
    Returns:
        JSON response with heatmap data and statistics
    """
    try:
        user_id = request.user_id
        
        # Get query parameters
        time_range = request.args.get('timeRange', '1h')
        user_role = request.args.get('userRole')
        severity = request.args.get('severity')
        
        # Validate time range
        valid_ranges = ['15m', '1h', '4h', '24h', '7d']
        if time_range not in valid_ranges:
            raise AppError('INVALID_TIME_RANGE', f'Time range must be one of: {", ".join(valid_ranges)}')
        
        # Validate user role if provided
        if user_role:
            valid_roles = ['student', 'faculty', 'admin', 'visitor']
            if user_role not in valid_roles:
                raise AppError('INVALID_USER_ROLE', f'User role must be one of: {", ".join(valid_roles)}')
        
        # Validate severity if provided
        if severity:
            valid_severities = ['low', 'medium', 'high', 'critical']
            if severity not in valid_severities:
                raise AppError('INVALID_SEVERITY', f'Severity must be one of: {", ".join(valid_severities)}')
        
        # Get heatmap data
        result = realtime_event_processor.get_heatmap_data(
            time_range=time_range,
            user_role=user_role,
            severity=severity
        )
        
        # Log audit event
        audit_logger.log_event(
            event_type='heatmap_data_access',
            user_id=user_id,
            action='get_heatmap_data',
            resource='security_heatmap',
            result='success',
            details={
                'time_range': time_range,
                'user_role_filter': user_role,
                'severity_filter': severity,
                'data_points': len(result.get('data', []))
            }
        )
        
        return jsonify(result), 200
        
    except AppError:
        raise
    except Exception as e:
        logger.error(f"Error getting heatmap data: {str(e)}")
        raise AppError('HEATMAP_DATA_ERROR', 'Failed to retrieve heatmap data')


@security_bp.route('/events', methods=['POST'])
@require_auth
def process_security_event():
    """
    Process a new security event for real-time heatmap updates
    
    Request Body:
        JSON object with event data including:
        - eventType: Type of security event
        - severity: Event severity level
        - userId: User ID associated with the event
        - eventData: Additional event details
    
    Returns:
        JSON response with processing result
    """
    try:
        user_id = request.user_id
        event_data = request.get_json()
        
        if not event_data:
            raise AppError('MISSING_EVENT_DATA', 'Event data is required')
        
        # Validate required fields
        required_fields = ['eventType']
        for field in required_fields:
            if field not in event_data:
                raise AppError('MISSING_REQUIRED_FIELD', f'Field {field} is required')
        
        # Add metadata
        event_data['submittedBy'] = user_id
        event_data['submittedAt'] = datetime.utcnow().isoformat()
        
        # Process the event
        result = realtime_event_processor.process_security_event(event_data)
        
        # Log audit event
        audit_logger.log_event(
            event_type='security_event_submitted',
            user_id=user_id,
            action='submit_security_event',
            resource='security_event',
            result='success' if result.get('success') else 'failure',
            details={
                'event_type': event_data.get('eventType'),
                'severity': event_data.get('severity'),
                'event_id': result.get('event_id')
            }
        )
        
        return jsonify(result), 200 if result.get('success') else 400
        
    except AppError:
        raise
    except Exception as e:
        logger.error(f"Error processing security event: {str(e)}")
        raise AppError('EVENT_PROCESSING_ERROR', 'Failed to process security event')


@security_bp.route('/metrics', methods=['GET'])
@require_auth
@require_role(['admin'])
def get_activity_metrics():
    """
    Get real-time activity metrics for administrators
    
    Returns:
        JSON response with current activity metrics
    """
    try:
        user_id = request.user_id
        
        # Get activity metrics
        metrics = realtime_event_processor.get_activity_metrics()
        
        # Log audit event
        audit_logger.log_event(
            event_type='metrics_access',
            user_id=user_id,
            action='get_activity_metrics',
            resource='activity_metrics',
            result='success',
            details={
                'total_events': metrics.get('total_events', 0)
            }
        )
        
        return jsonify({
            'success': True,
            'metrics': metrics,
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting activity metrics: {str(e)}")
        raise AppError('METRICS_ERROR', 'Failed to retrieve activity metrics')


@security_bp.route('/alerts', methods=['GET'])
@require_auth
@require_role(['admin'])
def get_alert_history():
    """
    Get recent security alert history
    
    Query Parameters:
        - limit: Maximum number of alerts to return (default: 50, max: 200)
    
    Returns:
        JSON response with alert history
    """
    try:
        user_id = request.user_id
        
        # Get limit parameter
        limit = request.args.get('limit', 50, type=int)
        limit = min(max(1, limit), 200)  # Clamp between 1 and 200
        
        # Get alert history
        alerts = realtime_event_processor.get_alert_history(limit=limit)
        
        # Log audit event
        audit_logger.log_event(
            event_type='alert_history_access',
            user_id=user_id,
            action='get_alert_history',
            resource='alert_history',
            result='success',
            details={
                'limit': limit,
                'alerts_returned': len(alerts)
            }
        )
        
        return jsonify({
            'success': True,
            'alerts': alerts,
            'count': len(alerts),
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting alert history: {str(e)}")
        raise AppError('ALERT_HISTORY_ERROR', 'Failed to retrieve alert history')


@security_bp.route('/events/<event_id>/acknowledge', methods=['POST'])
@require_auth
@require_role(['admin'])
def acknowledge_security_event(event_id):
    """
    Acknowledge a security event
    
    Path Parameters:
        - event_id: ID of the security event to acknowledge
    
    Request Body:
        JSON object with acknowledgment details:
        - comments: Optional comments about the acknowledgment
    
    Returns:
        JSON response with acknowledgment result
    """
    try:
        user_id = request.user_id
        data = request.get_json() or {}
        
        # Get the event from Firestore
        from app.firebase_config import db
        
        event_ref = db.collection('securityEvents').document(event_id)
        event_doc = event_ref.get()
        
        if not event_doc.exists:
            raise AppError('EVENT_NOT_FOUND', 'Security event not found')
        
        # Update the event with acknowledgment
        acknowledgment_data = {
            'response.acknowledged': True,
            'response.acknowledgedBy': user_id,
            'response.acknowledgedAt': datetime.utcnow().isoformat(),
            'response.comments': data.get('comments', '')
        }
        
        event_ref.update(acknowledgment_data)
        
        # Log audit event
        audit_logger.log_event(
            event_type='security_event_acknowledged',
            user_id=user_id,
            action='acknowledge_security_event',
            resource='security_event',
            result='success',
            details={
                'event_id': event_id,
                'comments': data.get('comments', '')
            }
        )
        
        return jsonify({
            'success': True,
            'message': 'Security event acknowledged successfully',
            'event_id': event_id,
            'acknowledged_by': user_id,
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except AppError:
        raise
    except Exception as e:
        logger.error(f"Error acknowledging security event: {str(e)}")
        raise AppError('ACKNOWLEDGMENT_ERROR', 'Failed to acknowledge security event')


@security_bp.route('/status', methods=['GET'])
@require_auth
@require_role(['admin'])
def get_security_status():
    """
    Get overall security system status
    
    Returns:
        JSON response with system status information
    """
    try:
        user_id = request.user_id
        
        # Get WebSocket statistics
        from websocket_config import get_websocket_stats
        ws_stats = get_websocket_stats()
        
        # Get processing statistics
        metrics = realtime_event_processor.get_activity_metrics()
        
        # Get recent alerts
        recent_alerts = realtime_event_processor.get_alert_history(limit=10)
        
        # Calculate status
        status = {
            'overall_status': 'healthy',
            'websocket_connections': ws_stats.get('total_connections', 0),
            'active_users': ws_stats.get('unique_users', 0),
            'total_events_today': metrics.get('total_events', 0),
            'critical_alerts_count': len([a for a in recent_alerts if a.get('severity') == 'critical']),
            'high_alerts_count': len([a for a in recent_alerts if a.get('severity') == 'high']),
            'event_processor_running': realtime_event_processor.is_running,
            'last_updated': datetime.utcnow().isoformat()
        }
        
        # Determine overall status
        if status['critical_alerts_count'] > 5:
            status['overall_status'] = 'critical'
        elif status['high_alerts_count'] > 10:
            status['overall_status'] = 'warning'
        elif not status['event_processor_running']:
            status['overall_status'] = 'degraded'
        
        # Log audit event
        audit_logger.log_event(
            event_type='security_status_check',
            user_id=user_id,
            action='get_security_status',
            resource='security_system',
            result='success',
            details={
                'overall_status': status['overall_status'],
                'active_connections': status['websocket_connections']
            }
        )
        
        return jsonify({
            'success': True,
            'status': status,
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting security status: {str(e)}")
        raise AppError('STATUS_ERROR', 'Failed to retrieve security status')


# Error handlers for this blueprint
@security_bp.errorhandler(AppError)
def handle_app_error(error):
    """Handle application errors for security routes"""
    return jsonify({
        'success': False,
        'error': {
            'code': error.code,
            'message': error.message
        }
    }), error.status_code


@security_bp.errorhandler(404)
def handle_not_found(error):
    """Handle 404 errors for security routes"""
    return jsonify({
        'success': False,
        'error': {
            'code': 'ENDPOINT_NOT_FOUND',
            'message': 'Security endpoint not found'
        }
    }), 404


@security_bp.errorhandler(405)
def handle_method_not_allowed(error):
    """Handle 405 errors for security routes"""
    return jsonify({
        'success': False,
        'error': {
            'code': 'METHOD_NOT_ALLOWED',
            'message': 'HTTP method not allowed for this security endpoint'
        }
    }), 405