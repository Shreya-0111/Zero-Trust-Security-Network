"""
Threat Prediction and Automated Response Routes
Handles threat prediction, detection, and automated response endpoints
"""

from flask import Blueprint, request, jsonify
from functools import wraps
import os
import asyncio
from app.services.threat_predictor import threat_predictor
from app.services.automated_threat_response import automated_threat_response
from app.models.threat_prediction import ThreatPrediction, ThreatIndicator
from app.services.audit_logger import log_audit_event
from app.tasks.automated_threat_detection_tasks import (
    run_automated_threat_detection_cycle,
    detect_device_based_threats,
    detect_coordinated_attacks
)

threat_bp = Blueprint('threat', __name__, url_prefix='/api/threat')

# Compatibility routes for frontend expectations
bp = Blueprint('threats', __name__, url_prefix='/api/threats')

# Check if threat prediction is enabled
THREAT_PREDICTION_ENABLED = os.getenv('THREAT_PREDICTION_ENABLED', 'false').lower() == 'true'


@bp.route('/predictions', methods=['GET'])
def get_threat_predictions_compat():
    """Compatibility endpoint: frontend expects GET /api/threats/predictions"""
    try:
        if not THREAT_PREDICTION_ENABLED:
            return jsonify({
                'success': True,
                'predictions': [],
                'count': 0,
                'enabled': False
            }), 200

        predictions = threat_predictor.predict_threats(user_id=None)
        return jsonify({
            'success': True,
            'predictions': predictions,
            'count': len(predictions),
            'enabled': True
        }), 200
    except Exception as e:
        print(f"Error getting predictions: {e}")
        return jsonify({
            'success': False,
            'message': 'Internal server error'
        }), 500

def require_threat_enabled(f):
    """Decorator to check if threat prediction is enabled"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not THREAT_PREDICTION_ENABLED:
            return jsonify({
                'success': False,
                'message': 'Threat prediction is not enabled'
            }), 403
        return f(*args, **kwargs)
    return decorated_function


@threat_bp.route('/predict', methods=['POST'])
@require_threat_enabled
def predict_threats():
    """Generate threat predictions"""
    try:
        data = request.get_json() or {}
        user_id = data.get('user_id')
        
        # Generate predictions
        predictions = threat_predictor.predict_threats(user_id=user_id)
        
        # Send admin alerts for high confidence predictions
        for prediction in predictions:
            if prediction.get('confidence', 0) >= 0.80:
                threat_predictor.send_admin_alert(prediction)
        
        return jsonify({
            'success': True,
            'predictions': predictions,
            'count': len(predictions)
        }), 200
        
    except Exception as e:
        print(f"Error predicting threats: {e}")
        return jsonify({
            'success': False,
            'message': 'Internal server error'
        }), 500


@threat_bp.route('/analyze/<user_id>', methods=['GET'])
@require_threat_enabled
def analyze_user_patterns(user_id):
    """Analyze user access patterns for threat indicators"""
    try:
        # Analyze patterns
        analysis = threat_predictor.analyze_patterns(user_id)
        
        # Save indicators if found
        if analysis.get('patterns_found'):
            for indicator in analysis.get('indicators', []):
                threat_indicator = ThreatIndicator(
                    user_id=user_id,
                    indicator_type=indicator.get('type'),
                    severity=indicator.get('severity'),
                    value=indicator.get('value'),
                    description=indicator.get('description')
                )
                threat_indicator.save()
        
        return jsonify({
            'success': True,
            'analysis': analysis
        }), 200
        
    except Exception as e:
        print(f"Error analyzing patterns: {e}")
        return jsonify({
            'success': False,
            'message': 'Internal server error'
        }), 500


@threat_bp.route('/detect/brute-force', methods=['POST'])
@require_threat_enabled
def detect_brute_force():
    """Detect brute force attacks"""
    try:
        data = request.get_json() or {}
        user_id = data.get('user_id')
        ip_address = data.get('ip_address')
        
        detection = threat_predictor.detect_brute_force(
            user_id=user_id,
            ip_address=ip_address
        )
        
        if detection:
            log_audit_event(
                user_id=user_id or 'system',
                action='brute_force_detected',
                resource_type='security_threat',
                resource_id='brute_force',
                details=detection,
                severity='high'
            )
        
        return jsonify({
            'success': True,
            'detected': detection is not None,
            'detection': detection
        }), 200
        
    except Exception as e:
        print(f"Error detecting brute force: {e}")
        return jsonify({
            'success': False,
            'message': 'Internal server error'
        }), 500


@threat_bp.route('/detect/privilege-escalation/<user_id>', methods=['GET'])
@require_threat_enabled
def detect_privilege_escalation(user_id):
    """Detect privilege escalation attempts"""
    try:
        detection = threat_predictor.detect_privilege_escalation(user_id)
        
        if detection:
            log_audit_event(
                user_id=user_id,
                action='privilege_escalation_detected',
                resource_type='security_threat',
                resource_id='privilege_escalation',
                details=detection,
                severity='high'
            )
        
        return jsonify({
            'success': True,
            'detected': detection is not None,
            'detection': detection
        }), 200
        
    except Exception as e:
        print(f"Error detecting privilege escalation: {e}")
        return jsonify({
            'success': False,
            'message': 'Internal server error'
        }), 500


@threat_bp.route('/detect/coordinated', methods=['GET'])
@require_threat_enabled
def detect_coordinated_attack():
    """Detect coordinated attacks"""
    try:
        detection = threat_predictor.detect_coordinated_attack()
        
        if detection:
            log_audit_event(
                user_id='system',
                action='coordinated_attack_detected',
                resource_type='security_threat',
                resource_id='coordinated_attack',
                details=detection,
                severity='critical'
            )
        
        return jsonify({
            'success': True,
            'detected': detection is not None,
            'detection': detection
        }), 200
        
    except Exception as e:
        print(f"Error detecting coordinated attack: {e}")
        return jsonify({
            'success': False,
            'message': 'Internal server error'
        }), 500


@threat_bp.route('/detect/all', methods=['POST'])
@require_threat_enabled
def run_all_detections():
    """Run all threat detection algorithms"""
    try:
        data = request.get_json() or {}
        user_id = data.get('user_id')
        
        detections = threat_predictor.run_all_detections(user_id=user_id)
        
        return jsonify({
            'success': True,
            'detections': detections,
            'count': len(detections)
        }), 200
        
    except Exception as e:
        print(f"Error running detections: {e}")
        return jsonify({
            'success': False,
            'message': 'Internal server error'
        }), 500


@threat_bp.route('/prediction/<prediction_id>', methods=['GET'])
@require_threat_enabled
def get_prediction(prediction_id):
    """Get threat prediction by ID"""
    try:
        prediction = ThreatPrediction.get_by_id(prediction_id)
        
        if not prediction:
            return jsonify({
                'success': False,
                'message': 'Prediction not found'
            }), 404
        
        return jsonify({
            'success': True,
            'prediction': prediction.to_dict()
        }), 200
        
    except Exception as e:
        print(f"Error getting prediction: {e}")
        return jsonify({
            'success': False,
            'message': 'Internal server error'
        }), 500


@threat_bp.route('/prediction/<prediction_id>/outcome', methods=['POST'])
@require_threat_enabled
def track_prediction_outcome(prediction_id):
    """Track the outcome of a threat prediction"""
    try:
        data = request.get_json()
        outcome = data.get('outcome')
        notes = data.get('notes')
        
        if outcome not in ['confirmed', 'false_positive', 'prevented']:
            return jsonify({
                'success': False,
                'message': 'Invalid outcome. Must be: confirmed, false_positive, or prevented'
            }), 400
        
        success = threat_predictor.track_prediction_outcome(
            prediction_id=prediction_id,
            outcome=outcome,
            notes=notes
        )
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Prediction outcome tracked successfully'
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to track prediction outcome'
            }), 400
        
    except Exception as e:
        print(f"Error tracking outcome: {e}")
        return jsonify({
            'success': False,
            'message': 'Internal server error'
        }), 500


@threat_bp.route('/accuracy', methods=['GET'])
@require_threat_enabled
def get_prediction_accuracy():
    """Get prediction accuracy metrics"""
    try:
        days = request.args.get('days', 30, type=int)
        
        accuracy = threat_predictor.calculate_prediction_accuracy(days=days)
        
        return jsonify({
            'success': True,
            'accuracy': accuracy
        }), 200
        
    except Exception as e:
        print(f"Error getting accuracy: {e}")
        return jsonify({
            'success': False,
            'message': 'Internal server error'
        }), 500


@threat_bp.route('/statistics', methods=['GET'])
@require_threat_enabled
def get_statistics():
    """Get threat prediction statistics"""
    try:
        stats = threat_predictor.get_prediction_statistics()
        
        return jsonify({
            'success': True,
            'statistics': stats
        }), 200
        
    except Exception as e:
        print(f"Error getting statistics: {e}")
        return jsonify({
            'success': False,
            'message': 'Internal server error'
        }), 500


@threat_bp.route('/predictions/pending', methods=['GET'])
@require_threat_enabled
def get_pending_predictions():
    """Get pending threat predictions"""
    try:
        limit = request.args.get('limit', 50, type=int)
        
        predictions = ThreatPrediction.get_pending_predictions(limit=limit)
        
        prediction_list = [p.to_dict() for p in predictions]
        
        return jsonify({
            'success': True,
            'predictions': prediction_list,
            'count': len(prediction_list)
        }), 200
        
    except Exception as e:
        print(f"Error getting pending predictions: {e}")
        return jsonify({
            'success': False,
            'message': 'Internal server error'
        }), 500


@threat_bp.route('/predictions/user/<user_id>', methods=['GET'])
@require_threat_enabled
def get_user_predictions(user_id):
    """Get threat predictions for a user"""
    try:
        limit = request.args.get('limit', 10, type=int)
        
        predictions = ThreatPrediction.get_by_user_id(user_id, limit=limit)
        
        prediction_list = [p.to_dict() for p in predictions]
        
        return jsonify({
            'success': True,
            'predictions': prediction_list,
            'count': len(prediction_list)
        }), 200
        
    except Exception as e:
        print(f"Error getting user predictions: {e}")
        return jsonify({
            'success': False,
            'message': 'Internal server error'
        }), 500


@threat_bp.route('/indicators/active', methods=['GET'])
@require_threat_enabled
def get_active_indicators():
    """Get active threat indicators"""
    try:
        user_id = request.args.get('user_id')
        limit = request.args.get('limit', 50, type=int)
        
        indicators = ThreatIndicator.get_active_indicators(
            user_id=user_id,
            limit=limit
        )
        
        indicator_list = [i.to_dict() for i in indicators]
        
        return jsonify({
            'success': True,
            'indicators': indicator_list,
            'count': len(indicator_list)
        }), 200
        
    except Exception as e:
        print(f"Error getting active indicators: {e}")
        return jsonify({
            'success': False,
            'message': 'Internal server error'
        }), 500


@threat_bp.route('/status', methods=['GET'])
def get_threat_status():
    """Get threat prediction status"""
    return jsonify({
        'success': True,
        'enabled': THREAT_PREDICTION_ENABLED,
        'features': {
            'pattern_analysis': THREAT_PREDICTION_ENABLED,
            'threat_prediction': THREAT_PREDICTION_ENABLED,
            'brute_force_detection': THREAT_PREDICTION_ENABLED,
            'privilege_escalation_detection': THREAT_PREDICTION_ENABLED,
            'coordinated_attack_detection': THREAT_PREDICTION_ENABLED,
            'prediction_tracking': THREAT_PREDICTION_ENABLED,
            'automated_response': THREAT_PREDICTION_ENABLED
        }
    }), 200


# ==================== Automated Threat Detection and Response Routes ====================

@threat_bp.route('/automated/detection-cycle', methods=['POST'])
@require_threat_enabled
def trigger_automated_detection():
    """Manually trigger automated threat detection cycle"""
    try:
        # Trigger the Celery task
        task = run_automated_threat_detection_cycle.delay()
        
        return jsonify({
            'success': True,
            'message': 'Automated threat detection cycle triggered',
            'task_id': task.id
        }), 200
        
    except Exception as e:
        print(f"Error triggering automated detection: {e}")
        return jsonify({
            'success': False,
            'message': 'Failed to trigger automated detection'
        }), 500


@threat_bp.route('/automated/device-threats', methods=['POST'])
@require_threat_enabled
def detect_device_threats():
    """Detect device-based threats"""
    try:
        data = request.get_json() or {}
        device_fingerprint = data.get('device_fingerprint')
        
        # Run detection synchronously for immediate response
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            threats = loop.run_until_complete(
                automated_threat_response.detect_multiple_failed_attempts(device_fingerprint)
            )
        finally:
            loop.close()
        
        return jsonify({
            'success': True,
            'threats_detected': len(threats),
            'threats': threats
        }), 200
        
    except Exception as e:
        print(f"Error detecting device threats: {e}")
        return jsonify({
            'success': False,
            'message': 'Internal server error'
        }), 500


@threat_bp.route('/automated/coordinated-attacks', methods=['POST'])
@require_threat_enabled
def detect_coordinated_attack_threats():
    """Detect coordinated attack threats"""
    try:
        # Run detection synchronously for immediate response
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            attacks = loop.run_until_complete(
                automated_threat_response.detect_coordinated_attacks()
            )
        finally:
            loop.close()
        
        return jsonify({
            'success': True,
            'attacks_detected': len(attacks),
            'attacks': attacks
        }), 200
        
    except Exception as e:
        print(f"Error detecting coordinated attacks: {e}")
        return jsonify({
            'success': False,
            'message': 'Internal server error'
        }), 500


@threat_bp.route('/automated/blocked-devices', methods=['GET'])
@require_threat_enabled
def get_blocked_devices():
    """Get list of blocked device fingerprints"""
    try:
        blocked_devices = automated_threat_response.get_blocked_devices()
        
        return jsonify({
            'success': True,
            'blocked_devices': blocked_devices,
            'count': len(blocked_devices)
        }), 200
        
    except Exception as e:
        print(f"Error getting blocked devices: {e}")
        return jsonify({
            'success': False,
            'message': 'Internal server error'
        }), 500


@threat_bp.route('/automated/locked-segments', methods=['GET'])
@require_threat_enabled
def get_locked_segments():
    """Get list of locked resource segments"""
    try:
        locked_segments = automated_threat_response.get_locked_segments()
        
        return jsonify({
            'success': True,
            'locked_segments': locked_segments,
            'count': len(locked_segments)
        }), 200
        
    except Exception as e:
        print(f"Error getting locked segments: {e}")
        return jsonify({
            'success': False,
            'message': 'Internal server error'
        }), 500


@threat_bp.route('/automated/unblock-device', methods=['POST'])
@require_threat_enabled
def unblock_device():
    """Manually unblock a device fingerprint"""
    try:
        data = request.get_json()
        device_fingerprint = data.get('device_fingerprint')
        admin_user_id = data.get('admin_user_id')
        
        if not device_fingerprint or not admin_user_id:
            return jsonify({
                'success': False,
                'message': 'device_fingerprint and admin_user_id are required'
            }), 400
        
        # Run unblock operation
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            success = loop.run_until_complete(
                automated_threat_response.unblock_device(device_fingerprint, admin_user_id)
            )
        finally:
            loop.close()
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Device unblocked successfully'
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to unblock device'
            }), 400
        
    except Exception as e:
        print(f"Error unblocking device: {e}")
        return jsonify({
            'success': False,
            'message': 'Internal server error'
        }), 500


@threat_bp.route('/automated/unlock-segment', methods=['POST'])
@require_threat_enabled
def unlock_resource_segment():
    """Manually unlock a resource segment"""
    try:
        data = request.get_json()
        segment_id = data.get('segment_id')
        admin_user_id = data.get('admin_user_id')
        
        if not segment_id or not admin_user_id:
            return jsonify({
                'success': False,
                'message': 'segment_id and admin_user_id are required'
            }), 400
        
        # Run unlock operation
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            success = loop.run_until_complete(
                automated_threat_response.unlock_resource_segment(segment_id, admin_user_id)
            )
        finally:
            loop.close()
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Resource segment unlocked successfully'
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to unlock resource segment'
            }), 400
        
    except Exception as e:
        print(f"Error unlocking resource segment: {e}")
        return jsonify({
            'success': False,
            'message': 'Internal server error'
        }), 500


@threat_bp.route('/automated/status', methods=['GET'])
@require_threat_enabled
def get_automated_threat_status():
    """Get automated threat detection system status"""
    try:
        blocked_devices = automated_threat_response.get_blocked_devices()
        locked_segments = automated_threat_response.get_locked_segments()
        
        # Get recent detection statistics
        from app.firebase_config import db
        from datetime import datetime, timedelta
        
        cutoff_time = datetime.utcnow() - timedelta(hours=24)
        
        # Count recent security alerts
        alerts_query = db.collection('security_alerts')\
                        .where('timestamp', '>=', cutoff_time)
        
        recent_alerts = len(list(alerts_query.stream()))
        
        # Count recent threat predictions
        predictions_query = db.collection('threat_predictions')\
                           .where('predicted_at', '>=', cutoff_time)
        
        recent_predictions = len(list(predictions_query.stream()))
        
        return jsonify({
            'success': True,
            'status': {
                'system_active': True,
                'blocked_devices_count': len(blocked_devices),
                'locked_segments_count': len(locked_segments),
                'recent_alerts_24h': recent_alerts,
                'recent_predictions_24h': recent_predictions,
                'detection_thresholds': {
                    'failed_attempts': automated_threat_response.failed_attempt_threshold,
                    'time_window_minutes': automated_threat_response.time_window_minutes,
                    'coordinated_attack_users': automated_threat_response.coordinated_attack_threshold
                }
            }
        }), 200
        
    except Exception as e:
        print(f"Error getting automated threat status: {e}")
        return jsonify({
            'success': False,
            'message': 'Internal server error'
        }), 500
