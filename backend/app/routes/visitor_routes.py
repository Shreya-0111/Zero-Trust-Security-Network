"""
Visitor Routes

API endpoints for visitor management including registration, session management,
route tracking, and compliance monitoring.
"""

import logging
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename
from functools import wraps
import inspect

from ..services.visitor_service import visitor_service
from ..models.visitor import VisitorRegistrationRequest, VisitorUpdateRequest
from ..middleware.authorization import require_auth, require_role
from ..utils.error_handler import ValidationError, NotFoundError, AuthorizationError

logger = logging.getLogger(__name__)

visitor_bp = Blueprint('visitor', __name__, url_prefix='/api/visitors')


def handle_visitor_errors(f):
    """Decorator to handle visitor service errors"""
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        try:
            if inspect.iscoroutinefunction(f):
                return await f(*args, **kwargs)
            return f(*args, **kwargs)
        except ValidationError as e:
            logger.warning(f"Validation error in {f.__name__}: {str(e)}")
            return jsonify({'error': str(e)}), 400
        except NotFoundError as e:
            logger.warning(f"Not found error in {f.__name__}: {str(e)}")
            return jsonify({'error': str(e)}), 404
        except AuthorizationError as e:
            logger.warning(f"Permission error in {f.__name__}: {str(e)}")
            return jsonify({'error': str(e)}), 403
        except Exception as e:
            logger.error(f"Unexpected error in {f.__name__}: {str(e)}")
            return jsonify({'error': 'Internal server error'}), 500
    
    return decorated_function


@visitor_bp.route('/register', methods=['POST'])
@require_auth
@require_role(['faculty', 'admin'])
@handle_visitor_errors
async def register_visitor():
    """
    Register a new visitor
    
    Requires faculty or admin role. Accepts multipart form data with visitor
    information and photo upload.
    
    Returns:
        JSON response with visitor data and credentials
    """
    try:
        print(f"📝 Visitor registration request from user: {request.user_id} ({request.user_role})")
        print(f"📝 Request files: {list(request.files.keys())}")
        print(f"📝 Request form: {list(request.form.keys())}")
        
        # Get visitor data from form
        visitor_data_json = request.form.get('visitorData')
        if not visitor_data_json:
            print("❌ Missing visitorData in form")
            return jsonify({'error': 'Visitor data is required'}), 400
        
        print(f"📝 Visitor data length: {len(visitor_data_json)} characters")
        
        import json
        try:
            visitor_data = json.loads(visitor_data_json)
            print(f"📝 Parsed visitor data: {visitor_data.get('name', 'Unknown')}")
        except json.JSONDecodeError as e:
            print(f"❌ JSON decode error: {str(e)}")
            return jsonify({'error': 'Invalid visitor data format'}), 400
        
        # Get photo file
        if 'photo' not in request.files:
            print("❌ No photo file in request")
            return jsonify({'error': 'Visitor photo is required'}), 400
        
        photo_file = request.files['photo']
        if photo_file.filename == '':
            print("❌ Empty photo filename")
            return jsonify({'error': 'No photo file selected'}), 400
        
        print(f"📸 Photo file: {photo_file.filename}, size: {photo_file.content_length}")
        
        # Validate file type
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
        if not ('.' in photo_file.filename and 
                photo_file.filename.rsplit('.', 1)[1].lower() in allowed_extensions):
            print(f"❌ Invalid file type: {photo_file.filename}")
            return jsonify({'error': 'Invalid photo file type. Allowed: PNG, JPG, JPEG, GIF'}), 400
        
        # Validate file size (max 10MB)
        if photo_file.content_length and photo_file.content_length > 10 * 1024 * 1024:
            print(f"❌ File too large: {photo_file.content_length} bytes")
            return jsonify({'error': 'Photo file size must be less than 10MB'}), 400
        
        # Create registration request
        registration_request = VisitorRegistrationRequest(**visitor_data)
        print(f"📝 Registration request created for: {registration_request.name}")
        
        # Register visitor
        print("🚀 Starting visitor registration...")
        visitor = await visitor_service.register_visitor(
            registration_request,
            photo_file,
            request.user_id
        )
        
        print(f"✅ Visitor {visitor.visitor_id} registered successfully")
        logger.info(f"Visitor {visitor.visitor_id} registered by user {request.user_id}")
        
        return jsonify({
            'success': True,
            'message': 'Visitor registered successfully',
            'visitor': visitor.to_dict()
        }), 201
        
    except json.JSONDecodeError:
        print("❌ JSON decode error in visitor data")
        return jsonify({'error': 'Invalid visitor data format'}), 400
    except Exception as e:
        print(f"❌ Registration error: {str(e)}")
        logger.error(f"Error in visitor registration: {str(e)}")
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500


@visitor_bp.route('/<visitor_id>', methods=['GET'])
@require_auth
@handle_visitor_errors
async def get_visitor(visitor_id):
    """
    Get visitor information
    
    Returns visitor data if user has permission (host or admin).
    
    Args:
        visitor_id: Visitor ID to retrieve
        
    Returns:
        JSON response with visitor data
    """
    visitor = await visitor_service.get_visitor(visitor_id, request.user_id)
    
    return jsonify({
        'success': True,
        'visitor': visitor.to_dict()
    })


@visitor_bp.route('/host/<host_id>', methods=['GET'])
@require_auth
@handle_visitor_errors
async def get_host_visitors(host_id):
    """
    Get all visitors for a specific host
    
    Args:
        host_id: Host user ID
        
    Query Parameters:
        status: Optional status filter ('active', 'completed', 'expired', 'terminated')
        
    Returns:
        JSON response with list of visitors
    """
    # Validate that user can access this host's visitors
    if request.user_id != host_id and request.user_role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    status_filter = request.args.get('status')
    visitors = await visitor_service.get_host_visitors(host_id, status_filter)
    
    return jsonify({
        'success': True,
        'visitors': [visitor.to_dict() for visitor in visitors],
        'count': len(visitors)
    })


@visitor_bp.route('/<visitor_id>/access', methods=['POST'])
@require_auth
@handle_visitor_errors
async def track_visitor_access(visitor_id):
    """
    Track visitor access to resources
    
    Args:
        visitor_id: Visitor ID
        
    Request Body:
        resource_segment: Resource segment being accessed
        action: Action being performed
        risk_score: Optional risk score for the access
        
    Returns:
        JSON response with access approval status
    """
    data = request.get_json()
    
    if not data or 'resource_segment' not in data or 'action' not in data:
        return jsonify({'error': 'Resource segment and action are required'}), 400
    
    resource_segment = data['resource_segment']
    action = data['action']
    risk_score = data.get('risk_score')
    
    approved = await visitor_service.track_visitor_access(
        visitor_id,
        resource_segment,
        action,
        request.user_id,
        risk_score
    )
    
    return jsonify({
        'success': True,
        'approved': approved,
        'message': 'Access approved' if approved else 'Access denied - route violation'
    })


@visitor_bp.route('/<visitor_id>/extend', methods=['POST'])
@require_auth
@handle_visitor_errors
async def extend_visitor_session(visitor_id):
    """
    Extend visitor session
    
    Requires host to request and admin to approve.
    
    Args:
        visitor_id: Visitor ID
        
    Request Body:
        additional_hours: Additional hours to grant (1-4)
        reason: Reason for extension
        approving_admin_id: Admin ID approving the extension
        
    Returns:
        JSON response with updated visitor data
    """
    data = request.get_json()
    
    if not data or 'additional_hours' not in data or 'reason' not in data or 'approving_admin_id' not in data:
        return jsonify({'error': 'Additional hours, reason, and approving admin ID are required'}), 400
    
    additional_hours = data['additional_hours']
    reason = data['reason']
    approving_admin_id = data['approving_admin_id']
    
    # Validate additional hours
    if not isinstance(additional_hours, int) or additional_hours < 1 or additional_hours > 4:
        return jsonify({'error': 'Additional hours must be between 1 and 4'}), 400
    
    # Validate reason length
    if len(reason.strip()) < 10:
        return jsonify({'error': 'Reason must be at least 10 characters'}), 400
    
    visitor = await visitor_service.extend_visitor_session(
        visitor_id,
        additional_hours,
        reason,
        request.user_id,  # requesting host
        approving_admin_id
    )
    
    return jsonify({
        'success': True,
        'message': f'Visitor session extended by {additional_hours} hours',
        'visitor': visitor.to_dict()
    })


@visitor_bp.route('/<visitor_id>/terminate', methods=['POST'])
@require_auth
@handle_visitor_errors
async def terminate_visitor_session(visitor_id):
    """
    Terminate visitor session
    
    Can be called by host or admin.
    
    Args:
        visitor_id: Visitor ID
        
    Request Body:
        reason: Reason for termination
        
    Returns:
        JSON response with updated visitor data
    """
    data = request.get_json()
    
    if not data or 'reason' not in data:
        return jsonify({'error': 'Termination reason is required'}), 400
    
    reason = data['reason']
    
    if len(reason.strip()) < 5:
        return jsonify({'error': 'Termination reason must be at least 5 characters'}), 400
    
    visitor = await visitor_service.terminate_visitor_session(
        visitor_id,
        reason,
        request.user_id
    )
    
    return jsonify({
        'success': True,
        'message': 'Visitor session terminated successfully',
        'visitor': visitor.to_dict()
    })


@visitor_bp.route('/<visitor_id>/compliance-report', methods=['GET'])
@require_auth
@handle_visitor_errors
async def get_visitor_compliance_report(visitor_id):
    """
    Get compliance report for a visitor
    
    Args:
        visitor_id: Visitor ID
        
    Returns:
        JSON response with detailed compliance report
    """
    report = await visitor_service.get_visitor_compliance_report(visitor_id, request.user_id)
    
    return jsonify({
        'success': True,
        'report': report
    })


@visitor_bp.route('/expired/check', methods=['POST'])
@require_auth
@require_role(['admin'])
@handle_visitor_errors
async def check_expired_sessions():
    """
    Check for and auto-terminate expired visitor sessions
    
    Admin-only endpoint for manual triggering of expiration check.
    
    Returns:
        JSON response with list of terminated visitor IDs
    """
    expired_visitors = await visitor_service.check_expired_sessions()
    
    return jsonify({
        'success': True,
        'message': f'Checked expired sessions, terminated {len(expired_visitors)} visitors',
        'terminated_visitors': expired_visitors
    })


@visitor_bp.route('/active', methods=['GET'])
@require_auth
@require_role(['admin'])
@handle_visitor_errors
async def get_all_active_visitors():
    """
    Get all active visitors (admin only)
    
    Returns:
        JSON response with list of all active visitors
    """
    from app.firebase_config import get_firestore_client

    db = get_firestore_client()
    if not db:
        return jsonify({
            'success': True,
            'visitors': [],
            'count': 0
        })

    query = db.collection('visitors').where('status', '==', 'active')
    docs = query.stream()
    
    visitors = []
    for doc in docs:
        visitor_data = doc.to_dict()
        from ..models.visitor import Visitor
        visitor = Visitor(**visitor_data)
        visitors.append(visitor.to_dict())
    
    return jsonify({
        'success': True,
        'visitors': visitors,
        'count': len(visitors)
    })


@visitor_bp.route('/<visitor_id>/compliance/monitor', methods=['POST'])
@require_auth
@handle_visitor_errors
async def monitor_visitor_compliance(visitor_id):
    """
    Monitor visitor route compliance for specific access attempt
    
    Args:
        visitor_id: Visitor ID
        
    Request Body:
        resource_segment: Resource segment being accessed
        action: Action being performed
        location_data: Optional location/context data
        
    Returns:
        JSON response with compliance analysis
    """
    data = request.get_json()
    
    if not data or 'resource_segment' not in data or 'action' not in data:
        return jsonify({'error': 'Resource segment and action are required'}), 400
    
    resource_segment = data['resource_segment']
    action = data['action']
    location_data = data.get('location_data')
    
    from ..services.route_compliance_service import route_compliance_service
    
    compliance_result = await route_compliance_service.monitor_visitor_access(
        visitor_id,
        resource_segment,
        action,
        location_data
    )
    
    return jsonify({
        'success': True,
        'compliance_result': compliance_result
    })


@visitor_bp.route('/<visitor_id>/compliance/status', methods=['GET'])
@require_auth
@handle_visitor_errors
async def get_visitor_compliance_status(visitor_id):
    """
    Get real-time compliance status for a visitor
    
    Args:
        visitor_id: Visitor ID
        
    Returns:
        JSON response with current compliance status and metrics
    """
    from ..services.route_compliance_service import route_compliance_service
    
    status = await route_compliance_service.get_real_time_compliance_status(visitor_id)
    
    return jsonify({
        'success': True,
        'status': status
    })


@visitor_bp.route('/compliance/dashboard', methods=['GET'])
@require_auth
@handle_visitor_errors
async def get_compliance_dashboard():
    """
    Get compliance dashboard data
    
    Query Parameters:
        host_id: Optional host ID to filter visitors
        
    Returns:
        JSON response with dashboard metrics and data
    """
    host_id = request.args.get('host_id')
    
    # If not admin, can only view own visitors
    if request.user_role != 'admin' and host_id != request.user_id:
        host_id = request.user_id
    
    from ..services.route_compliance_service import route_compliance_service
    
    dashboard_data = await route_compliance_service.get_compliance_dashboard_data(host_id)
    
    return jsonify({
        'success': True,
        'dashboard': dashboard_data
    })


@visitor_bp.route('/compliance/alerts', methods=['GET'])
@require_auth
@require_role(['admin'])
@handle_visitor_errors
async def get_compliance_alerts():
    """
    Get recent compliance alerts (admin only)
    
    Query Parameters:
        limit: Maximum number of alerts to return (default: 50)
        severity: Filter by severity (critical, high, medium, low)
        
    Returns:
        JSON response with list of compliance alerts
    """
    try:
        limit = int(request.args.get('limit', 50))
        severity_filter = request.args.get('severity')

        from app.firebase_config import get_firestore_client

        db = get_firestore_client()
        if not db:
            return jsonify({
                'success': True,
                'alerts': [],
                'count': 0
            })
        
        # Build query
        from google.cloud.firestore_v1 import Query
        query = db.collection('compliance_alerts').order_by('timestamp', direction=Query.DESCENDING)
        
        if severity_filter:
            query = query.where('severity', '==', severity_filter)
        
        # Limit results
        query = query.limit(limit)
        
        alerts = []
        docs = query.stream()
        
        for doc in docs:
            alert_data = doc.to_dict()
            alerts.append(alert_data)
        
        return jsonify({
            'success': True,
            'alerts': alerts,
            'count': len(alerts)
        })
        
    except Exception as e:
        logger.error(f"Error retrieving compliance alerts: {str(e)}")
        return jsonify({'error': 'Failed to retrieve alerts'}), 500


@visitor_bp.route('/compliance/alerts/generate', methods=['POST'])
@require_auth
@require_role(['admin'])
@handle_visitor_errors
async def generate_compliance_alerts():
    """
    Manually trigger compliance alert generation (admin only)
    
    Returns:
        JSON response with generated alerts
    """
    from ..services.route_compliance_service import route_compliance_service
    
    alerts = await route_compliance_service.generate_compliance_alerts()
    
    return jsonify({
        'success': True,
        'message': f'Generated {len(alerts)} compliance alerts',
        'alerts': alerts
    })


@visitor_bp.route('/stats', methods=['GET'])
@require_auth
@require_role(['admin', 'faculty'])
@handle_visitor_errors
async def get_visitor_stats():
    """
    Get visitor statistics
    
    Returns aggregated statistics about visitor activity.
    
    Returns:
        JSON response with visitor statistics
    """
    try:
        from app.firebase_config import get_firestore_client

        db = get_firestore_client()
        if not db:
            return jsonify({
                'success': True,
                'stats': {
                    'status_breakdown': {
                        'active': 0,
                        'completed': 0,
                        'expired': 0,
                        'terminated': 0,
                        'total': 0
                    },
                    'today_stats': {
                        'new_visitors': 0,
                        'average_compliance_score': 100
                    },
                    'generated_at': datetime.utcnow().isoformat()
                }
            })
        
        # Get current date for filtering
        now = datetime.utcnow()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        
        # Query visitors by status
        active_count = len(list(db.collection('visitors').where('status', '==', 'active').stream()))
        completed_count = len(list(db.collection('visitors').where('status', '==', 'completed').stream()))
        expired_count = len(list(db.collection('visitors').where('status', '==', 'expired').stream()))
        terminated_count = len(list(db.collection('visitors').where('status', '==', 'terminated').stream()))
        
        # Query today's visitors
        today_visitors = list(db.collection('visitors')
                            .where('entry_time', '>=', today_start)
                            .stream())
        
        # Calculate compliance metrics
        total_compliance_score = 0
        visitors_with_compliance = 0
        
        for doc in today_visitors:
            visitor_data = doc.to_dict()
            if 'route_compliance' in visitor_data:
                total_compliance_score += visitor_data['route_compliance'].get('compliance_score', 100)
                visitors_with_compliance += 1
        
        avg_compliance = (total_compliance_score / visitors_with_compliance) if visitors_with_compliance > 0 else 100
        
        stats = {
            'status_breakdown': {
                'active': active_count,
                'completed': completed_count,
                'expired': expired_count,
                'terminated': terminated_count,
                'total': active_count + completed_count + expired_count + terminated_count
            },
            'today_stats': {
                'new_visitors': len(today_visitors),
                'average_compliance_score': round(avg_compliance, 2)
            },
            'generated_at': now.isoformat()
        }
        
        return jsonify({
            'success': True,
            'stats': stats
        })
        
    except Exception as e:
        logger.error(f"Error generating visitor stats: {str(e)}")
        return jsonify({'error': 'Failed to generate statistics'}), 500


# Error handlers for the blueprint
@visitor_bp.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad request'}), 400


@visitor_bp.errorhandler(401)
def unauthorized(error):
    return jsonify({'error': 'Unauthorized'}), 401


@visitor_bp.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Forbidden'}), 403


@visitor_bp.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404


@visitor_bp.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500