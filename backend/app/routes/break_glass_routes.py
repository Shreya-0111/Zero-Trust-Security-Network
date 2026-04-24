"""
Break-Glass Emergency Access Routes

API endpoints for emergency access procedures with dual approval, comprehensive logging,
and enhanced off-hours security features.
"""

import logging
from functools import wraps
import inspect

from flask import Blueprint, request, jsonify, make_response
from datetime import datetime

from ..middleware.authorization import require_auth, require_role
from ..services.break_glass_service import get_break_glass_service
from ..services.enhanced_break_glass_service import enhanced_break_glass_service
from ..utils.error_handler import ValidationError, NotFoundError, AuthorizationError
from ..utils.async_helper import run_async
from ..firebase_config import get_firestore_client

logger = logging.getLogger(__name__)

break_glass_bp = Blueprint('break_glass', __name__, url_prefix='/api/break-glass')


def _add_cors_headers(response):
    origin = request.headers.get("Origin")
    if origin in ("http://localhost:3000", "http://127.0.0.1:3000"):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Vary"] = "Origin"
    return response


def _json_safe(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    if isinstance(value, tuple):
        return [_json_safe(v) for v in value]
    return value


def handle_break_glass_errors(f):
    """Decorator to handle break-glass service errors"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            rv = f(*args, **kwargs)
            if inspect.isawaitable(rv):
                return run_async(rv)
            return rv
        except ValidationError as e:
            logger.warning(f"Validation error in {f.__name__}: {str(e)}")
            return _add_cors_headers(make_response(jsonify({'error': str(e)}), 400))
        except NotFoundError as e:
            logger.warning(f"Not found error in {f.__name__}: {str(e)}")
            return _add_cors_headers(make_response(jsonify({'error': str(e)}), 404))
        except AuthorizationError as e:
            logger.warning(f"Permission error in {f.__name__}: {str(e)}")
            return _add_cors_headers(make_response(jsonify({'error': str(e)}), 403))
        except Exception as e:
            logger.error(f"Unexpected error in {f.__name__}: {str(e)}")
            return _add_cors_headers(make_response(jsonify({'error': 'Internal server error'}), 500))
    
    return decorated_function


@break_glass_bp.route('/emergency-request', methods=['POST'])
@require_auth
@handle_break_glass_errors
def submit_emergency_request():
    """
    Submit emergency access request requiring dual approval with off-hours security enhancements
    
    Request Body:
        emergencyType: Type of emergency (system_outage, security_incident, data_recovery, critical_maintenance)
        urgencyLevel: Urgency level (critical, high, medium)
        justification: Detailed justification (minimum 100 characters)
        requiredResources: List of resource segment IDs
        estimatedDuration: Estimated duration in hours (0.5 to 2 hours)
        
    Returns:
        JSON response with request submission result including off-hours considerations
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
            
        # Check for mandatory step-up MFA
        mfa_token = data.get('mfaToken')
        if not mfa_token:
            return jsonify({'error': 'Step-up MFA token is required for break-glass emergency requests'}), 401
            
        # Basic validation placeholder (would integrate with real MFA service)
        if mfa_token == "invalid":
            return jsonify({'error': 'Invalid MFA token'}), 401
        
        # Validate required fields
        required_fields = ['emergencyType', 'urgencyLevel', 'justification', 'requiredResources', 'estimatedDuration']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'{field} is required'}), 400
        
        # Add requester ID from authenticated user
        request_data = {
            'requesterId': request.user_id,
            'emergencyType': data['emergencyType'],
            'urgencyLevel': data['urgencyLevel'],
            'justification': data['justification'],
            'requiredResources': data['requiredResources'],
            'estimatedDuration': data['estimatedDuration']
        }
        
        # Use enhanced break-glass service for off-hours security
        result = run_async(enhanced_break_glass_service.submit_emergency_request(request_data))
        
        if result['success']:
            return jsonify(result), 201
        else:
            return jsonify({'error': result['error']}), 400
        
    except Exception as e:
        logger.error(f"Error submitting emergency request: {str(e)}")
        return jsonify({'error': str(e)}), 500


@break_glass_bp.route('/available-administrators', methods=['GET'])
@require_auth
@handle_break_glass_errors
def get_available_administrators():
    """
    Get list of available administrators for emergency approval
    
    Returns:
        JSON response with list of available administrators
    """
    try:
        # Get service instance
        db = get_firestore_client()
        service = get_break_glass_service(db)
        
        # Get available administrators
        administrators = run_async(service.get_available_administrators())
        
        return jsonify({
            'success': True,
            'administrators': administrators,
            'count': len(administrators)
        })
        
    except Exception as e:
        logger.error(f"Error getting available administrators: {str(e)}")
        return jsonify({'error': str(e)}), 500


@break_glass_bp.route('/my-requests', methods=['GET'])
@require_auth
@handle_break_glass_errors
def get_my_emergency_requests():
    """
    Get emergency requests submitted by the current user
    
    Returns:
        JSON response with list of user's emergency requests
    """
    try:
        db = get_firestore_client()
        
        # Query requests where requesterId matches current user
        requests_ref = db.collection('breakGlassRequests')
        query = requests_ref.where('requesterId', '==', request.user_id).limit(50)
        
        requests = []
        for doc in query.stream():
            req_data = doc.to_dict()
            req_data['id'] = doc.id
            requests.append(req_data)
        
        # Sort in memory by requestedAt descending
        requests.sort(key=lambda x: x.get('requestedAt', ''), reverse=True)
        # Limit to 20 after sorting
        requests = requests[:20]

            
        return _add_cors_headers(make_response(jsonify({
            'success': True,
            'requests': _json_safe(requests),
            'count': len(requests)
        })))
        
    except Exception as e:
        logger.error(f"Error getting my emergency requests: {str(e)}")
        return _add_cors_headers(make_response(jsonify({'error': str(e)}), 500))


@break_glass_bp.route('/pending-requests', methods=['GET'])

@require_auth
@require_role(['admin'])
@handle_break_glass_errors
def get_pending_emergency_requests():
    """
    Get pending emergency requests for administrator review
    
    Returns:
        JSON response with list of pending emergency requests
    """
    try:
        # Get service instance
        db = get_firestore_client()
        service = get_break_glass_service(db)
        
        # Get pending requests for this administrator
        pending_requests = run_async(service.get_pending_emergency_requests(request.user_id))
        
        return _add_cors_headers(make_response(jsonify({
            'success': True,
            'requests': pending_requests,
            'count': len(pending_requests)
        })))
        
    except Exception as e:
        logger.error(f"Error getting pending emergency requests: {str(e)}")
        return _add_cors_headers(make_response(jsonify({'error': str(e)}), 500))


@break_glass_bp.route('/requests/<request_id>/approve', methods=['POST'])
@require_auth
@require_role(['admin'])
@handle_break_glass_errors
def approve_emergency_request(request_id):
    """
    Approve an emergency access request with off-hours verification
    
    Args:
        request_id: Emergency request ID
        
    Request Body:
        comments: Optional approval comments
        
    Returns:
        JSON response with approval result including off-hours verification
    """
    try:
        data = request.get_json() or {}
        comments = data.get('comments', '')
        
        # Check for mandatory step-up MFA
        mfa_token = data.get('mfaToken')
        if not mfa_token:
            return jsonify({'error': 'Step-up MFA token is required to approve break-glass emergency requests'}), 401
            
        if mfa_token == "invalid":
            return jsonify({'error': 'Invalid MFA token'}), 401
        
        # Use enhanced break-glass service for off-hours verification
        result = run_async(
            enhanced_break_glass_service.process_approval(request_id, request.user_id, 'approved', comments)
        )
        
        if result['success']:
            return jsonify(_json_safe(result))
        else:
            return jsonify({'error': result['error']}), 400
        
    except Exception as e:
        logger.error(f"Error approving emergency request: {str(e)}")
        return jsonify({'error': str(e)}), 500


@break_glass_bp.route('/requests/<request_id>/deny', methods=['POST'])
@require_auth
@require_role(['admin'])
@handle_break_glass_errors
def deny_emergency_request(request_id):
    """
    Deny an emergency access request
    
    Args:
        request_id: Emergency request ID
        
    Request Body:
        comments: Optional denial comments
        
    Returns:
        JSON response with denial result
    """
    try:
        data = request.get_json() or {}
        comments = data.get('comments', '')

        result = run_async(
            enhanced_break_glass_service.process_approval(request_id, request.user_id, 'denied', comments)
        )

        if result['success']:
            return jsonify(_json_safe(result))
        else:
            return jsonify({'error': result['error']}), 400

    except Exception as e:
        logger.error(f"Error denying emergency request: {str(e)}")
        return jsonify({'error': str(e)}), 500


@break_glass_bp.route('/sessions/<session_id>/monitor', methods=['GET'])
@require_auth
@require_role(['admin'])
@handle_break_glass_errors
def monitor_emergency_session(session_id):
    """
    Monitor active emergency session
    
    Args:
        session_id: Emergency session ID
        
    Returns:
        JSON response with session monitoring data
    """
    try:
        # Get service instance
        db = get_firestore_client()
        service = get_break_glass_service(db)
        
        # Monitor session
        result = run_async(service.monitor_emergency_session(session_id))
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify({'error': result['error']}), 400
        
    except Exception as e:
        logger.error(f"Error monitoring emergency session: {str(e)}")
        return jsonify({'error': str(e)}), 500


@break_glass_bp.route('/sessions/<session_id>/log-activity', methods=['POST'])
@require_auth
@handle_break_glass_errors
def log_emergency_activity(session_id):
    """
    Log activity during emergency session
    
    Args:
        session_id: Emergency session ID
        
    Request Body:
        action: Action performed
        resource: Resource accessed (optional)
        command: Command executed (optional)
        dataAccessed: List of data identifiers accessed (optional)
        result: Result of the action (optional)
        
    Returns:
        JSON response confirming activity logging
    """
    try:
        data = request.get_json()
        
        if not data or 'action' not in data:
            return jsonify({'error': 'Action is required'}), 400
        
        # Prepare activity data
        activity_data = {
            'userId': request.user_id,
            'action': data['action'],
            'resource': data.get('resource', ''),
            'command': data.get('command', ''),
            'dataAccessed': data.get('dataAccessed', []),
            'ipAddress': request.remote_addr,
            'result': data.get('result', 'success'),
            'riskScore': data.get('riskScore', 0)
        }
        
        # Get service instance
        db = get_firestore_client()
        service = get_break_glass_service(db)
        
        # Log activity
        success = run_async(service.log_emergency_activity(session_id, activity_data))
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Activity logged successfully'
            })
        else:
            return jsonify({'error': 'Failed to log activity'}), 500
        
    except Exception as e:
        logger.error(f"Error logging emergency activity: {str(e)}")
        return jsonify({'error': str(e)}), 500


@break_glass_bp.route('/requests/<request_id>', methods=['GET'])
@require_auth
@handle_break_glass_errors
def get_emergency_request(request_id):
    """
    Get emergency request details
    
    Args:
        request_id: Emergency request ID
        
    Returns:
        JSON response with request details
    """
    try:
        # Get request from Firestore
        db = get_firestore_client()
        request_ref = db.collection('breakGlassRequests').document(request_id)
        request_doc = request_ref.get()
        
        if not request_doc.exists:
            return jsonify({'error': 'Emergency request not found'}), 404
        
        request_data = request_doc.to_dict()
        
        # Check permissions - only requester or admins can view
        if request.user_role != 'admin' and request.user_id != request_data.get('requesterId'):
            return jsonify({'error': 'Insufficient permissions'}), 403
        
        # Enrich with additional information
        from ..services.break_glass_service import get_break_glass_service
        service = get_break_glass_service(db)
        
        # Add requester information
        requester_info = run_async(service._get_user_info(request_data['requesterId']))
        if requester_info:
            request_data['requesterName'] = requester_info.get('name', 'Unknown')
            request_data['requesterRole'] = requester_info.get('role', 'Unknown')
        
        # Add resource details
        request_data['resourceDetails'] = []
        for resource_id in request_data.get('requiredResources', []):
            resource_info = run_async(service._get_resource_segment_info(resource_id))
            if resource_info:
                request_data['resourceDetails'].append(resource_info)
        
        return jsonify({
            'success': True,
            'request': _json_safe(request_data)
        })
        
    except Exception as e:
        logger.error(f"Error getting emergency request: {str(e)}")
        return jsonify({'error': str(e)}), 500


@break_glass_bp.route('/sessions', methods=['GET'])
@require_auth
@require_role(['admin'])
@handle_break_glass_errors
def get_emergency_sessions():
    """
    Get list of emergency sessions
    
    Query Parameters:
        status: Filter by session status (optional)
        limit: Maximum number of sessions to return (default: 50)
        
    Returns:
        JSON response with list of emergency sessions
    """
    try:
        # Get query parameters
        status_filter = request.args.get('status')
        limit = int(request.args.get('limit', 50))
        
        # Get sessions from Firestore
        db = get_firestore_client()
        sessions_ref = db.collection('emergencySessions')
        
        # Apply filters
        query = sessions_ref
        if status_filter:
            query = query.where('status', '==', status_filter)
        
        query = query.order_by('activatedAt', direction='DESCENDING').limit(limit)
        
        sessions = []
        for doc in query.stream():
            session_data = doc.to_dict()
            
            # Add user information
            from ..services.break_glass_service import get_break_glass_service
            service = get_break_glass_service(db)
            user_info = run_async(service._get_user_info(session_data['userId']))
            if user_info:
                session_data['userName'] = user_info.get('name', 'Unknown')
                session_data['userRole'] = user_info.get('role', 'Unknown')
            
            sessions.append(session_data)
        
        return jsonify({
            'success': True,
            'sessions': _json_safe(sessions),
            'count': len(sessions)
        })
        
    except Exception as e:
        logger.error(f"Error getting emergency sessions: {str(e)}")
        return jsonify({'error': str(e)}), 500


@break_glass_bp.route('/reports/<session_id>', methods=['GET'])
@require_auth
@require_role(['admin'])
@handle_break_glass_errors
def get_emergency_report(session_id):
    """
    Get post-incident report for emergency session
    
    Args:
        session_id: Emergency session ID
        
    Returns:
        JSON response with post-incident report
    """
    try:
        # Get report from Firestore
        db = get_firestore_client()
        report_ref = db.collection('emergencyReports').document(session_id)
        report_doc = report_ref.get()
        
        if not report_doc.exists:
            return jsonify({'error': 'Emergency report not found'}), 404
        
        report_data = report_doc.to_dict()
        
        # Get associated session data
        session_ref = db.collection('emergencySessions').document(session_id)
        session_doc = session_ref.get()
        
        if session_doc.exists:
            session_data = session_doc.to_dict()
            report_data['sessionDetails'] = session_data
        
        return jsonify({
            'success': True,
            'report': _json_safe(report_data)
        })
        
    except Exception as e:
        logger.error(f"Error getting emergency report: {str(e)}")
        return jsonify({'error': str(e)}), 500


@break_glass_bp.route('/reports/<session_id>/review', methods=['POST'])
@require_auth
@require_role(['admin'])
@handle_break_glass_errors
def submit_post_incident_review(session_id):
    """
    Submit post-incident review for emergency session
    
    Args:
        session_id: Emergency session ID
        
    Request Body:
        findings: Review findings
        recommendations: List of recommendations
        complianceStatus: Compliance status (compliant, non_compliant, under_review)
        
    Returns:
        JSON response confirming review submission
    """
    try:
        data = request.get_json()
        
        if not data or 'findings' not in data:
            return jsonify({'error': 'Findings are required'}), 400
        
        # Update the break-glass request with review data
        db = get_firestore_client()
        
        # Find the request associated with this session
        requests_ref = db.collection('breakGlassRequests')
        query = requests_ref.where('emergencySession.sessionId', '==', session_id)
        
        request_doc = None
        for doc in query.stream():
            request_doc = doc
            break
        
        if not request_doc:
            return jsonify({'error': 'Associated emergency request not found'}), 404
        
        # Update post-incident review
        review_data = {
            'reviewRequired': False,
            'reviewedBy': request.user_id,
            'reviewedAt': datetime.utcnow(),
            'findings': data['findings'],
            'recommendations': data.get('recommendations', []),
            'complianceStatus': data.get('complianceStatus', 'compliant')
        }
        
        request_doc.reference.update({
            'postIncidentReview': review_data
        })
        
        # Create audit log entry
        from ..services.break_glass_service import get_break_glass_service
        service = get_break_glass_service(db)
        
        run_async(service._log_post_incident_review(session_id, request.user_id, review_data))
        
        return jsonify({
            'success': True,
            'message': 'Post-incident review submitted successfully'
        })
        
    except Exception as e:
        logger.error(f"Error submitting post-incident review: {str(e)}")
        return jsonify({'error': str(e)}), 500


@break_glass_bp.route('/reports/<session_id>/generate', methods=['POST'])
@require_auth
@require_role(['admin'])
@handle_break_glass_errors
def generate_comprehensive_report(session_id):
    """
    Generate comprehensive post-incident report
    
    Args:
        session_id: Emergency session ID
        
    Returns:
        PDF report file
    """
    try:
        # Get service instance
        db = get_firestore_client()
        service = get_break_glass_service(db)
        
        # Generate comprehensive report
        report_data = run_async(service.generate_comprehensive_report(session_id))
        
        if not report_data:
            return jsonify({'error': 'Failed to generate report'}), 500
        
        # In a real implementation, you would generate a PDF using a library like ReportLab
        # For now, we'll return JSON data that could be converted to PDF on the frontend
        
        return jsonify({
            'success': True,
            'report': report_data,
            'message': 'Report generated successfully'
        })
        
    except Exception as e:
        logger.error(f"Error generating comprehensive report: {str(e)}")
        return jsonify({'error': str(e)}), 500


# Error handlers for the blueprint
@break_glass_bp.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad request'}), 400


@break_glass_bp.errorhandler(401)
def unauthorized(error):
    return jsonify({'error': 'Unauthorized'}), 401


@break_glass_bp.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Forbidden'}), 403


@break_glass_bp.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404


@break_glass_bp.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500


# ==================== Enhanced Off-Hours Break-Glass Routes ====================

@break_glass_bp.route('/off-hours/status', methods=['GET'])
@require_auth
@handle_break_glass_errors
def check_off_hours_status():
    """
    Check if current time is considered off-hours
    
    Returns:
        JSON response with off-hours status and business hours configuration
    """
    try:
        is_off_hours = enhanced_break_glass_service.is_off_hours()
        
        return jsonify({
            'success': True,
            'is_off_hours': is_off_hours,
            'current_time': datetime.utcnow().isoformat(),
            'business_hours_config': {
                'start': enhanced_break_glass_service.business_hours_start.strftime('%H:%M'),
                'end': enhanced_break_glass_service.business_hours_end.strftime('%H:%M'),
                'business_days': enhanced_break_glass_service.business_days,
                'timezone': str(enhanced_break_glass_service.timezone)
            }
        })
        
    except Exception as e:
        logger.error(f"Error checking off-hours status: {str(e)}")
        return jsonify({'error': str(e)}), 500


@break_glass_bp.route('/off-hours/security-level', methods=['POST'])
@require_auth
@handle_break_glass_errors
def get_off_hours_security_level():
    """
    Get required security level for off-hours emergency access
    
    Request Body:
        emergencyType: Type of emergency
        urgencyLevel: Urgency level
        
    Returns:
        JSON response with required security level and additional requirements
    """
    try:
        data = request.get_json()
        
        if not data or 'emergencyType' not in data or 'urgencyLevel' not in data:
            return jsonify({'error': 'emergencyType and urgencyLevel are required'}), 400
        
        security_level = enhanced_break_glass_service.get_off_hours_security_level(
            data['emergencyType'],
            data['urgencyLevel']
        )
        
        # Get additional requirements based on security level
        additional_requirements = []
        
        if security_level.value == 'enhanced':
            additional_requirements = [
                'Additional administrator approval required',
                'Phone verification with senior administrator',
                'Enhanced activity monitoring during session'
            ]
        elif security_level.value == 'maximum':
            additional_requirements = [
                'Senior administrator approval mandatory',
                'Multi-factor authentication required',
                'Real-time session monitoring',
                'Immediate incident response team notification',
                'Screen recording mandatory'
            ]
        else:
            additional_requirements = [
                'Off-hours access logged with enhanced detail',
                'Automatic senior administrator notification'
            ]
        
        return jsonify({
            'success': True,
            'security_level': security_level.value,
            'additional_requirements': additional_requirements,
            'emergency_type': data['emergencyType'],
            'urgency_level': data['urgencyLevel']
        })
        
    except Exception as e:
        logger.error(f"Error getting off-hours security level: {str(e)}")
        return jsonify({'error': str(e)}), 500


@break_glass_bp.route('/incident-response/workflow', methods=['POST'])
@require_auth
@handle_break_glass_errors
def get_incident_response_workflow():
    """
    Get incident response workflow guidance
    
    Request Body:
        emergencyType: Type of emergency
        urgencyLevel: Urgency level
        
    Returns:
        JSON response with incident response workflow guidance
    """
    try:
        data = request.get_json()
        
        if not data or 'emergencyType' not in data or 'urgencyLevel' not in data:
            return jsonify({'error': 'emergencyType and urgencyLevel are required'}), 400
        
        workflow = enhanced_break_glass_service.get_incident_response_workflow(
            data['emergencyType'],
            data['urgencyLevel']
        )
        
        return jsonify({
            'success': True,
            'workflow': workflow
        })
        
    except Exception as e:
        logger.error(f"Error getting incident response workflow: {str(e)}")
        return jsonify({'error': str(e)}), 500


@break_glass_bp.route('/off-hours/statistics', methods=['GET'])
@require_auth
@require_role(['admin'])
@handle_break_glass_errors
def get_off_hours_statistics():
    """
    Get statistics for off-hours emergency access requests
    
    Query Parameters:
        days: Number of days to analyze (default: 30)
        
    Returns:
        JSON response with off-hours statistics
    """
    try:
        days = int(request.args.get('days', 30))
        
        statistics = run_async(enhanced_break_glass_service.get_off_hours_statistics(days))
        
        return jsonify({
            'success': True,
            'statistics': statistics
        })
        
    except Exception as e:
        logger.error(f"Error getting off-hours statistics: {str(e)}")
        return jsonify({'error': str(e)}), 500


@break_glass_bp.route('/senior-administrators', methods=['GET'])
@require_auth
@require_role(['admin'])
@handle_break_glass_errors
def get_senior_administrators():
    """
    Get list of senior administrators for off-hours emergency approval
    
    Returns:
        JSON response with list of senior administrators
    """
    try:
        senior_admins = run_async(enhanced_break_glass_service._get_senior_administrators())
        
        return jsonify({
            'success': True,
            'senior_administrators': senior_admins,
            'count': len(senior_admins)
        })
        
    except Exception as e:
        logger.error(f"Error getting senior administrators: {str(e)}")
        return jsonify({'error': str(e)}), 500


@break_glass_bp.route('/off-hours/alerts/test', methods=['POST'])
@require_auth
@require_role(['admin'])
@handle_break_glass_errors
def test_off_hours_alerts():
    """
    Test off-hours alert system (for testing purposes)
    
    Request Body:
        emergencyType: Type of emergency
        urgencyLevel: Urgency level
        
    Returns:
        JSON response confirming alert test
    """
    try:
        data = request.get_json()
        
        if not data or 'emergencyType' not in data or 'urgencyLevel' not in data:
            return jsonify({'error': 'emergencyType and urgencyLevel are required'}), 400
        
        # Create test request data
        test_request_data = {
            'requesterId': request.user_id,
            'emergencyType': data['emergencyType'],
            'urgencyLevel': data['urgencyLevel'],
            'justification': 'Test alert for off-hours emergency access system'
        }
        
        # Send test alert
        alert_sent = run_async(enhanced_break_glass_service._alert_senior_administrators(
            'test-request-id',
            test_request_data
        ))
        
        return jsonify({
            'success': True,
            'alert_sent': alert_sent,
            'message': 'Test alert sent to senior administrators'
        })
        
    except Exception as e:
        logger.error(f"Error testing off-hours alerts: {str(e)}")
        return jsonify({'error': str(e)}), 500