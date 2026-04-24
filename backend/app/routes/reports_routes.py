"""Security Reports Routes"""
from flask import Blueprint, request, jsonify
from functools import wraps
from app.models.security_report import SecurityReport, UserSecurityReputation
from app.models.notification import create_notification
from app.services.audit_logger import audit_logger
from app.firebase_config import db
from datetime import datetime

reports_bp = Blueprint('reports', __name__, url_prefix='/api/security')

# Rate limiting storage (in production, use Redis)
report_rate_limits = {}


def rate_limit_check(user_id, limit=10, window=3600):
    """Check if user has exceeded rate limit for reports"""
    current_time = datetime.utcnow().timestamp()
    
    if user_id not in report_rate_limits:
        report_rate_limits[user_id] = []
    
    # Remove old timestamps outside the window
    report_rate_limits[user_id] = [
        ts for ts in report_rate_limits[user_id]
        if current_time - ts < window
    ]
    
    # Check if limit exceeded
    if len(report_rate_limits[user_id]) >= limit:
        return False
    
    # Add current timestamp
    report_rate_limits[user_id].append(current_time)
    return True


def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # In production, verify JWT token
        user_id = request.headers.get('X-User-ID')
        if not user_id:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'UNAUTHORIZED',
                    'message': 'Authentication required'
                }
            }), 401
        
        request.user_id = user_id
        return f(*args, **kwargs)
    
    return decorated_function


def require_admin(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # In production, verify JWT token and check role
        user_id = request.headers.get('X-User-ID')
        user_role = request.headers.get('X-User-Role')
        
        if not user_id or user_role != 'admin':
            return jsonify({
                'success': False,
                'error': {
                    'code': 'FORBIDDEN',
                    'message': 'Admin access required'
                }
            }), 403
        
        request.user_id = user_id
        return f(*args, **kwargs)
    
    return decorated_function


@reports_bp.route('/report', methods=['POST'])
@require_auth
def submit_report():
    """
    Submit a security report
    
    Request Body:
        reportedBy (str): User ID of reporter
        reportType (str): Type of security report
        targetUserId (str, optional): User ID being reported
        targetResource (str, optional): Resource being reported
        description (str): Detailed description
        severity (str): Severity level (low, medium, high, critical)
        evidenceUrls (list, optional): URLs to evidence
    
    Returns:
        JSON response with report ID and status
    """
    try:
        data = request.get_json()
        user_id = request.user_id
        
        # Rate limiting check
        if not rate_limit_check(user_id, limit=10, window=3600):
            audit_logger.log_event(
                event_type='rate_limit_exceeded',
                user_id=user_id,
                action='submit_security_report',
                resource='/api/security/report',
                result='failure',
                details={'reason': 'Rate limit exceeded'},
                severity='low'
            )
            
            return jsonify({
                'success': False,
                'error': {
                    'code': 'RATE_LIMIT_EXCEEDED',
                    'message': 'Too many reports submitted. Limit is 10 reports per hour.'
                }
            }), 429
        
        # Create security report
        report = SecurityReport(
            reported_by=user_id,
            report_type=data.get('reportType'),
            target_user_id=data.get('targetUserId'),
            target_resource=data.get('targetResource'),
            description=data.get('description'),
            severity=data.get('severity', 'medium'),
            evidence_urls=data.get('evidenceUrls', [])
        )
        
        # Validate report
        is_valid, error_message = report.validate()
        if not is_valid:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'VALIDATION_ERROR',
                    'message': error_message
                }
            }), 400
        
        # Save report
        if not report.save():
            raise Exception("Failed to save security report")
        
        # Update user reputation
        reputation = UserSecurityReputation.get_by_user_id(user_id)
        reputation.reports_submitted += 1
        reputation.add_contribution('report_submitted', 5)
        reputation.save()
        
        # Send notifications to admins
        admins_ref = db.collection('users').where('role', '==', 'admin').stream()
        for admin_doc in admins_ref:
            admin_data = admin_doc.to_dict()
            create_notification(
                db=db,
                user_id=admin_data.get('userId'),
                notification_type='security_report',
                title='New Security Report',
                message=f'A new {report.severity} severity security report has been submitted.',
                data={
                    'reportId': report.report_id,
                    'reportType': report.report_type,
                    'severity': report.severity
                }
            )
        
        # Log audit event
        audit_logger.log_event(
            event_type='security_report',
            user_id=user_id,
            action='submit_security_report',
            resource=report.report_id,
            result='success',
            details={
                'reportType': report.report_type,
                'severity': report.severity,
                'targetUserId': report.target_user_id
            },
            severity=report.severity
        )
        
        return jsonify({
            'success': True,
            'reportId': report.report_id,
            'status': 'pending'
        }), 200
        
    except Exception as e:
        audit_logger.log_event(
            event_type='system_error',
            user_id=request.user_id,
            action='submit_security_report',
            resource='/api/security/report',
            result='failure',
            details={'error': str(e)},
            severity='medium'
        )
        
        return jsonify({
            'success': False,
            'error': {
                'code': 'INTERNAL_ERROR',
                'message': 'Failed to submit security report'
            }
        }), 500


@reports_bp.route('/reports', methods=['GET'])
@require_admin
def get_reports():
    """
    Get security reports (admin only)
    
    Query Parameters:
        status (str, optional): Filter by status
        severity (str, optional): Filter by severity
        limit (int, optional): Maximum number of reports (default: 100)
    
    Returns:
        JSON response with list of reports
    """
    try:
        filters = {}
        
        status = request.args.get('status')
        if status:
            filters['status'] = status
        
        severity = request.args.get('severity')
        if severity:
            filters['severity'] = severity
        
        limit = int(request.args.get('limit', 100))
        
        # Get reports
        reports = SecurityReport.get_all(filters=filters, limit=limit)
        
        # Convert to dict
        reports_data = [report.to_dict() for report in reports]
        
        # Get reporter reputation for prioritization
        for report_data in reports_data:
            reputation = UserSecurityReputation.get_by_user_id(report_data['reportedBy'])
            if reputation:
                report_data['reporterReputation'] = reputation.reputation_score
                report_data['prioritize'] = reputation.reputation_score > 80
        
        return jsonify({
            'success': True,
            'reports': reports_data,
            'totalCount': len(reports_data)
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'INTERNAL_ERROR',
                'message': 'Failed to retrieve security reports'
            }
        }), 500


@reports_bp.route('/report/<report_id>/verify', methods=['PUT'])
@require_admin
def verify_report(report_id):
    """
    Verify or mark report as false positive (admin only)
    
    Request Body:
        status (str): 'verified' or 'false_positive'
        resolution (str): Resolution notes
    
    Returns:
        JSON response with updated reputation status
    """
    try:
        data = request.get_json()
        admin_id = request.user_id
        
        # Get report
        report = SecurityReport.get_by_id(report_id)
        if not report:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'NOT_FOUND',
                    'message': 'Security report not found'
                }
            }), 404
        
        # Update report status
        new_status = data.get('status')
        if new_status not in ['verified', 'false_positive', 'resolved']:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'VALIDATION_ERROR',
                    'message': 'Status must be verified, false_positive, or resolved'
                }
            }), 400
        
        report.status = new_status
        report.verified_by = admin_id
        report.resolution = data.get('resolution', '')
        report.save()
        
        # Update reporter reputation
        reputation = UserSecurityReputation.get_by_user_id(report.reported_by)
        
        if new_status == 'verified':
            # Increase reputation for accurate report
            reputation.verified_reports += 1
            reputation.add_contribution('report_verified', 10)
            
            # Check for new badges
            new_badges = reputation.check_and_award_badges()
            
            # Notify reporter
            create_notification(
                db=db,
                user_id=report.reported_by,
                notification_type='report_verified',
                title='Security Report Verified',
                message=f'Your security report has been verified. You earned 10 reputation points!',
                data={
                    'reportId': report.report_id,
                    'pointsEarned': 10,
                    'newBadges': new_badges
                }
            )
            
        elif new_status == 'false_positive':
            # Decrease reputation for false positive
            reputation.false_positives += 1
            reputation.add_contribution('report_false_positive', -5)
            
            # Notify reporter
            create_notification(
                db=db,
                user_id=report.reported_by,
                notification_type='report_false_positive',
                title='Security Report Marked as False Positive',
                message=f'Your security report was marked as a false positive.',
                data={
                    'reportId': report.report_id,
                    'resolution': report.resolution
                }
            )
        
        # Recalculate reputation score
        reputation.calculate_reputation_score()
        reputation.save()
        
        # Log audit event
        audit_logger.log_event(
            event_type='admin_action',
            user_id=admin_id,
            action='verify_security_report',
            resource=report_id,
            result='success',
            details={
                'status': new_status,
                'reportedBy': report.reported_by,
                'newReputationScore': reputation.reputation_score
            },
            severity='medium'
        )
        
        return jsonify({
            'success': True,
            'reputationUpdated': True,
            'newReputationScore': reputation.reputation_score
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'INTERNAL_ERROR',
                'message': 'Failed to verify security report'
            }
        }), 500


@reports_bp.route('/reputation/<user_id>', methods=['GET'])
@require_auth
def get_reputation(user_id):
    """
    Get user's security reputation and badges
    
    Returns:
        JSON response with reputation data
    """
    try:
        # Users can only view their own reputation unless they're admin
        if request.user_id != user_id and request.headers.get('X-User-Role') != 'admin':
            return jsonify({
                'success': False,
                'error': {
                    'code': 'FORBIDDEN',
                    'message': 'Cannot view other users reputation'
                }
            }), 403
        
        reputation = UserSecurityReputation.get_by_user_id(user_id)
        if not reputation:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'NOT_FOUND',
                    'message': 'Reputation not found'
                }
            }), 404
        
        return jsonify({
            'success': True,
            'reputation': reputation.to_dict(),
            'rank': reputation.rank
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'INTERNAL_ERROR',
                'message': 'Failed to retrieve reputation'
            }
        }), 500


@reports_bp.route('/leaderboard', methods=['GET'])
@require_auth
def get_leaderboard():
    """
    Get security contribution leaderboard
    
    Query Parameters:
        limit (int, optional): Maximum number of entries (default: 100)
        timeRange (str, optional): Time range filter (not implemented yet)
    
    Returns:
        JSON response with leaderboard data
    """
    try:
        limit = int(request.args.get('limit', 100))
        
        # Get leaderboard
        leaderboard = UserSecurityReputation.get_leaderboard(limit=limit)
        
        # Convert to dict and add user info
        leaderboard_data = []
        for reputation in leaderboard:
            rep_dict = reputation.to_dict()
            
            # Get user name (in production, join with users collection)
            user_doc = db.collection('users').document(reputation.user_id).get()
            if user_doc.exists:
                user_data = user_doc.to_dict()
                rep_dict['userName'] = user_data.get('name', 'Unknown')
            
            leaderboard_data.append(rep_dict)
        
        return jsonify({
            'success': True,
            'leaderboard': leaderboard_data
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'INTERNAL_ERROR',
                'message': 'Failed to retrieve leaderboard'
            }
        }), 500
