"""
Admin Routes
API endpoints for administrative operations (user management, audit logs, analytics)
"""

from flask import Blueprint, request, jsonify
from app.middleware.authorization import require_auth, require_admin, get_current_user
from app.models.user import get_user_by_id, update_user
from app.firebase_config import get_firestore_client
from app.services.audit_logger import audit_logger
from firebase_admin import auth as firebase_auth
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

bp = Blueprint('admin', __name__, url_prefix='/api/admin')


def get_client_ip():
    """Get client IP address from request"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr


def send_role_change_notification(user_email, user_name, old_role, new_role, admin_name):
    """
    Send email notification to user when their role is changed
    
    Args:
        user_email (str): User's email address
        user_name (str): User's name
        old_role (str): Previous role
        new_role (str): New role
        admin_name (str): Administrator who made the change
    """
    smtp_host = os.getenv('SMTP_HOST', 'smtp.gmail.com')
    smtp_port = int(os.getenv('SMTP_PORT', 587))
    smtp_user = os.getenv('SMTP_USER')
    smtp_password = os.getenv('SMTP_PASSWORD')
    email_enabled = os.getenv('EMAIL_NOTIFICATIONS_ENABLED', 'false').lower() == 'true'
    
    if not email_enabled:
        print(f"Email notifications disabled. Would send role change notification to {user_email}")
        return
    
    if not smtp_user or not smtp_password:
        print("SMTP credentials not configured. Cannot send notification email.")
        return
    
    try:
        # Create email message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = "Your Account Role Has Been Updated"
        msg['From'] = smtp_user
        msg['To'] = user_email
        
        # Create email body
        text_body = f"""
Hello {user_name},

Your account role has been updated in the Zero Trust Security Framework.

Previous Role: {old_role}
New Role: {new_role}
Updated By: {admin_name}

This change is effective immediately. Your access permissions have been updated accordingly.

If you have any questions about this change, please contact your system administrator.

Best regards,
Zero Trust Security Framework Team
"""
        
        html_body = f"""
<html>
<head></head>
<body>
    <h2>Account Role Updated</h2>
    <p>Hello {user_name},</p>
    <p>Your account role has been updated in the Zero Trust Security Framework.</p>
    <table style="border-collapse: collapse; margin: 20px 0;">
        <tr>
            <td style="padding: 8px; border: 1px solid #ddd;"><strong>Previous Role:</strong></td>
            <td style="padding: 8px; border: 1px solid #ddd;">{old_role}</td>
        </tr>
        <tr>
            <td style="padding: 8px; border: 1px solid #ddd;"><strong>New Role:</strong></td>
            <td style="padding: 8px; border: 1px solid #ddd;">{new_role}</td>
        </tr>
        <tr>
            <td style="padding: 8px; border: 1px solid #ddd;"><strong>Updated By:</strong></td>
            <td style="padding: 8px; border: 1px solid #ddd;">{admin_name}</td>
        </tr>
    </table>
    <p>This change is effective immediately. Your access permissions have been updated accordingly.</p>
    <p>If you have any questions about this change, please contact your system administrator.</p>
    <p><em>Best regards,<br>Zero Trust Security Framework Team</em></p>
</body>
</html>
"""
        
        # Attach both plain text and HTML versions
        part1 = MIMEText(text_body, 'plain')
        part2 = MIMEText(html_body, 'html')
        msg.attach(part1)
        msg.attach(part2)
        
        # Send email
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
        
        print(f"Role change notification sent to {user_email}")
    except Exception as e:
        print(f"Error sending role change notification: {str(e)}")


@bp.route('/users', methods=['GET'])
@require_auth
@require_admin
def get_users():
    """
    Get all users with filtering and pagination (Admin only)
    
    Query Parameters:
        - role: Filter by role (optional)
        - status: Filter by active status (optional, 'active' or 'inactive')
        - search: Search by name or email (optional)
        - limit: Number of results per page (default: 50)
        - offset: Number of results to skip (default: 0)
    
    Returns:
        List of users with pagination info
    """
    try:
        db = get_firestore_client()
        
        # Get query parameters
        role_filter = request.args.get('role')
        status_filter = request.args.get('status')
        search_query = request.args.get('search', '').lower()
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
        
        # Build query
        users_ref = db.collection('users')
        query = users_ref
        
        # Apply role filter
        if role_filter:
            query = query.where('role', '==', role_filter)
        
        # Apply status filter
        if status_filter:
            is_active = status_filter.lower() == 'active'
            query = query.where('isActive', '==', is_active)
        
        # Execute query
        all_users = []
        for doc in query.stream():
            user_data = doc.to_dict()
            
            # Apply search filter (client-side since Firestore doesn't support full-text search)
            if search_query:
                name_match = search_query in user_data.get('name', '').lower()
                email_match = search_query in user_data.get('email', '').lower()
                if not (name_match or email_match):
                    continue
            
            # Remove sensitive fields
            user_data.pop('mfaSecret', None)
            user_data.pop('lockoutUntil', None)
            
            # Convert timestamps to ISO format
            if 'createdAt' in user_data:
                user_data['createdAt'] = user_data['createdAt'].isoformat() if hasattr(user_data['createdAt'], 'isoformat') else str(user_data['createdAt'])
            if 'lastLogin' in user_data:
                user_data['lastLogin'] = user_data['lastLogin'].isoformat() if hasattr(user_data['lastLogin'], 'isoformat') else str(user_data['lastLogin'])
            
            all_users.append(user_data)
        
        # Apply pagination
        total_count = len(all_users)
        paginated_users = all_users[offset:offset + limit]
        
        return jsonify({
            'success': True,
            'users': paginated_users,
            'totalCount': total_count,
            'limit': limit,
            'offset': offset
        }), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'USER_LIST_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('/users/<user_id>', methods=['PUT'])
@require_auth
@require_admin
def update_user_admin(user_id):
    """
    Update user account (Admin only)
    
    Args:
        user_id: User ID to update
    
    Request Body:
        - role: New role (optional)
        - isActive: Active status (optional)
        - department: Department (optional)
        - name: User name (optional)
    
    Returns:
        Updated user data
    """
    try:
        current_user = get_current_user()
        admin_id = current_user['user_id']
        ip_address = get_client_ip()
        
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'VALIDATION_ERROR',
                    'message': 'No update data provided'
                }
            }), 400
        
        db = get_firestore_client()
        
        # Get current user data
        user = get_user_by_id(db, user_id)
        if not user:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'USER_NOT_FOUND',
                    'message': 'User not found'
                }
            }), 404
        
        # Store old values for audit log
        old_role = user.role
        old_status = user.is_active
        
        # Prepare update data
        update_data = {}
        allowed_fields = ['role', 'isActive', 'department', 'name']
        
        for field in allowed_fields:
            if field in data:
                update_data[field] = data[field]
        
        # Validate role if being updated
        if 'role' in update_data:
            valid_roles = ['student', 'faculty', 'admin']
            if update_data['role'] not in valid_roles:
                return jsonify({
                    'success': False,
                    'error': {
                        'code': 'VALIDATION_ERROR',
                        'message': f'Invalid role. Must be one of: {", ".join(valid_roles)}'
                    }
                }), 400
        
        # Update user
        update_user(db, user_id, update_data)
        
        # Get updated user
        updated_user = get_user_by_id(db, user_id)
        
        # Log admin action
        action_details = {
            'updatedFields': list(update_data.keys()),
            'changes': {}
        }
        
        if 'role' in update_data and old_role != update_data['role']:
            action_details['changes']['role'] = {
                'old': old_role,
                'new': update_data['role']
            }
        
        if 'isActive' in update_data and old_status != update_data['isActive']:
            action_details['changes']['isActive'] = {
                'old': old_status,
                'new': update_data['isActive']
            }
        
        audit_logger.log_admin_action(
            admin_id=admin_id,
            action='Update user',
            target_user_id=user_id,
            details=action_details,
            ip_address=ip_address
        )
        
        # Send email notification if role changed
        if 'role' in update_data and old_role != update_data['role']:
            # Get admin user for notification
            admin_user = get_user_by_id(db, admin_id)
            admin_name = admin_user.name if admin_user else 'Administrator'
            
            send_role_change_notification(
                user_email=updated_user.email,
                user_name=updated_user.name,
                old_role=old_role,
                new_role=update_data['role'],
                admin_name=admin_name
            )
        
        return jsonify({
            'success': True,
            'user': updated_user.to_public_dict(),
            'message': 'User updated successfully'
        }), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'USER_UPDATE_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('/users/<user_id>', methods=['DELETE'])
@require_auth
@require_admin
def delete_user_admin(user_id):
    """
    Soft delete user account (Admin only)
    Sets isActive to false and invalidates all sessions
    
    Args:
        user_id: User ID to delete
    
    Returns:
        Success message
    """
    try:
        current_user = get_current_user()
        admin_id = current_user['user_id']
        ip_address = get_client_ip()
        
        # Prevent self-deletion
        if admin_id == user_id:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'INVALID_OPERATION',
                    'message': 'Cannot delete your own account'
                }
            }), 400
        
        db = get_firestore_client()
        
        # Check if user exists
        user = get_user_by_id(db, user_id)
        if not user:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'USER_NOT_FOUND',
                    'message': 'User not found'
                }
            }), 404
        
        # Soft delete (set isActive to false)
        update_user(db, user_id, {'isActive': False})
        
        # Revoke all Firebase sessions for this user
        try:
            firebase_auth.revoke_refresh_tokens(user_id)
        except Exception as e:
            print(f"Error revoking Firebase tokens: {str(e)}")
        
        # Log admin action
        audit_logger.log_admin_action(
            admin_id=admin_id,
            action='Deactivate user',
            target_user_id=user_id,
            details={
                'userName': user.name,
                'userEmail': user.email,
                'userRole': user.role
            },
            ip_address=ip_address
        )
        
        return jsonify({
            'success': True,
            'message': 'User account deactivated successfully'
        }), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'USER_DELETE_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('/logs', methods=['GET'])
@require_auth
@require_admin
def get_audit_logs():
    """
    Get audit logs with filtering and pagination (Admin only)
    
    Query Parameters:
        - userId: Filter by user ID (optional)
        - eventType: Filter by event type (optional)
        - startDate: Filter by start date ISO format (optional)
        - endDate: Filter by end date ISO format (optional)
        - severity: Filter by severity level (optional)
        - result: Filter by result (optional)
        - limit: Number of results per page (default: 100)
        - offset: Number of results to skip (default: 0)
    
    Returns:
        List of audit logs with pagination info
    """
    try:
        from datetime import datetime
        
        db = get_firestore_client()
        
        # Get query parameters
        user_id_filter = request.args.get('userId')
        event_type_filter = request.args.get('eventType')
        start_date_str = request.args.get('startDate')
        end_date_str = request.args.get('endDate')
        severity_filter = request.args.get('severity')
        result_filter = request.args.get('result')
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        
        # Build query
        logs_ref = db.collection('auditLogs')
        query = logs_ref
        
        # Apply filters
        if user_id_filter:
            query = query.where('userId', '==', user_id_filter)
        
        if event_type_filter:
            query = query.where('eventType', '==', event_type_filter)
        
        if severity_filter:
            query = query.where('severity', '==', severity_filter)
        
        if result_filter:
            query = query.where('result', '==', result_filter)
        
        # Order by timestamp descending
        query = query.order_by('timestamp', direction='DESCENDING')
        
        # Execute query and get all matching logs
        all_logs = []
        for doc in query.stream():
            log_data = doc.to_dict()
            
            # Apply date range filters (client-side since Firestore has limitations on range queries)
            if start_date_str or end_date_str:
                log_timestamp = log_data.get('timestamp')
                
                # Convert timestamp to datetime if needed
                if log_timestamp:
                    if hasattr(log_timestamp, 'isoformat'):
                        log_datetime = log_timestamp
                    else:
                        try:
                            log_datetime = datetime.fromisoformat(str(log_timestamp).replace('Z', '+00:00'))
                        except:
                            log_datetime = None
                    
                    if log_datetime:
                        if start_date_str:
                            try:
                                start_date = datetime.fromisoformat(start_date_str.replace('Z', '+00:00'))
                                if log_datetime < start_date:
                                    continue
                            except:
                                pass
                        
                        if end_date_str:
                            try:
                                end_date = datetime.fromisoformat(end_date_str.replace('Z', '+00:00'))
                                if log_datetime > end_date:
                                    continue
                            except:
                                pass
            
            # Convert timestamp to ISO format for JSON serialization
            if 'timestamp' in log_data:
                if hasattr(log_data['timestamp'], 'isoformat'):
                    log_data['timestamp'] = log_data['timestamp'].isoformat()
                else:
                    log_data['timestamp'] = str(log_data['timestamp'])
            
            all_logs.append(log_data)
        
        # Apply pagination
        total_count = len(all_logs)
        paginated_logs = all_logs[offset:offset + limit]
        
        return jsonify({
            'success': True,
            'logs': paginated_logs,
            'totalCount': total_count,
            'limit': limit,
            'offset': offset
        }), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'LOGS_RETRIEVAL_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('/analytics', methods=['GET'])
@require_auth
@require_admin
def get_analytics():
    """
    Get system analytics and metrics (Admin only)
    
    Query Parameters:
        - timeRange: Time range for analytics ('day', 'week', 'month', default: 'week')
    
    Returns:
        Analytics data including:
        - Total requests
        - Approval rate
        - Average confidence score
        - Requests by role
        - Top denied users
        - Confidence score distribution
    """
    try:
        from datetime import datetime, timedelta
        from collections import defaultdict
        
        db = get_firestore_client()
        
        # Get time range parameter
        time_range = request.args.get('timeRange', 'week')
        
        # Calculate start date based on time range
        now = datetime.utcnow()
        if time_range == 'day':
            start_date = now - timedelta(days=1)
        elif time_range == 'month':
            start_date = now - timedelta(days=30)
        else:  # default to week
            start_date = now - timedelta(days=7)
        
        # Fetch all access requests within time range
        requests_ref = db.collection('accessRequests')
        query = requests_ref.order_by('timestamp', direction='DESCENDING')
        
        all_requests = []
        for doc in query.stream():
            request_data = doc.to_dict()
            
            # Filter by date range
            request_timestamp = request_data.get('timestamp')
            if request_timestamp:
                if hasattr(request_timestamp, 'replace'):
                    request_datetime = request_timestamp
                else:
                    try:
                        request_datetime = datetime.fromisoformat(str(request_timestamp).replace('Z', '+00:00'))
                    except:
                        continue
                
                # Check if within time range
                if request_datetime.replace(tzinfo=None) >= start_date:
                    all_requests.append(request_data)
        
        # Calculate metrics
        total_requests = len(all_requests)
        
        # Count approved vs denied
        approved_count = 0
        denied_count = 0
        confidence_scores = []
        requests_by_role = defaultdict(int)
        denied_by_user = defaultdict(int)
        confidence_distribution = {
            '0-20': 0,
            '21-40': 0,
            '41-60': 0,
            '61-80': 0,
            '81-100': 0
        }
        
        for req in all_requests:
            decision = req.get('decision', '')
            user_role = req.get('userRole', 'unknown')
            user_id = req.get('userId', '')
            confidence_score = req.get('confidenceScore', 0)
            
            # Count approvals
            if decision in ['granted', 'granted_with_mfa']:
                approved_count += 1
            elif decision == 'denied':
                denied_count += 1
                denied_by_user[user_id] += 1
            
            # Collect confidence scores
            if confidence_score:
                confidence_scores.append(confidence_score)
                
                # Categorize confidence score
                if confidence_score <= 20:
                    confidence_distribution['0-20'] += 1
                elif confidence_score <= 40:
                    confidence_distribution['21-40'] += 1
                elif confidence_score <= 60:
                    confidence_distribution['41-60'] += 1
                elif confidence_score <= 80:
                    confidence_distribution['61-80'] += 1
                else:
                    confidence_distribution['81-100'] += 1
            
            # Count by role
            requests_by_role[user_role] += 1
        
        # Calculate approval rate
        approval_rate = (approved_count / total_requests * 100) if total_requests > 0 else 0
        
        # Calculate average confidence
        average_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0
        
        # Get top denied users (top 5)
        top_denied_users = []
        sorted_denied = sorted(denied_by_user.items(), key=lambda x: x[1], reverse=True)[:5]
        
        for user_id, count in sorted_denied:
            # Get user details
            user = get_user_by_id(db, user_id)
            if user:
                top_denied_users.append({
                    'userId': user_id,
                    'name': user.name,
                    'email': user.email,
                    'role': user.role,
                    'deniedCount': count
                })
            else:
                top_denied_users.append({
                    'userId': user_id,
                    'name': 'Unknown User',
                    'email': '',
                    'role': 'unknown',
                    'deniedCount': count
                })
        
        # Prepare response
        analytics = {
            'totalRequests': total_requests,
            'approvalRate': round(approval_rate, 2),
            'averageConfidence': round(average_confidence, 2),
            'requestsByRole': dict(requests_by_role),
            'topDeniedUsers': top_denied_users,
            'confidenceDistribution': confidence_distribution,
            'timeRange': time_range,
            'startDate': start_date.isoformat(),
            'endDate': now.isoformat()
        }
        
        return jsonify({
            'success': True,
            'analytics': analytics
        }), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'ANALYTICS_FAILED',
                'message': str(e)
            }
        }), 500
