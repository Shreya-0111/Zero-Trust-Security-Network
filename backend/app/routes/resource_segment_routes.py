"""
Resource Segment Routes
API endpoints for resource segment management and queries
"""

import os

from flask import Blueprint, request, jsonify

from app.middleware.authorization import require_auth
from app.models.resource_segment import get_resource_segment_by_id, get_all_resource_segments
from app.models.user import get_user_by_id
from app.services.resource_segment_service import get_segments_by_role
from app.firebase_config import get_firestore_client


def _get_user_security_clearance(user):
    return getattr(user, "security_clearance", getattr(user, "securityClearance", 1))

bp = Blueprint('resource_segments', __name__, url_prefix='/api/resource-segments')



@bp.route('/available', methods=['GET'])
@require_auth
def get_available_segments():
    """
    Get resource segments available to the authenticated user
    
    Query Parameters:
        - jit_only: If true, only return segments that require JIT access (default: false)
    
    Returns:
        List of available resource segments
    """
    try:
        user_id = request.user_id
        user_role = request.user_role
        jit_only = request.args.get('jit_only', 'false').lower() == 'true'
        
        # Get user from database to check security clearance
        db = get_firestore_client()
        user = get_user_by_id(db, user_id)
        
        if not user or not user.is_active:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'USER_INACTIVE',
                    'message': 'User account is not active'
                }
            }), 403
        
        # Get segments accessible by user role
        segments = get_segments_by_role(db, user_role)
        
        # Filter segments based on user's security clearance
        user_clearance = _get_user_security_clearance(user)
        accessible_segments = []
        
        for segment in segments:
            # Check if user can access this segment
            can_access, _ = segment.can_user_access(user_role, user_clearance)
            
            if can_access:
                # If jit_only is true, only include segments that require JIT
                if jit_only and not segment.requires_jit:
                    continue
                
                # Convert to public dictionary (no sensitive internal data)
                segment_data = segment.to_public_dict()
                accessible_segments.append(segment_data)
        
        # Development fallback: if role/clearance filtering yields nothing,
        # return all active segments so the UI can function in a fresh project.
        if not accessible_segments and os.getenv('FLASK_ENV', 'development') == 'development':
            all_segments = get_all_resource_segments(db, include_inactive=False)
            accessible_segments = [segment.to_public_dict() for segment in all_segments]

        # Sort by security level and name
        accessible_segments.sort(key=lambda s: (s.get('securityLevel', 0), s.get('name', '')))
        
        return jsonify({
            'success': True,
            'segments': accessible_segments,
            'count': len(accessible_segments)
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'SEGMENTS_FETCH_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('/<segment_id>', methods=['GET'])
@require_auth
def get_segment_details(segment_id):
    """
    Get detailed information about a specific resource segment
    
    Path Parameters:
        - segment_id: Resource segment ID
    
    Returns:
        Resource segment details
    """
    try:
        user_id = request.user_id
        user_role = request.user_role
        
        # Get user from database
        db = get_firestore_client()
        user = get_user_by_id(db, user_id)
        
        if not user or not user.is_active:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'USER_INACTIVE',
                    'message': 'User account is not active'
                }
            }), 403
        
        # Get resource segment
        segment = get_resource_segment_by_id(db, segment_id)
        
        if not segment:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'SEGMENT_NOT_FOUND',
                    'message': 'Resource segment not found'
                }
            }), 404
        
        # Check if user can access this segment
        user_clearance = _get_user_security_clearance(user)
        can_access, access_reason = segment.can_user_access(user_role, user_clearance)
        
        if not can_access:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'INSUFFICIENT_PERMISSIONS',
                    'message': access_reason
                }
            }), 403
        
        # Return segment details
        segment_data = segment.to_public_dict()
        segment_data['accessInfo'] = {
            'canAccess': can_access,
            'userClearance': user_clearance,
            'accessReason': access_reason
        }
        
        return jsonify({
            'success': True,
            'segment': segment_data
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'SEGMENT_FETCH_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('/', methods=['GET'])
@require_auth
def list_all_segments():
    """
    List all resource segments (admin only)
    
    Query Parameters:
        - include_inactive: Include inactive segments (default: false)
    
    Returns:
        List of all resource segments
    """
    try:
        user_role = request.user_role
        
        # Only admins can list all segments
        if user_role != 'admin':
            return jsonify({
                'success': False,
                'error': {
                    'code': 'INSUFFICIENT_PERMISSIONS',
                    'message': 'Only administrators can list all segments'
                }
            }), 403
        
        include_inactive = request.args.get('include_inactive', 'false').lower() == 'true'
        
        # Get all segments
        db = get_firestore_client()
        segments = get_all_resource_segments(db, include_inactive=include_inactive)
        
        # Convert to dictionaries
        segments_data = [segment.to_dict() for segment in segments]
        
        # Sort by security level and name
        segments_data.sort(key=lambda s: (s['securityLevel'], s['name']))
        
        return jsonify({
            'success': True,
            'segments': segments_data,
            'count': len(segments_data)
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'SEGMENTS_LIST_FAILED',
                'message': str(e)
            }
        }), 500


def _get_user_security_clearance(user) -> int:
    """Get user's security clearance level based on role"""
    role_clearance = {
        'student': 1,
        'visitor': 1,
        'user': 3,      # Give users level 3 clearance (same as faculty)
        'faculty': 3,
        'admin': 5
    }
    return role_clearance.get(user.role, 1)