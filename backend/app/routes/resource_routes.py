"""
Resource Routes

API endpoints for resource segment management and access control.
"""

import logging
from datetime import datetime
from flask import Blueprint, request, jsonify
from functools import wraps

from ..middleware.authorization import require_auth, require_role
from ..utils.error_handler import ValidationError, NotFoundError, AuthorizationError
from ..services.resource_segment_service import get_resource_segment_service
from ..firebase_config import get_firestore_client

logger = logging.getLogger(__name__)

resource_bp = Blueprint('resource', __name__, url_prefix='/api/resources')


def handle_resource_errors(f):
    """Decorator to handle resource service errors"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
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


@resource_bp.route('/segments', methods=['GET'])
@require_auth
@handle_resource_errors
async def get_resource_segments():
    """
    Get available resource segments
    
    Returns list of resource segments that the user can access or assign to visitors.
    Filters based on user role and security clearance.
    
    Returns:
        JSON response with list of resource segments
    """
    try:
        # Get service instance
        db = get_firestore_client()
        service = get_resource_segment_service(db)
        
        # Get segments for the current user
        include_visitor_segments = request.user_role in ['faculty', 'admin']
        segments = await service.get_segments_for_user(request.user_id, include_visitor_segments)
        
        return jsonify({
            'success': True,
            'segments': [segment.to_public_dict() for segment in segments],
            'count': len(segments)
        })
        
    except Exception as e:
        logger.error(f"Error retrieving resource segments: {str(e)}")
        return jsonify({'error': 'Failed to retrieve resource segments'}), 500


@resource_bp.route('/segments/<segment_id>', methods=['GET'])
@require_auth
@handle_resource_errors
async def get_resource_segment(segment_id):
    """
    Get detailed information about a specific resource segment
    
    Args:
        segment_id: Resource segment ID
        
    Returns:
        JSON response with detailed segment information
    """
    try:
        # Get service instance
        db = get_firestore_client()
        service = get_resource_segment_service(db)
        
        # Get segment with access control
        segment = await service.get_segment(segment_id, request.user_id)
        
        if not segment:
            return jsonify({'error': 'Resource segment not found or access denied'}), 404
        
        return jsonify({
            'success': True,
            'segment': segment.to_public_dict()
        })
        
    except Exception as e:
        logger.error(f"Error retrieving resource segment {segment_id}: {str(e)}")
        return jsonify({'error': 'Failed to retrieve resource segment'}), 500


@resource_bp.route('/segments/<segment_id>/access-check', methods=['POST'])
@require_auth
@handle_resource_errors
async def check_segment_access(segment_id):
    """
    Check if a user or visitor can access a specific resource segment
    
    Args:
        segment_id: Resource segment ID
        
    Request Body:
        user_id: User ID to check (optional, defaults to current user)
        visitor_id: Visitor ID to check (optional)
        action: Action being performed
        
    Returns:
        JSON response with access decision
    """
    try:
        data = request.get_json() or {}
        user_id = data.get('user_id', request.user_id)
        visitor_id = data.get('visitor_id')
        action = data.get('action', 'access')
        
        # Get service instance
        db = get_firestore_client()
        service = get_resource_segment_service(db)
        
        # If checking visitor access, use visitor service
        if visitor_id:
            from ..services.visitor_service import visitor_service
            access_granted = await visitor_service.track_visitor_access(
                visitor_id, segment_id, action, request.user_id
            )
            reason = "Route compliance check" if access_granted else "Route violation detected"
        else:
            # Check user access permission
            access_granted, reason, additional_info = await service.check_access_permission(
                user_id, segment_id, action
            )
        
        return jsonify({
            'success': True,
            'access_granted': access_granted,
            'reason': reason,
            'segment_id': segment_id,
            'user_id': user_id,
            'visitor_id': visitor_id,
            'action': action,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error checking segment access: {str(e)}")
        return jsonify({'error': 'Failed to check segment access'}), 500


# Error handlers for the blueprint
@resource_bp.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad request'}), 400


@resource_bp.errorhandler(401)
def unauthorized(error):
    return jsonify({'error': 'Unauthorized'}), 401


@resource_bp.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Forbidden'}), 403


@resource_bp.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404


@resource_bp.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500