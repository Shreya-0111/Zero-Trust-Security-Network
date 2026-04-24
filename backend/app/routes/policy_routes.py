"""
Policy Routes
API endpoints for policy configuration and management
"""

from flask import Blueprint, request, jsonify
from app.middleware.authorization import require_auth, require_admin, get_current_user
from app.models.policy import (
    create_policy, get_policy_by_id, get_all_policies, 
    update_policy, delete_policy, Policy
)
from app.firebase_config import get_firestore_client
from app.services.audit_logger import audit_logger
from datetime import datetime

bp = Blueprint('policy', __name__, url_prefix='/api')


def get_client_ip():
    """Get client IP address from request"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr


@bp.route('/admin/policy', methods=['POST'])
@require_auth
@require_admin
def create_or_update_policy():
    """
    Create or update access policy (Admin only)
    
    Request Body:
        - policyId: Policy ID (optional, for updates)
        - name: Policy name (required)
        - description: Policy description (required)
        - rules: List of policy rules (required)
        - priority: Policy priority (optional, default: 0)
    
    Returns:
        Created or updated policy data
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
                    'message': 'No policy data provided'
                }
            }), 400
        
        db = get_firestore_client()
        if not db:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'FIRESTORE_UNAVAILABLE',
                    'message': 'Firestore is not available in this environment'
                }
            }), 503
        
        # Check if this is an update (policyId provided)
        policy_id = data.get('policyId')
        
        if policy_id:
            # Update existing policy
            existing_policy = get_policy_by_id(db, policy_id)
            
            if not existing_policy:
                return jsonify({
                    'success': False,
                    'error': {
                        'code': 'POLICY_NOT_FOUND',
                        'message': 'Policy not found'
                    }
                }), 404
            
            # Store old values for audit log
            old_policy_data = existing_policy.to_dict()
            
            # Prepare update data
            update_data = {}
            
            if 'name' in data:
                # Check if new name conflicts with another policy
                if data['name'] != existing_policy.name:
                    policies_ref = db.collection('policies')
                    existing = policies_ref.where('name', '==', data['name']).limit(1).stream()
                    if any(existing):
                        return jsonify({
                            'success': False,
                            'error': {
                                'code': 'VALIDATION_ERROR',
                                'message': f"Policy with name '{data['name']}' already exists"
                            }
                        }), 400
                update_data['name'] = data['name']
            
            if 'description' in data:
                update_data['description'] = data['description']
            
            if 'rules' in data:
                # Validate rules
                temp_policy = Policy(
                    name=data.get('name', existing_policy.name),
                    description=data.get('description', existing_policy.description),
                    rules=data['rules'],
                    priority=data.get('priority', existing_policy.priority)
                )
                
                is_valid, error_message = temp_policy.validate()
                if not is_valid:
                    return jsonify({
                        'success': False,
                        'error': {
                            'code': 'VALIDATION_ERROR',
                            'message': error_message
                        }
                    }), 400
                
                update_data['rules'] = data['rules']
            
            if 'priority' in data:
                if not isinstance(data['priority'], int):
                    return jsonify({
                        'success': False,
                        'error': {
                            'code': 'VALIDATION_ERROR',
                            'message': 'Priority must be an integer'
                        }
                    }), 400
                update_data['priority'] = data['priority']
            
            if 'isActive' in data:
                update_data['isActive'] = data['isActive']
            
            # Update policy
            update_policy(db, policy_id, update_data, modified_by=admin_id)
            
            # Get updated policy
            updated_policy = get_policy_by_id(db, policy_id)
            
            # Log policy change
            audit_logger.log_policy_change(
                admin_id=admin_id,
                policy_id=policy_id,
                action='update',
                changes={
                    'action': 'update',
                    'updatedFields': list(update_data.keys()),
                    'oldValues': {k: old_policy_data.get(k) for k in update_data.keys()},
                    'newValues': update_data
                },
                ip_address=ip_address
            )
            
            return jsonify({
                'success': True,
                'policyId': policy_id,
                'policy': updated_policy.to_dict(),
                'message': 'Policy updated successfully'
            }), 200
        
        else:
            # Create new policy
            name = data.get('name')
            description = data.get('description', '')
            rules = data.get('rules', [])
            priority = data.get('priority', 0)
            
            # Validate required fields
            if not name:
                return jsonify({
                    'success': False,
                    'error': {
                        'code': 'VALIDATION_ERROR',
                        'message': 'Policy name is required'
                    }
                }), 400
            
            if not rules or len(rules) == 0:
                return jsonify({
                    'success': False,
                    'error': {
                        'code': 'VALIDATION_ERROR',
                        'message': 'At least one rule is required'
                    }
                }), 400
            
            # Validate priority
            if not isinstance(priority, int):
                return jsonify({
                    'success': False,
                    'error': {
                        'code': 'VALIDATION_ERROR',
                        'message': 'Priority must be an integer'
                    }
                }), 400
            
            # Create policy
            try:
                policy = create_policy(
                    db=db,
                    name=name,
                    description=description,
                    rules=rules,
                    priority=priority,
                    created_by=admin_id
                )
            except Exception as e:
                return jsonify({
                    'success': False,
                    'error': {
                        'code': 'POLICY_CREATION_FAILED',
                        'message': str(e)
                    }
                }), 400
            
            # Log policy creation
            audit_logger.log_policy_change(
                admin_id=admin_id,
                policy_id=policy.policy_id,
                action='create',
                changes={
                    'action': 'create',
                    'policyData': policy.to_dict()
                },
                ip_address=ip_address
            )
            
            return jsonify({
                'success': True,
                'policyId': policy.policy_id,
                'policy': policy.to_dict(),
                'message': 'Policy created successfully'
            }), 201
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'POLICY_OPERATION_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('/policy/rules', methods=['GET'])
@require_auth
def get_policy_rules():
    """
    Get all active policy rules
    
    Query Parameters:
        - includeInactive: Include inactive policies (optional, admin only)
    
    Returns:
        List of policy rules
    """
    try:
        current_user = get_current_user()
        user_role = current_user.get('role')
        
        # Check if user wants inactive policies (admin only)
        include_inactive = request.args.get('includeInactive', 'false').lower() == 'true'
        
        if include_inactive and user_role != 'admin':
            return jsonify({
                'success': False,
                'error': {
                    'code': 'INSUFFICIENT_PERMISSIONS',
                    'message': 'Only administrators can view inactive policies'
                }
            }), 403
        
        db = get_firestore_client()
        if not db:
            return jsonify({
                'success': True,
                'policies': [],
                'totalCount': 0
            }), 200
        
        # Get policies
        active_only = not include_inactive
        policies = get_all_policies(db, active_only=active_only)
        
        # Convert to dict format
        policies_data = [policy.to_dict() for policy in policies]
        
        # Convert timestamps to ISO format for JSON serialization
        for policy_data in policies_data:
            if 'createdAt' in policy_data:
                if hasattr(policy_data['createdAt'], 'isoformat'):
                    policy_data['createdAt'] = policy_data['createdAt'].isoformat()
                else:
                    policy_data['createdAt'] = str(policy_data['createdAt'])
            
            if 'lastModified' in policy_data:
                if hasattr(policy_data['lastModified'], 'isoformat'):
                    policy_data['lastModified'] = policy_data['lastModified'].isoformat()
                else:
                    policy_data['lastModified'] = str(policy_data['lastModified'])
        
        return jsonify({
            'success': True,
            'policies': policies_data,
            'totalCount': len(policies_data)
        }), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'POLICY_RETRIEVAL_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('/admin/policy/<policy_id>', methods=['GET'])
@require_auth
@require_admin
def get_policy(policy_id):
    """
    Get specific policy by ID (Admin only)
    
    Args:
        policy_id: Policy ID
    
    Returns:
        Policy data
    """
    try:
        db = get_firestore_client()
        if not db:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'FIRESTORE_UNAVAILABLE',
                    'message': 'Firestore is not available in this environment'
                }
            }), 503
        policy = get_policy_by_id(db, policy_id)
        
        if not policy:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'POLICY_NOT_FOUND',
                    'message': 'Policy not found'
                }
            }), 404
        
        policy_data = policy.to_dict()
        
        # Convert timestamps to ISO format
        if 'createdAt' in policy_data:
            if hasattr(policy_data['createdAt'], 'isoformat'):
                policy_data['createdAt'] = policy_data['createdAt'].isoformat()
            else:
                policy_data['createdAt'] = str(policy_data['createdAt'])
        
        if 'lastModified' in policy_data:
            if hasattr(policy_data['lastModified'], 'isoformat'):
                policy_data['lastModified'] = policy_data['lastModified'].isoformat()
            else:
                policy_data['lastModified'] = str(policy_data['lastModified'])
        
        return jsonify({
            'success': True,
            'policy': policy_data
        }), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'POLICY_RETRIEVAL_FAILED',
                'message': str(e)
            }
        }), 500


@bp.route('/admin/policy/<policy_id>', methods=['DELETE'])
@require_auth
@require_admin
def delete_policy_route(policy_id):
    """
    Delete (deactivate) policy (Admin only)
    
    Args:
        policy_id: Policy ID
    
    Returns:
        Success message
    """
    try:
        current_user = get_current_user()
        admin_id = current_user['user_id']
        ip_address = get_client_ip()
        
        db = get_firestore_client()
        if not db:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'FIRESTORE_UNAVAILABLE',
                    'message': 'Firestore is not available in this environment'
                }
            }), 503
        
        # Get policy before deletion for audit log
        policy = get_policy_by_id(db, policy_id)
        
        if not policy:
            return jsonify({
                'success': False,
                'error': {
                    'code': 'POLICY_NOT_FOUND',
                    'message': 'Policy not found'
                }
            }), 404
        
        # Soft delete policy
        delete_policy(db, policy_id)
        
        # Log policy deletion
        audit_logger.log_policy_change(
            admin_id=admin_id,
            policy_id=policy_id,
            action='delete',
            changes={
                'action': 'delete',
                'policyData': policy.to_dict()
            },
            ip_address=ip_address
        )
        
        return jsonify({
            'success': True,
            'message': 'Policy deactivated successfully'
        }), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': {
                'code': 'POLICY_DELETE_FAILED',
                'message': str(e)
            }
        }), 500
