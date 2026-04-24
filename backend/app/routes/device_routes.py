"""
Device Fingerprint API Routes
Handles device registration, validation, and management
"""

from flask import Blueprint, request, jsonify
from flask_cors import cross_origin
from app.services.device_fingerprint_service import DeviceFingerprintService
from app.services.auth_service_simple import auth_service
from app.services.audit_logger import AuditLogger
from app.middleware.authorization import require_auth, require_role
from app.utils.error_handler import handle_api_error
import logging

logger = logging.getLogger(__name__)

device_bp = Blueprint('device', __name__, url_prefix='/api/devices')
device_service = DeviceFingerprintService()
auth_service = auth_service
audit_logger = AuditLogger()

@device_bp.route('/register', methods=['POST'])
@require_auth
@handle_api_error
def register_device():
    """Register a new device fingerprint for a user"""
    try:
        data = request.get_json()
        user_id = data.get('userId')
        fingerprint_data = data.get('fingerprintData')
        device_name = data.get('deviceName', 'Unknown Device')
        mfa_verified = data.get('mfaVerified', False)
        
        if not user_id or not fingerprint_data:
            return jsonify({
                "success": False,
                "error": {
                    "code": "MISSING_REQUIRED_FIELDS",
                    "message": "User ID and fingerprint data are required"
                }
            }), 400
        
        # Validate user authorization
        current_user = request.current_user
        if current_user['uid'] != user_id and current_user.get('role') != 'admin':
            return jsonify({
                "success": False,
                "error": {
                    "code": "UNAUTHORIZED",
                    "message": "Cannot register device for another user"
                }
            }), 403
        
        # Add device name to fingerprint data
        fingerprint_data['deviceName'] = device_name
        
        # Detect anomalies in fingerprint
        anomalies = device_service.detect_fingerprint_anomalies(fingerprint_data)
        if anomalies:
            logger.warning(f"Fingerprint anomalies detected for user {user_id}: {anomalies}")
        
        # Register device with MFA consideration
        result = device_service.register_device(user_id, fingerprint_data, mfa_verified)
        
        # Log the registration attempt
        audit_logger.log_event(
            event_type="device_registration",
            user_id=user_id,
            action="register_device",
            resource="device_fingerprint",
            result="success" if result.get("success") else "failure",
            details={
                "device_id": result.get("deviceId"),
                "anomalies_detected": anomalies,
                "fingerprint_components": list(fingerprint_data.keys()),
                "mfa_verified": mfa_verified
            },
            ip_address=request.remote_addr,
            severity="medium"
        )
        
        if result.get("success"):
            return jsonify(result), 200
        else:
            return jsonify(result), 400
            
    except Exception as e:
        logger.error(f"Device registration error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": {
                "code": "REGISTRATION_ERROR",
                "message": f"Failed to register device: {str(e)}"
            }
        }), 500

@device_bp.route('/validate', methods=['POST'])
@require_auth
@handle_api_error
def validate_device():
    """Validate device fingerprint against stored fingerprints"""
    try:
        data = request.get_json()
        user_id = data.get('userId')
        current_fingerprint = data.get('currentFingerprint')
        
        if not user_id or not current_fingerprint:
            return jsonify({
                "success": False,
                "error": {
                    "code": "MISSING_REQUIRED_FIELDS",
                    "message": "User ID and current fingerprint are required"
                }
            }), 400
        
        # Validate user authorization
        current_user = request.current_user
        if current_user['uid'] != user_id and current_user.get('role') != 'admin':
            return jsonify({
                "success": False,
                "error": {
                    "code": "UNAUTHORIZED",
                    "message": "Cannot validate device for another user"
                }
            }), 403
        
        # Validate fingerprint
        result = device_service.validate_fingerprint(user_id, current_fingerprint)
        
        # Update trust score based on validation result
        if result.get("deviceId"):
            device_service.update_fingerprint_trust_score(
                result["deviceId"], 
                result.get("approved", False)
            )
        
        # Log the validation attempt
        audit_logger.log_event(
            event_type="device_validation",
            user_id=user_id,
            action="validate_fingerprint",
            resource="device_fingerprint",
            result="success" if result.get("approved") else "failure",
            details={
                "device_id": result.get("deviceId"),
                "similarity_score": result.get("similarity", 0),
                "trust_score": result.get("trustScore"),
                "requires_additional_verification": result.get("requires_additional_verification", False)
            },
            ip_address=request.remote_addr,
            severity="low" if result.get("approved") else "medium"
        )
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Device validation error: {str(e)}")
        return jsonify({
            "success": False,
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "Failed to validate device fingerprint"
            }
        }), 500

@device_bp.route('/list/<user_id>', methods=['GET'])
@require_auth
@handle_api_error
def list_user_devices(user_id):
    """Get list of registered devices for a user"""
    try:
        # Validate user authorization
        current_user = request.current_user
        if current_user['uid'] != user_id and current_user.get('role') != 'admin':
            return jsonify({
                "success": False,
                "error": {
                    "code": "UNAUTHORIZED",
                    "message": "Cannot access devices for another user"
                }
            }), 403
        
        # Get user devices
        devices = device_service._get_user_devices(user_id)
        
        # Remove sensitive data from response
        safe_devices = []
        for device in devices:
            safe_device = {
                "deviceId": device.get("deviceId"),
                "deviceName": device.get("deviceName"),
                "trustScore": device.get("trustScore"),
                "registeredAt": device.get("registeredAt"),
                "lastVerified": device.get("lastVerified"),
                "isActive": device.get("isActive"),
                "verificationCount": len(device.get("verificationHistory", []))
            }
            safe_devices.append(safe_device)
        
        return jsonify({
            "success": True,
            "devices": safe_devices,
            "totalCount": len(safe_devices)
        }), 200
        
    except Exception as e:
        logger.error(f"Device list error: {str(e)}")
        return jsonify({
            "success": False,
            "error": {
                "code": "LIST_ERROR",
                "message": "Failed to retrieve device list"
            }
        }), 500

@device_bp.route('/<device_id>', methods=['DELETE'])
@require_auth
@handle_api_error
def remove_device(device_id):
    """Remove/deactivate a registered device"""
    try:
        current_user = request.current_user
        
        # Get device information
        from firebase_admin import firestore
        db = firestore.client()
        device_ref = db.collection('deviceFingerprints').document(device_id)
        device_doc = device_ref.get()
        
        if not device_doc.exists:
            return jsonify({
                "success": False,
                "error": {
                    "code": "DEVICE_NOT_FOUND",
                    "message": "Device not found"
                }
            }), 404
        
        device_data = device_doc.to_dict()
        
        # Validate user authorization
        if current_user['uid'] != device_data.get('userId') and current_user.get('role') != 'admin':
            return jsonify({
                "success": False,
                "error": {
                    "code": "UNAUTHORIZED",
                    "message": "Cannot remove device for another user"
                }
            }), 403
        
        # Deactivate device (soft delete)
        device_ref.update({
            "isActive": False,
            "deactivatedAt": firestore.SERVER_TIMESTAMP,
            "deactivatedBy": current_user['uid']
        })
        
        # Log the device removal
        audit_logger.log_event(
            event_type="device_removal",
            user_id=device_data.get('userId'),
            action="remove_device",
            resource="device_fingerprint",
            result="success",
            details={
                "device_id": device_id,
                "device_name": device_data.get("deviceName"),
                "removed_by": current_user['uid']
            },
            ip_address=request.remote_addr,
            severity="medium"
        )
        
        return jsonify({
            "success": True,
            "message": "Device removed successfully"
        }), 200
        
    except Exception as e:
        logger.error(f"Device removal error: {str(e)}")
        return jsonify({
            "success": False,
            "error": {
                "code": "REMOVAL_ERROR",
                "message": "Failed to remove device"
            }
        }), 500

@device_bp.route('/admin/cleanup', methods=['POST'])
@cross_origin()
@require_auth
@require_role('admin')
@handle_api_error
def cleanup_expired_devices():
    """Admin endpoint to cleanup expired device fingerprints"""
    try:
        current_user = request.current_user
        
        # Perform cleanup
        cleanup_count = device_service.cleanup_expired_fingerprints()
        
        # Log the cleanup operation
        audit_logger.log_event(
            event_type="admin_action",
            user_id=current_user['uid'],
            action="cleanup_expired_devices",
            resource="device_fingerprints",
            result="success",
            details={
                "devices_cleaned": cleanup_count
            },
            ip_address=request.remote_addr,
            severity="low"
        )
        
        return jsonify({
            "success": True,
            "message": f"Cleaned up {cleanup_count} expired device fingerprints",
            "cleanupCount": cleanup_count
        }), 200
        
    except Exception as e:
        logger.error(f"Device cleanup error: {str(e)}")
        return jsonify({
            "success": False,
            "error": {
                "code": "CLEANUP_ERROR",
                "message": "Failed to cleanup expired devices"
            }
        }), 500

@device_bp.route('/admin/stats', methods=['GET'])
@cross_origin()
@require_auth
@require_role('admin')
@handle_api_error
def get_device_statistics():
    """Admin endpoint to get device fingerprint statistics"""
    try:
        from firebase_admin import firestore
        db = firestore.client()
        
        # Get device statistics
        devices_ref = db.collection('deviceFingerprints')
        
        # Total devices
        total_devices = len(devices_ref.get())
        
        # Active devices
        active_devices = len(devices_ref.where('isActive', '==', True).get())
        
        # Devices by trust score ranges
        high_trust = len(devices_ref.where('trustScore', '>=', 80).get())
        medium_trust = len(devices_ref.where('trustScore', '>=', 60).where('trustScore', '<', 80).get())
        low_trust = len(devices_ref.where('trustScore', '<', 60).get())
        
        # Recent registrations (last 7 days)
        from datetime import datetime, timedelta
        week_ago = datetime.utcnow() - timedelta(days=7)
        recent_registrations = len(devices_ref.where('registeredAt', '>=', week_ago).get())
        
        stats = {
            "totalDevices": total_devices,
            "activeDevices": active_devices,
            "inactiveDevices": total_devices - active_devices,
            "trustScoreDistribution": {
                "high": high_trust,
                "medium": medium_trust,
                "low": low_trust
            },
            "recentRegistrations": recent_registrations
        }
        
        return jsonify({
            "success": True,
            "statistics": stats
        }), 200
        
    except Exception as e:
        logger.error(f"Device statistics error: {str(e)}")
        return jsonify({
            "success": False,
            "error": {
                "code": "STATISTICS_ERROR",
                "message": "Failed to retrieve device statistics"
            }
        }), 500