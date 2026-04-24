"""
API Request/Response Validation Service
Implements JSON schema validation for API endpoints
"""

from typing import Dict, Any, Optional, List
from marshmallow import Schema, fields, validate, ValidationError, post_load
from flask import request, jsonify
from functools import wraps
from app.utils.error_handler import AppError
from app.services.audit_logger import audit_logger


# Base schemas for common data types
class TimestampField(fields.DateTime):
    """Custom timestamp field"""
    default_format = 'iso'


class UUIDField(fields.String):
    """Custom UUID field with validation"""
    def __init__(self, **kwargs):
        super().__init__(validate=validate.Regexp(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            error='Invalid UUID format'
        ), **kwargs)


# Device Registration Schemas
class DeviceFingerprintSchema(Schema):
    """Schema for device fingerprint data"""
    canvas = fields.Dict(required=True)
    webgl = fields.Dict(required=True)
    audio = fields.Dict(required=True)
    screen = fields.Dict(required=True)
    system = fields.Dict(required=True)
    fonts = fields.List(fields.String(), required=True)
    plugins = fields.List(fields.String(), required=True)


class DeviceRegistrationSchema(Schema):
    """Schema for device registration request"""
    device_name = fields.String(required=True, validate=validate.Length(min=1, max=100))
    fingerprint_data = fields.Nested(DeviceFingerprintSchema, required=True)
    user_agent = fields.String(required=True)
    
    @post_load
    def validate_fingerprint(self, data, **kwargs):
        """Additional validation for fingerprint data"""
        fingerprint = data['fingerprint_data']
        
        # Validate canvas data
        if 'hash' not in fingerprint['canvas']:
            raise ValidationError('Canvas hash is required')
        
        # Validate WebGL data
        if 'renderer' not in fingerprint['webgl'] or 'vendor' not in fingerprint['webgl']:
            raise ValidationError('WebGL renderer and vendor are required')
        
        return data


class DeviceValidationSchema(Schema):
    """Schema for device validation request"""
    fingerprint_data = fields.Nested(DeviceFingerprintSchema, required=True)


# Visitor Management Schemas
class VisitorRegistrationSchema(Schema):
    """Schema for visitor registration request"""
    name = fields.String(required=True, validate=validate.Length(min=1, max=100))
    email = fields.Email(required=False, allow_none=True)
    phone = fields.String(required=True, validate=validate.Length(min=10, max=20))
    visit_purpose = fields.String(required=True, validate=validate.Length(min=10, max=500))
    expected_duration = fields.Integer(required=True, validate=validate.Range(min=1, max=8))
    photo = fields.String(required=False, allow_none=True)  # Base64 encoded image
    assigned_route = fields.Dict(required=True)
    
    @post_load
    def validate_route(self, data, **kwargs):
        """Validate assigned route data"""
        route = data['assigned_route']
        if 'allowed_segments' not in route or not isinstance(route['allowed_segments'], list):
            raise ValidationError('Route must include allowed_segments list')
        return data


class VisitorUpdateSchema(Schema):
    """Schema for visitor update request"""
    status = fields.String(validate=validate.OneOf(['active', 'completed', 'expired', 'terminated']))
    additional_hours = fields.Integer(validate=validate.Range(min=1, max=4))
    termination_reason = fields.String(validate=validate.Length(max=500))


# Access Request Schemas
class JITAccessRequestSchema(Schema):
    """Schema for JIT access request"""
    resource_segment_id = UUIDField(required=True)
    justification = fields.String(required=True, validate=validate.Length(min=50, max=1000))
    requested_duration = fields.Integer(required=True, validate=validate.Range(min=1, max=24))
    urgency = fields.String(validate=validate.OneOf(['low', 'medium', 'high']))


class EmergencyAccessRequestSchema(Schema):
    """Schema for emergency access request"""
    emergency_type = fields.String(required=True, validate=validate.OneOf([
        'system_outage', 'security_incident', 'data_recovery', 'critical_maintenance'
    ]))
    urgency_level = fields.String(required=True, validate=validate.OneOf(['critical', 'high', 'medium']))
    justification = fields.String(required=True, validate=validate.Length(min=100, max=2000))
    required_resources = fields.List(UUIDField(), required=True, validate=validate.Length(min=1))
    estimated_duration = fields.Integer(required=True, validate=validate.Range(min=1, max=2))


class AccessApprovalSchema(Schema):
    """Schema for access approval/denial"""
    decision = fields.String(required=True, validate=validate.OneOf(['approved', 'denied']))
    comments = fields.String(validate=validate.Length(max=500))
    approved_duration = fields.Integer(validate=validate.Range(min=1, max=24))


# Audit Log Schemas
class AuditLogQuerySchema(Schema):
    """Schema for audit log query parameters"""
    start_date = TimestampField(required=False)
    end_date = TimestampField(required=False)
    event_type = fields.String(validate=validate.OneOf([
        'authentication', 'access_request', 'jit_access', 'break_glass',
        'device_registration', 'visitor_management', 'policy_change', 'admin_action'
    ]))
    user_id = fields.String()
    severity = fields.String(validate=validate.OneOf(['low', 'medium', 'high', 'critical']))
    limit = fields.Integer(validate=validate.Range(min=1, max=1000), load_default=100)
    offset = fields.Integer(validate=validate.Range(min=0), load_default=0)


# Response Schemas
class SuccessResponseSchema(Schema):
    """Schema for successful API responses"""
    success = fields.Boolean(dump_default=True)
    data = fields.Raw()
    message = fields.String()


class ErrorResponseSchema(Schema):
    """Schema for error API responses"""
    success = fields.Boolean(dump_default=False)
    error = fields.Dict(required=True)


class PaginatedResponseSchema(Schema):
    """Schema for paginated responses"""
    success = fields.Boolean(dump_default=True)
    data = fields.List(fields.Raw())
    pagination = fields.Dict(required=True)


# OAuth Schemas
class OAuthTokenRequestSchema(Schema):
    """Schema for OAuth token request"""
    grant_type = fields.String(required=True, validate=validate.OneOf([
        'authorization_code', 'refresh_token', 'client_credentials'
    ]))
    code = fields.String()  # Required for authorization_code
    redirect_uri = fields.String()  # Required for authorization_code
    refresh_token = fields.String()  # Required for refresh_token
    code_verifier = fields.String()  # Required for PKCE
    client_id = fields.String(required=True)
    client_secret = fields.String()
    scope = fields.String()


class OAuthAuthorizationSchema(Schema):
    """Schema for OAuth authorization request"""
    response_type = fields.String(required=True, validate=validate.OneOf(['code']))
    client_id = fields.String(required=True)
    redirect_uri = fields.String(required=True)
    scope = fields.String()
    state = fields.String()
    code_challenge = fields.String(required=True)  # PKCE
    code_challenge_method = fields.String(required=True, validate=validate.OneOf(['S256']))


class APIValidator:
    """API request/response validation service"""
    
    def __init__(self):
        self.schemas = {
            # Device endpoints
            'device_registration': DeviceRegistrationSchema(),
            'device_validation': DeviceValidationSchema(),
            
            # Visitor endpoints
            'visitor_registration': VisitorRegistrationSchema(),
            'visitor_update': VisitorUpdateSchema(),
            
            # Access request endpoints
            'jit_access_request': JITAccessRequestSchema(),
            'emergency_access_request': EmergencyAccessRequestSchema(),
            'access_approval': AccessApprovalSchema(),
            
            # Audit endpoints
            'audit_log_query': AuditLogQuerySchema(),
            
            # OAuth endpoints
            'oauth_token_request': OAuthTokenRequestSchema(),
            'oauth_authorization': OAuthAuthorizationSchema(),
            
            # Response schemas
            'success_response': SuccessResponseSchema(),
            'error_response': ErrorResponseSchema(),
            'paginated_response': PaginatedResponseSchema()
        }
    
    def validate_request(self, schema_name: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate request data against schema"""
        if schema_name not in self.schemas:
            raise AppError('INVALID_SCHEMA', f'Unknown schema: {schema_name}', 500)
        
        schema = self.schemas[schema_name]
        
        try:
            validated_data = schema.load(data)
            return validated_data
        except ValidationError as e:
            # Log validation error
            audit_logger.log_event(
                event_type='validation_error',
                user_id=getattr(request, 'user_id', None),
                action='request_validation',
                resource=request.path,
                result='failure',
                details={
                    'schema': schema_name,
                    'errors': e.messages,
                    'invalid_data': data
                },
                severity='low'
            )
            
            raise AppError(
                'VALIDATION_ERROR',
                'Request validation failed',
                400,
                details={'validation_errors': e.messages}
            )
    
    def validate_response(self, schema_name: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate response data against schema"""
        if schema_name not in self.schemas:
            return data  # Skip validation for unknown schemas
        
        schema = self.schemas[schema_name]
        
        try:
            validated_data = schema.dump(data)
            return validated_data
        except ValidationError as e:
            # Log response validation error (this shouldn't happen in production)
            audit_logger.log_event(
                event_type='response_validation_error',
                user_id=getattr(request, 'user_id', None),
                action='response_validation',
                resource=request.path,
                result='failure',
                details={
                    'schema': schema_name,
                    'errors': e.messages
                },
                severity='high'
            )
            
            # Return original data if validation fails (don't break the response)
            return data
    
    def get_schema_documentation(self, schema_name: str) -> Dict[str, Any]:
        """Get schema documentation for API docs"""
        if schema_name not in self.schemas:
            return {}
        
        schema = self.schemas[schema_name]
        
        # Generate field documentation
        fields_doc = {}
        for field_name, field_obj in schema.fields.items():
            field_doc = {
                'type': type(field_obj).__name__,
                'required': field_obj.required,
                'allow_none': field_obj.allow_none
            }
            
            # Add validation info
            if hasattr(field_obj, 'validate') and field_obj.validate:
                if isinstance(field_obj.validate, validate.Length):
                    field_doc['min_length'] = field_obj.validate.min
                    field_doc['max_length'] = field_obj.validate.max
                elif isinstance(field_obj.validate, validate.Range):
                    field_doc['min_value'] = field_obj.validate.min
                    field_doc['max_value'] = field_obj.validate.max
                elif isinstance(field_obj.validate, validate.OneOf):
                    field_doc['choices'] = field_obj.validate.choices
            
            fields_doc[field_name] = field_doc
        
        return {
            'schema_name': schema_name,
            'fields': fields_doc
        }


# Global validator instance
api_validator = APIValidator()


def validate_json(schema_name: str, location: str = 'json'):
    """
    Decorator to validate JSON request data
    
    Args:
        schema_name: Name of the schema to use for validation
        location: Where to get data from ('json', 'args', 'form')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get data based on location
            if location == 'json':
                data = request.get_json(force=True) or {}
            elif location == 'args':
                data = request.args.to_dict()
            elif location == 'form':
                data = request.form.to_dict()
            else:
                raise AppError('INVALID_LOCATION', f'Invalid data location: {location}', 500)
            
            # Validate data
            validated_data = api_validator.validate_request(schema_name, data)
            
            # Add validated data to request context
            request.validated_data = validated_data
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def validate_response(schema_name: str):
    """
    Decorator to validate API response data
    
    Args:
        schema_name: Name of the schema to use for validation
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            response = f(*args, **kwargs)
            
            # Handle different response formats
            if isinstance(response, tuple):
                data, status_code = response
                if isinstance(data, dict):
                    validated_data = api_validator.validate_response(schema_name, data)
                    return validated_data, status_code
                return response
            elif isinstance(response, dict):
                validated_data = api_validator.validate_response(schema_name, response)
                return validated_data
            else:
                return response
        
        return decorated_function
    return decorator