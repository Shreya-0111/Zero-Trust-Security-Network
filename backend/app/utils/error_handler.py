"""
Error Handler Utility
Centralized error handling and logging for the backend
"""

from flask import jsonify
from functools import wraps
import traceback
import sys
from app.services.audit_logger import audit_logger
import inspect


class AppError(Exception):
    """Base application error class"""
    def __init__(self, message, code='INTERNAL_ERROR', status_code=500, details=None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}


class ValidationError(AppError):
    """Validation error"""
    def __init__(self, message, field=None, details=None):
        super().__init__(
            message=message,
            code='VALIDATION_ERROR',
            status_code=400,
            details=details or {'field': field} if field else details
        )


class AuthenticationError(AppError):
    """Authentication error"""
    def __init__(self, message, code='AUTH_FAILED'):
        super().__init__(
            message=message,
            code=code,
            status_code=401
        )


class AuthorizationError(AppError):
    """Authorization error"""
    def __init__(self, message, code='INSUFFICIENT_PERMISSIONS'):
        super().__init__(
            message=message,
            code=code,
            status_code=403
        )


class NotFoundError(AppError):
    """Resource not found error"""
    def __init__(self, message, resource_type=None):
        super().__init__(
            message=message,
            code='RESOURCE_NOT_FOUND',
            status_code=404,
            details={'resourceType': resource_type} if resource_type else {}
        )


class RateLimitError(AppError):
    """Rate limit exceeded error"""
    def __init__(self, message='Too many requests. Please try again later.'):
        super().__init__(
            message=message,
            code='RATE_LIMIT_EXCEEDED',
            status_code=429
        )


def create_error_response(error, include_details=True):
    """
    Create standardized error response
    
    Args:
        error: Exception object
        include_details: Whether to include error details (False in production)
    
    Returns:
        tuple: (response_dict, status_code)
    """
    if isinstance(error, AppError):
        response = {
            'success': False,
            'error': {
                'code': error.code,
                'message': error.message
            }
        }
        
        if include_details and error.details:
            response['error']['details'] = error.details
        
        return response, error.status_code
    
    # Handle unexpected errors
    error_message = str(error) if str(error) else 'An unexpected error occurred'
    
    response = {
        'success': False,
        'error': {
            'code': 'INTERNAL_ERROR',
            'message': error_message if include_details else 'An unexpected error occurred'
        }
    }
    
    return response, 500


def handle_errors(f):
    """
    Decorator for handling errors in route handlers
    Logs errors to audit system and returns standardized error responses
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except AppError as e:
            # Log application errors
            severity = 'medium' if e.status_code < 500 else 'high'
            
            try:
                audit_logger.log_event(
                    event_type='application_error',
                    user_id=getattr(kwargs.get('request'), 'user_id', None),
                    action=f.__name__,
                    resource=f.__module__,
                    result='failure',
                    details={
                        'error_code': e.code,
                        'error_message': e.message,
                        'status_code': e.status_code
                    },
                    severity=severity
                )
            except Exception as log_error:
                print(f"Failed to log error: {log_error}", file=sys.stderr)
            
            response, status_code = create_error_response(e, include_details=True)
            return jsonify(response), status_code
        
        except Exception as e:
            # Log unexpected errors with stack trace
            stack_trace = traceback.format_exc()
            
            try:
                audit_logger.log_event(
                    event_type='system_error',
                    user_id=getattr(kwargs.get('request'), 'user_id', None),
                    action=f.__name__,
                    resource=f.__module__,
                    result='failure',
                    details={
                        'error_message': str(e),
                        'stack_trace': stack_trace
                    },
                    severity='critical'
                )
            except Exception as log_error:
                print(f"Failed to log error: {log_error}", file=sys.stderr)
            
            # Print to stderr for debugging
            print(f"Unexpected error in {f.__name__}: {e}", file=sys.stderr)
            print(stack_trace, file=sys.stderr)
            
            response, status_code = create_error_response(e, include_details=False)
            return jsonify(response), status_code
    
    return decorated_function


def validate_required_fields(data, required_fields):
    """
    Validate that all required fields are present in request data
    
    Args:
        data: Request data dictionary
        required_fields: List of required field names
    
    Raises:
        ValidationError: If any required field is missing
    """
    missing_fields = []
    
    for field in required_fields:
        if field not in data or data[field] is None or data[field] == '':
            missing_fields.append(field)
    
    if missing_fields:
        raise ValidationError(
            message=f"Missing required fields: {', '.join(missing_fields)}",
            details={'missingFields': missing_fields}
        )


def validate_field_length(value, field_name, min_length=None, max_length=None):
    """
    Validate field length
    
    Args:
        value: Field value
        field_name: Name of the field
        min_length: Minimum length (optional)
        max_length: Maximum length (optional)
    
    Raises:
        ValidationError: If length validation fails
    """
    if value is None:
        return
    
    length = len(str(value))
    
    if min_length and length < min_length:
        raise ValidationError(
            message=f"{field_name} must be at least {min_length} characters",
            field=field_name
        )
    
    if max_length and length > max_length:
        raise ValidationError(
            message=f"{field_name} must not exceed {max_length} characters",
            field=field_name
        )


def validate_enum(value, field_name, allowed_values):
    """
    Validate that value is in allowed set
    
    Args:
        value: Field value
        field_name: Name of the field
        allowed_values: List of allowed values
    
    Raises:
        ValidationError: If value is not in allowed set
    """
    if value not in allowed_values:
        raise ValidationError(
            message=f"{field_name} must be one of: {', '.join(allowed_values)}",
            field=field_name,
            details={'allowedValues': allowed_values}
        )


def validate_email(email):
    """
    Validate email format
    
    Args:
        email: Email address
    
    Raises:
        ValidationError: If email format is invalid
    """
    import re
    
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if not re.match(email_pattern, email):
        raise ValidationError(
            message='Invalid email format',
            field='email'
        )


def validate_word_count(text, field_name, min_words=None):
    """
    Validate minimum word count in text
    
    Args:
        text: Text to validate
        field_name: Name of the field
        min_words: Minimum number of words
    
    Raises:
        ValidationError: If word count is below minimum
    """
    if not text:
        return
    
    words = text.split()
    word_count = len(words)
    
    if min_words and word_count < min_words:
        raise ValidationError(
            message=f"{field_name} must contain at least {min_words} words",
            field=field_name,
            details={'wordCount': word_count, 'minWords': min_words}
        )


def handle_service_error(f):
    """
    Decorator for handling errors in service methods
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            print(f"Service error in {f.__name__}: {str(e)}")
            raise
    return decorated_function


def handle_api_error(f):
    """
    Decorator for handling errors in API routes
    """
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        try:
            if inspect.iscoroutinefunction(f):
                return await f(*args, **kwargs)
            result = f(*args, **kwargs)
            if inspect.isawaitable(result):
                return await result
            return result
        except Exception as e:
            print(f"API error in {f.__name__}: {str(e)}")
            return jsonify({
                "success": False,
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": str(e)
                }
            }), 500
    return decorated_function