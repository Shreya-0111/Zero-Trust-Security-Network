"""
Comprehensive Input Validation Service
Provides advanced validation, sanitization, and security checks for all user inputs
"""

import re
import html
import json
import urllib.parse
from typing import Any, Dict, List, Optional, Union, Tuple
from datetime import datetime
import validators
import bleach
from app.config.security_config import get_security_config
from app.services.audit_logger import audit_logger
from flask import request, g
import sys


class InputValidator:
    """Comprehensive input validation and sanitization service"""
    
    def __init__(self):
        self.security_config = get_security_config()
        self.dangerous_patterns = self.security_config.DANGEROUS_PATTERNS
        self.sql_patterns = self.security_config.SQL_INJECTION_PATTERNS
        self.allowed_tags = self.security_config.ALLOWED_HTML_TAGS
        self.allowed_attributes = self.security_config.ALLOWED_HTML_ATTRIBUTES
    
    def detect_sql_injection(self, value: str) -> Tuple[bool, List[str]]:
        """
        Detect potential SQL injection attempts
        
        Args:
            value: String to check
            
        Returns:
            Tuple of (is_suspicious, matched_patterns)
        """
        if not isinstance(value, str):
            return False, []
        
        matched_patterns = []
        value_lower = value.lower()
        
        for pattern in self.sql_patterns:
            if re.search(pattern, value_lower, re.IGNORECASE):
                matched_patterns.append(pattern)
        
        return len(matched_patterns) > 0, matched_patterns
    
    def detect_xss_attempt(self, value: str) -> Tuple[bool, List[str]]:
        """
        Detect potential XSS attempts
        
        Args:
            value: String to check
            
        Returns:
            Tuple of (is_suspicious, matched_patterns)
        """
        if not isinstance(value, str):
            return False, []
        
        matched_patterns = []
        
        for pattern in self.dangerous_patterns:
            if re.search(pattern, value, re.IGNORECASE | re.DOTALL):
                matched_patterns.append(pattern)
        
        return len(matched_patterns) > 0, matched_patterns
    
    def detect_path_traversal(self, value: str) -> bool:
        """
        Detect path traversal attempts
        
        Args:
            value: String to check
            
        Returns:
            True if path traversal detected
        """
        if not isinstance(value, str):
            return False
        
        # Common path traversal patterns
        traversal_patterns = [
            r'\.\./+',  # ../
            r'\.\.\\+',  # ..\
            r'%2e%2e%2f',  # URL encoded ../
            r'%2e%2e%5c',  # URL encoded ..\
            r'\.\.%2f',  # Mixed encoding
            r'\.\.%5c',  # Mixed encoding
        ]
        
        for pattern in traversal_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        
        return False
    
    def sanitize_string(self, value: str, allow_html: bool = False, max_length: int = 10000) -> str:
        """
        Comprehensive string sanitization
        
        Args:
            value: String to sanitize
            allow_html: Whether to allow safe HTML tags
            max_length: Maximum allowed length
            
        Returns:
            Sanitized string
        """
        if not isinstance(value, str):
            return str(value) if value is not None else ""
        
        # Check length
        if len(value) > max_length:
            value = value[:max_length]
        
        # Log security violations
        sql_detected, sql_patterns = self.detect_sql_injection(value)
        xss_detected, xss_patterns = self.detect_xss_attempt(value)
        path_traversal_detected = self.detect_path_traversal(value)
        
        if sql_detected or xss_detected or path_traversal_detected:
            try:
                audit_logger.log_event(
                    event_type='security_violation',
                    user_id=getattr(g, 'user_id', None),
                    action='malicious_input_detected',
                    resource=request.path if request else 'unknown',
                    result='sanitized',
                    details={
                        'sql_injection': sql_detected,
                        'sql_patterns': sql_patterns,
                        'xss_attempt': xss_detected,
                        'xss_patterns': xss_patterns,
                        'path_traversal': path_traversal_detected,
                        'input_sample': value[:200],  # First 200 chars
                        'client_ip': request.remote_addr if request else 'unknown'
                    },
                    severity='high'
                )
            except Exception as e:
                print(f"Failed to log security violation: {e}", file=sys.stderr)
        
        # For XSS, only return empty if it's purely malicious content
        if xss_detected and not allow_html:
            # Check if the content has any legitimate parts
            # Remove the malicious parts and keep safe content
            for pattern in xss_patterns:
                value = re.sub(pattern, '', value, flags=re.IGNORECASE | re.DOTALL)
        
        # Return empty string for SQL injection attempts
        if sql_detected:
            return ""
        
        # Sanitize based on HTML allowance
        if allow_html:
            # Use bleach for safe HTML sanitization
            sanitized = bleach.clean(
                value,
                tags=self.allowed_tags,
                attributes=self.allowed_attributes,
                strip=True
            )
        else:
            # HTML escape to prevent XSS
            sanitized = html.escape(value)
        
        # URL decode to prevent double encoding attacks
        try:
            sanitized = urllib.parse.unquote(sanitized)
        except Exception:
            pass  # Keep original if URL decoding fails
        
        # Remove null bytes and control characters
        sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', sanitized)
        
        # Normalize whitespace
        sanitized = re.sub(r'\s+', ' ', sanitized).strip()
        
        return sanitized
    
    def validate_email(self, email: str) -> Tuple[bool, str]:
        """
        Validate email address
        
        Args:
            email: Email to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not email:
            return False, "Email is required"
        
        # Sanitize first
        email = self.sanitize_string(email, allow_html=False, max_length=254)
        
        # Use validators library
        if not validators.email(email):
            return False, "Invalid email format"
        
        # Additional checks
        if len(email) > 254:  # RFC 5321 limit
            return False, "Email address too long"
        
        local_part, domain = email.rsplit('@', 1)
        if len(local_part) > 64:  # RFC 5321 limit
            return False, "Email local part too long"
        
        return True, ""
    
    def validate_url(self, url: str, allowed_schemes: List[str] = None) -> Tuple[bool, str]:
        """
        Validate URL
        
        Args:
            url: URL to validate
            allowed_schemes: List of allowed URL schemes
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not url:
            return False, "URL is required"
        
        if allowed_schemes is None:
            allowed_schemes = ['http', 'https']
        
        # Sanitize first
        url = self.sanitize_string(url, allow_html=False, max_length=2048)
        
        # Use validators library
        if not validators.url(url):
            return False, "Invalid URL format"
        
        # Check scheme
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme.lower() not in allowed_schemes:
                return False, f"URL scheme must be one of: {', '.join(allowed_schemes)}"
        except Exception:
            return False, "Invalid URL format"
        
        return True, ""
    
    def validate_phone(self, phone: str) -> Tuple[bool, str]:
        """
        Validate phone number
        
        Args:
            phone: Phone number to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not phone:
            return False, "Phone number is required"
        
        # Sanitize first
        phone = self.sanitize_string(phone, allow_html=False, max_length=20)
        
        # Remove common formatting characters
        cleaned_phone = re.sub(r'[^\d+]', '', phone)
        
        # Basic validation
        if len(cleaned_phone) < 10:
            return False, "Phone number too short"
        
        if len(cleaned_phone) > 15:  # E.164 standard
            return False, "Phone number too long"
        
        # Must start with + or digit
        if not re.match(r'^[\+\d]', cleaned_phone):
            return False, "Invalid phone number format"
        
        return True, ""
    
    def validate_password(self, password: str, min_length: int = 8) -> Tuple[bool, List[str]]:
        """
        Validate password strength
        
        Args:
            password: Password to validate
            min_length: Minimum password length
            
        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        if not password:
            return False, ["Password is required"]
        
        issues = []
        
        # Length check
        if len(password) < min_length:
            issues.append(f"Password must be at least {min_length} characters long")
        
        if len(password) > 128:  # Reasonable maximum
            issues.append("Password is too long (max 128 characters)")
        
        # Complexity checks
        if not re.search(r'[a-z]', password):
            issues.append("Password must contain at least one lowercase letter")
        
        if not re.search(r'[A-Z]', password):
            issues.append("Password must contain at least one uppercase letter")
        
        if not re.search(r'\d', password):
            issues.append("Password must contain at least one digit")
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            issues.append("Password must contain at least one special character")
        
        # Common password checks
        common_passwords = [
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey'
        ]
        
        if password.lower() in common_passwords:
            issues.append("Password is too common")
        
        return len(issues) == 0, issues
    
    def validate_json_structure(self, data: Any, required_fields: List[str] = None, 
                              optional_fields: List[str] = None) -> Tuple[bool, List[str]]:
        """
        Validate JSON structure
        
        Args:
            data: JSON data to validate
            required_fields: List of required field names
            optional_fields: List of optional field names
            
        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        if not isinstance(data, dict):
            return False, ["Data must be a JSON object"]
        
        issues = []
        required_fields = required_fields or []
        optional_fields = optional_fields or []
        allowed_fields = set(required_fields + optional_fields)
        
        # Check required fields
        for field in required_fields:
            if field not in data:
                issues.append(f"Required field '{field}' is missing")
            elif data[field] is None:
                issues.append(f"Required field '{field}' cannot be null")
            elif isinstance(data[field], str) and not data[field].strip():
                issues.append(f"Required field '{field}' cannot be empty")
        
        # Check for unexpected fields
        unexpected_fields = set(data.keys()) - allowed_fields
        if unexpected_fields:
            issues.append(f"Unexpected fields: {', '.join(unexpected_fields)}")
        
        return len(issues) == 0, issues
    
    def sanitize_dict(self, data: Any, allow_html: bool = False) -> Any:
        """
        Recursively sanitize dictionary values
        
        Args:
            data: Data structure to sanitize
            allow_html: Whether to allow safe HTML tags
            
        Returns:
            Sanitized data structure
        """
        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                # Sanitize keys as well
                clean_key = self.sanitize_string(str(key), allow_html=False, max_length=100)
                sanitized[clean_key] = self.sanitize_dict(value, allow_html)
            return sanitized
        elif isinstance(data, list):
            return [self.sanitize_dict(item, allow_html) for item in data]
        elif isinstance(data, str):
            return self.sanitize_string(data, allow_html)
        elif isinstance(data, (int, float, bool)) or data is None:
            return data
        else:
            # Convert unknown types to string and sanitize
            return self.sanitize_string(str(data), allow_html=False)
    
    def validate_file_upload(self, file_data: bytes, filename: str, 
                           allowed_extensions: List[str] = None,
                           max_size: int = None) -> Tuple[bool, List[str]]:
        """
        Validate file upload
        
        Args:
            file_data: File content as bytes
            filename: Original filename
            allowed_extensions: List of allowed file extensions
            max_size: Maximum file size in bytes
            
        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []
        
        if not file_data:
            return False, ["File data is required"]
        
        if not filename:
            return False, ["Filename is required"]
        
        # Sanitize filename
        filename = self.sanitize_string(filename, allow_html=False, max_length=255)
        
        # Check file size
        if max_size and len(file_data) > max_size:
            issues.append(f"File size exceeds maximum allowed size of {max_size} bytes")
        
        # Check file extension
        if allowed_extensions:
            file_ext = filename.lower().split('.')[-1] if '.' in filename else ''
            if file_ext not in [ext.lower() for ext in allowed_extensions]:
                issues.append(f"File extension '{file_ext}' not allowed. Allowed: {', '.join(allowed_extensions)}")
        
        # Check for dangerous filenames
        dangerous_names = ['..', '.htaccess', 'web.config', 'index.php', 'index.html']
        if filename.lower() in dangerous_names:
            issues.append("Filename not allowed for security reasons")
        
        # Check for null bytes in filename
        if '\x00' in filename:
            issues.append("Filename contains null bytes")
        
        return len(issues) == 0, issues
    
    def validate_ip_address(self, ip: str) -> Tuple[bool, str]:
        """
        Validate IP address
        
        Args:
            ip: IP address to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not ip:
            return False, "IP address is required"
        
        # Sanitize first
        ip = self.sanitize_string(ip, allow_html=False, max_length=45)
        
        # Use validators library
        if validators.ipv4(ip) or validators.ipv6(ip):
            return True, ""
        
        return False, "Invalid IP address format"
    
    def validate_uuid(self, uuid_str: str) -> Tuple[bool, str]:
        """
        Validate UUID format
        
        Args:
            uuid_str: UUID string to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not uuid_str:
            return False, "UUID is required"
        
        # Sanitize first
        uuid_str = self.sanitize_string(uuid_str, allow_html=False, max_length=36)
        
        # UUID pattern
        uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        
        if re.match(uuid_pattern, uuid_str, re.IGNORECASE):
            return True, ""
        
        return False, "Invalid UUID format"


# Global validator instance
input_validator = InputValidator()


def validate_and_sanitize_input(data: Any, validation_rules: Dict[str, Any] = None) -> Tuple[Any, List[str]]:
    """
    Validate and sanitize input data according to rules
    
    Args:
        data: Input data to validate and sanitize
        validation_rules: Dictionary of validation rules
        
    Returns:
        Tuple of (sanitized_data, list_of_errors)
    """
    if validation_rules is None:
        validation_rules = {}
    
    errors = []
    sanitized_data = input_validator.sanitize_dict(data)
    
    # Apply validation rules
    for field, rules in validation_rules.items():
        if field not in sanitized_data:
            if rules.get('required', False):
                errors.append(f"Field '{field}' is required")
            continue
        
        value = sanitized_data[field]
        field_type = rules.get('type')
        
        # Type validation
        if field_type == 'email':
            is_valid, error = input_validator.validate_email(value)
            if not is_valid:
                errors.append(f"Field '{field}': {error}")
        
        elif field_type == 'url':
            allowed_schemes = rules.get('allowed_schemes', ['http', 'https'])
            is_valid, error = input_validator.validate_url(value, allowed_schemes)
            if not is_valid:
                errors.append(f"Field '{field}': {error}")
        
        elif field_type == 'phone':
            is_valid, error = input_validator.validate_phone(value)
            if not is_valid:
                errors.append(f"Field '{field}': {error}")
        
        elif field_type == 'password':
            min_length = rules.get('min_length', 8)
            is_valid, issues = input_validator.validate_password(value, min_length)
            if not is_valid:
                errors.extend([f"Field '{field}': {issue}" for issue in issues])
        
        elif field_type == 'uuid':
            is_valid, error = input_validator.validate_uuid(value)
            if not is_valid:
                errors.append(f"Field '{field}': {error}")
        
        # Length validation
        if 'max_length' in rules and isinstance(value, str):
            if len(value) > rules['max_length']:
                errors.append(f"Field '{field}' exceeds maximum length of {rules['max_length']}")
        
        if 'min_length' in rules and isinstance(value, str):
            if len(value) < rules['min_length']:
                errors.append(f"Field '{field}' is below minimum length of {rules['min_length']}")
    
    return sanitized_data, errors