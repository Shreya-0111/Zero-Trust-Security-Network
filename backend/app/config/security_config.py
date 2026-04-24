"""
Security Configuration for Zero Trust Framework
Centralized security settings and policies
"""

import os
from typing import Dict, List, Any
from datetime import timedelta

class SecurityConfig:
    """Centralized security configuration"""
    
    # CSRF Protection
    CSRF_TOKEN_LIFETIME = 3600  # 1 hour
    CSRF_COOKIE_SECURE = True
    CSRF_COOKIE_HTTPONLY = True
    CSRF_COOKIE_SAMESITE = 'Strict'
    
    # Session Security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    SESSION_LIFETIME = timedelta(hours=8)
    
    # Request Size Limits (in bytes)
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024  # 1 MB
    MAX_JSON_PAYLOAD = 512 * 1024  # 512 KB
    MAX_FORM_PAYLOAD = 1 * 1024 * 1024  # 1 MB
    MAX_FILE_UPLOAD = 5 * 1024 * 1024  # 5 MB
    
    # Rate Limiting Configuration
    RATE_LIMITS = {
        'auth': {'requests': 10, 'window': 60},  # 10 requests per minute
        'access_request': {'requests': 100, 'window': 3600},  # 100 requests per hour
        'admin': {'requests': 500, 'window': 3600},  # 500 requests per hour
        'api': {'requests': 1000, 'window': 3600},  # 1000 requests per hour
        'emergency': {'requests': 5, 'window': 3600},  # 5 emergency requests per hour
        'default': {'requests': 200, 'window': 3600}  # 200 requests per hour
    }
    
    # Content Security Policy
    CSP_POLICY = {
        'default-src': ["'self'"],
        'script-src': [
            "'self'",
            "'unsafe-inline'",  # Required for some React functionality
            "'unsafe-eval'",    # Required for some development tools
            "https://apis.google.com",
            "https://www.gstatic.com"
        ],
        'style-src': [
            "'self'",
            "'unsafe-inline'",  # Required for dynamic styles
            "https://fonts.googleapis.com"
        ],
        'img-src': [
            "'self'",
            "data:",
            "https:",
            "blob:"
        ],
        'font-src': [
            "'self'",
            "data:",
            "https://fonts.gstatic.com"
        ],
        'connect-src': [
            "'self'",
            "https://api.github.com",
            "https://identitytoolkit.googleapis.com",
            "wss:",
            "ws:"
        ],
        'media-src': ["'self'"],
        'object-src': ["'none'"],
        'base-uri': ["'self'"],
        'form-action': ["'self'"],
        'frame-ancestors': ["'none'"],
        'upgrade-insecure-requests': True,
        'block-all-mixed-content': True
    }
    
    # Security Headers
    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Cross-Origin-Embedder-Policy': 'require-corp',
        'Cross-Origin-Opener-Policy': 'same-origin',
        'Cross-Origin-Resource-Policy': 'same-origin'
    }
    
    # Permissions Policy (Feature Policy)
    PERMISSIONS_POLICY = {
        'geolocation': [],
        'microphone': [],
        'camera': [],
        'payment': [],
        'usb': [],
        'magnetometer': [],
        'gyroscope': [],
        'accelerometer': [],
        'ambient-light-sensor': [],
        'autoplay': [],
        'battery': [],
        'display-capture': [],
        'document-domain': [],
        'encrypted-media': [],
        'fullscreen': [],
        'gamepad': [],
        'midi': [],
        'picture-in-picture': [],
        'publickey-credentials-get': [],
        'screen-wake-lock': [],
        'sync-xhr': [],
        'web-share': []
    }
    
    # Input Sanitization
    ALLOWED_HTML_TAGS = ['p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li', 'a']
    ALLOWED_HTML_ATTRIBUTES = {
        'a': ['href', 'title'],
        '*': ['class']
    }
    
    # Dangerous Patterns for Detection
    DANGEROUS_PATTERNS = [
        r'<script[^>]*>.*?</script>',  # Script tags
        r'javascript:',  # JavaScript protocol
        r'vbscript:',  # VBScript protocol
        r'data:text/html',  # Data URLs with HTML
        r'on\w+\s*=',  # Event handlers
        r'expression\s*\(',  # CSS expressions
        r'@import',  # CSS imports
        r'<iframe[^>]*>',  # Iframes
        r'<object[^>]*>',  # Objects
        r'<embed[^>]*>',  # Embeds
        r'<form[^>]*>',  # Forms
        r'<input[^>]*>',  # Inputs
        r'[\'"];?\s*alert\s*\(',  # Alert function calls
        r'[\'"];?\s*eval\s*\(',  # Eval function calls
    ]
    
    # SQL Injection Patterns
    SQL_INJECTION_PATTERNS = [
        r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)',
        r'(\b(OR|AND)\s+\d+\s*=\s*\d+)',
        r'(\b(OR|AND)\s+[\'"][^\'"]*[\'"])',
        r'(--|#|/\*|\*/)',
        r'(\bxp_cmdshell\b)',
        r'(\bsp_executesql\b)',
    ]
    
    # Suspicious User Agent Patterns
    SUSPICIOUS_USER_AGENTS = [
        r'sqlmap',
        r'nikto',
        r'nmap',
        r'masscan',
        r'burp',
        r'owasp',
        r'<script',
        r'python-requests/\d+\.\d+\.\d+$',  # Basic python requests
        r'^$'  # Empty user agent
    ]
    
    # Allowed Content Types
    ALLOWED_CONTENT_TYPES = {
        'json': ['application/json'],
        'form': ['application/x-www-form-urlencoded', 'multipart/form-data'],
        'text': ['text/plain'],
        'all': ['application/json', 'application/x-www-form-urlencoded', 'multipart/form-data']
    }
    
    # IP Whitelist for Admin Operations (empty means no restriction)
    ADMIN_IP_WHITELIST = []
    
    # Trusted Proxy IPs (for rate limiting and logging)
    TRUSTED_PROXIES = []
    
    # Security Audit Settings
    AUDIT_SECURITY_EVENTS = True
    AUDIT_FAILED_LOGINS = True
    AUDIT_RATE_LIMIT_VIOLATIONS = True
    AUDIT_CSRF_VIOLATIONS = True
    AUDIT_INPUT_SANITIZATION = True
    
    # Emergency Mode Settings
    EMERGENCY_MODE_ENABLED = False
    EMERGENCY_RATE_LIMIT_MULTIPLIER = 5  # Increase rate limits by 5x in emergency
    
    @classmethod
    def get_csp_header_value(cls) -> str:
        """Generate CSP header value from policy configuration"""
        csp_parts = []
        
        for directive, values in cls.CSP_POLICY.items():
            if directive in ['upgrade-insecure-requests', 'block-all-mixed-content']:
                if values:
                    csp_parts.append(directive.replace('_', '-'))
            else:
                if values:
                    value_str = ' '.join(values)
                    csp_parts.append(f"{directive.replace('_', '-')} {value_str}")
        
        return '; '.join(csp_parts)
    
    @classmethod
    def get_permissions_policy_header_value(cls) -> str:
        """Generate Permissions Policy header value"""
        policy_parts = []
        
        for feature, allowed_origins in cls.PERMISSIONS_POLICY.items():
            if allowed_origins:
                origins_str = ' '.join(f'"{origin}"' for origin in allowed_origins)
                policy_parts.append(f"{feature.replace('_', '-')}=({origins_str})")
            else:
                policy_parts.append(f"{feature.replace('_', '-')}=()")
        
        return ', '.join(policy_parts)
    
    @classmethod
    def is_emergency_mode(cls) -> bool:
        """Check if emergency mode is enabled"""
        return cls.EMERGENCY_MODE_ENABLED or os.getenv('EMERGENCY_MODE', '').lower() == 'true'
    
    @classmethod
    def get_rate_limit_config(cls, limit_type: str) -> Dict[str, int]:
        """Get rate limit configuration with emergency mode adjustment"""
        config = cls.RATE_LIMITS.get(limit_type, cls.RATE_LIMITS['default']).copy()
        
        if cls.is_emergency_mode():
            config['requests'] *= cls.EMERGENCY_RATE_LIMIT_MULTIPLIER
        
        return config
    
    @classmethod
    def validate_config(cls) -> List[str]:
        """Validate security configuration and return any issues"""
        issues = []
        
        # Check required environment variables
        required_env_vars = ['SECRET_KEY', 'JWT_SECRET_KEY']
        for var in required_env_vars:
            if not os.getenv(var):
                issues.append(f"Missing required environment variable: {var}")
        
        # Check secret key strength
        secret_key = os.getenv('SECRET_KEY', '')
        if len(secret_key) < 32:
            issues.append("SECRET_KEY should be at least 32 characters long")
        
        # Check HTTPS in production
        if os.getenv('FLASK_ENV') == 'production' and not os.getenv('FORCE_HTTPS'):
            issues.append("HTTPS should be enforced in production")
        
        return issues


# Environment-specific configurations
class DevelopmentSecurityConfig(SecurityConfig):
    """Development environment security configuration"""
    
    # Relaxed settings for development
    CSRF_COOKIE_SECURE = False
    SESSION_COOKIE_SECURE = False
    
    # Allow unsafe-eval and unsafe-inline for development tools
    CSP_POLICY = SecurityConfig.CSP_POLICY.copy()
    CSP_POLICY['script-src'].extend(["'unsafe-eval'", "'unsafe-inline'"])


class ProductionSecurityConfig(SecurityConfig):
    """Production environment security configuration"""
    
    # Strict settings for production
    CSRF_COOKIE_SECURE = True
    SESSION_COOKIE_SECURE = True
    
    # Stricter CSP for production
    CSP_POLICY = SecurityConfig.CSP_POLICY.copy()
    # Remove unsafe-eval and unsafe-inline in production if possible
    
    # Lower rate limits for production
    RATE_LIMITS = {
        'auth': {'requests': 5, 'window': 60},  # Stricter auth limits
        'access_request': {'requests': 50, 'window': 3600},
        'admin': {'requests': 200, 'window': 3600},
        'api': {'requests': 500, 'window': 3600},
        'emergency': {'requests': 3, 'window': 3600},
        'default': {'requests': 100, 'window': 3600}
    }


def get_security_config():
    """Get appropriate security configuration based on environment"""
    env = os.getenv('FLASK_ENV', 'development')
    
    if env == 'production':
        return ProductionSecurityConfig
    else:
        return DevelopmentSecurityConfig