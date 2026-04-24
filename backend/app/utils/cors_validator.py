"""
CORS Configuration Validator
Validates CORS origins and provides security recommendations
"""

import os
import re
from urllib.parse import urlparse
from typing import List, Dict, Tuple, Optional


class CORSValidator:
    """Validates CORS configuration for security compliance"""
    
    def __init__(self):
        self.valid_schemes = ['http', 'https']
        self.development_patterns = [
            r'^http://localhost:\d+$',
            r'^http://127\.0\.0\.1:\d+$',
            r'^http://\[::1\]:\d+$'
        ]
        self.production_requirements = {
            'https_only': True,
            'no_wildcards': True,
            'no_ip_addresses': True,
            'valid_domains': True
        }
    
    def validate_cors_origins(self, origins_string: str, environment: str = 'development') -> Dict:
        """
        Validate CORS origins configuration
        
        Args:
            origins_string: Comma-separated CORS origins
            environment: 'development' or 'production'
            
        Returns:
            Dict with validation results
        """
        if not origins_string:
            return {
                'valid': False,
                'errors': ['CORS_ORIGINS environment variable is empty'],
                'warnings': [],
                'origins': [],
                'recommendations': ['Set CORS_ORIGINS to specific allowed domains']
            }
        
        # Parse origins
        origins = [origin.strip() for origin in origins_string.split(',') if origin.strip()]
        
        if not origins:
            return {
                'valid': False,
                'errors': ['No valid origins found in CORS_ORIGINS'],
                'warnings': [],
                'origins': [],
                'recommendations': ['Add at least one valid origin to CORS_ORIGINS']
            }
        
        errors = []
        warnings = []
        recommendations = []
        valid_origins = []
        
        for origin in origins:
            result = self._validate_single_origin(origin, environment)
            
            if result['valid']:
                valid_origins.append(origin)
            else:
                errors.extend(result['errors'])
            
            warnings.extend(result['warnings'])
            recommendations.extend(result['recommendations'])
        
        # Remove duplicate recommendations
        recommendations = list(set(recommendations))
        
        # Additional validation for production
        if environment == 'production':
            prod_result = self._validate_production_requirements(valid_origins)
            errors.extend(prod_result['errors'])
            warnings.extend(prod_result['warnings'])
            recommendations.extend(prod_result['recommendations'])
        
        return {
            'valid': len(errors) == 0 and len(valid_origins) > 0,
            'errors': errors,
            'warnings': warnings,
            'origins': valid_origins,
            'recommendations': list(set(recommendations))
        }
    
    def _validate_single_origin(self, origin: str, environment: str) -> Dict:
        """Validate a single CORS origin"""
        errors = []
        warnings = []
        recommendations = []
        
        # Check for wildcards
        if '*' in origin:
            errors.append(f"Wildcard not allowed in origin: {origin}")
            recommendations.append("Use specific domains instead of wildcards")
            return {'valid': False, 'errors': errors, 'warnings': warnings, 'recommendations': recommendations}
        
        # Check for null origin
        if origin.lower() == 'null':
            errors.append("'null' origin is not secure")
            recommendations.append("Remove 'null' from CORS origins")
            return {'valid': False, 'errors': errors, 'warnings': warnings, 'recommendations': recommendations}
        
        # Parse URL
        try:
            parsed = urlparse(origin)
        except Exception as e:
            errors.append(f"Invalid URL format: {origin} - {str(e)}")
            return {'valid': False, 'errors': errors, 'warnings': warnings, 'recommendations': recommendations}
        
        # Validate scheme
        if parsed.scheme not in self.valid_schemes:
            errors.append(f"Invalid scheme '{parsed.scheme}' in origin: {origin}")
            recommendations.append("Use http:// or https:// schemes only")
            return {'valid': False, 'errors': errors, 'warnings': warnings, 'recommendations': recommendations}
        
        # Validate hostname
        if not parsed.hostname:
            errors.append(f"Missing hostname in origin: {origin}")
            return {'valid': False, 'errors': errors, 'warnings': warnings, 'recommendations': recommendations}
        
        # Check for development patterns
        is_development_origin = any(re.match(pattern, origin) for pattern in self.development_patterns)
        
        if environment == 'production' and is_development_origin:
            errors.append(f"Development origin not allowed in production: {origin}")
            recommendations.append("Remove localhost/127.0.0.1 origins from production")
            return {'valid': False, 'errors': errors, 'warnings': warnings, 'recommendations': recommendations}
        
        # Production-specific validations
        if environment == 'production':
            if parsed.scheme != 'https':
                errors.append(f"HTTPS required in production: {origin}")
                recommendations.append("Use HTTPS for all production origins")
            
            # Check for IP addresses (not recommended in production)
            if self._is_ip_address(parsed.hostname):
                warnings.append(f"IP address used instead of domain: {origin}")
                recommendations.append("Use domain names instead of IP addresses")
            
            # Check for non-standard ports
            if parsed.port and parsed.port not in [80, 443]:
                warnings.append(f"Non-standard port used: {origin}")
                recommendations.append("Use standard ports (80/443) when possible")
        
        # Development-specific warnings
        if environment == 'development':
            if parsed.scheme == 'http' and not is_development_origin:
                warnings.append(f"HTTP used for non-localhost origin: {origin}")
                recommendations.append("Use HTTPS for non-localhost origins")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings,
            'recommendations': recommendations
        }
    
    def _validate_production_requirements(self, origins: List[str]) -> Dict:
        """Validate production-specific requirements"""
        errors = []
        warnings = []
        recommendations = []
        
        if not origins:
            errors.append("No valid origins for production environment")
            return {'errors': errors, 'warnings': warnings, 'recommendations': recommendations}
        
        https_count = sum(1 for origin in origins if origin.startswith('https://'))
        
        if https_count == 0:
            errors.append("At least one HTTPS origin required in production")
            recommendations.append("Add HTTPS origins for production deployment")
        
        if len(origins) > 10:
            warnings.append(f"Large number of CORS origins ({len(origins)}) may impact performance")
            recommendations.append("Consider reducing the number of CORS origins")
        
        return {'errors': errors, 'warnings': warnings, 'recommendations': recommendations}
    
    def _is_ip_address(self, hostname: str) -> bool:
        """Check if hostname is an IP address"""
        import ipaddress
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False
    
    def get_websocket_cors_validation(self, websocket_origins: str, http_origins: str) -> Dict:
        """Validate WebSocket CORS consistency with HTTP CORS"""
        errors = []
        warnings = []
        recommendations = []
        
        if not websocket_origins:
            errors.append("WebSocket CORS origins not configured")
            recommendations.append("Set WEBSOCKET_CORS_ALLOWED_ORIGINS")
            return {'valid': False, 'errors': errors, 'warnings': warnings, 'recommendations': recommendations}
        
        # Parse both configurations
        ws_origins = set(origin.strip() for origin in websocket_origins.split(',') if origin.strip())
        http_origins_set = set(origin.strip() for origin in http_origins.split(',') if origin.strip())
        
        # Check for consistency
        if ws_origins != http_origins_set:
            warnings.append("WebSocket CORS origins differ from HTTP CORS origins")
            recommendations.append("Keep WebSocket and HTTP CORS origins synchronized")
            
            # Show differences
            only_in_ws = ws_origins - http_origins_set
            only_in_http = http_origins_set - ws_origins
            
            if only_in_ws:
                warnings.append(f"Origins only in WebSocket CORS: {', '.join(only_in_ws)}")
            
            if only_in_http:
                warnings.append(f"Origins only in HTTP CORS: {', '.join(only_in_http)}")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings,
            'recommendations': recommendations,
            'websocket_origins': list(ws_origins),
            'http_origins': list(http_origins_set)
        }
    
    def generate_secure_cors_config(self, domains: List[str], environment: str = 'production') -> Dict:
        """Generate secure CORS configuration"""
        if environment == 'production':
            origins = [f"https://{domain}" for domain in domains]
            # Add www variants
            www_origins = [f"https://www.{domain}" for domain in domains if not domain.startswith('www.')]
            origins.extend(www_origins)
        else:
            origins = [f"http://localhost:3000"]  # Default development origin
            origins.extend([f"https://{domain}" for domain in domains])
        
        return {
            'CORS_ORIGINS': ','.join(origins),
            'WEBSOCKET_CORS_ALLOWED_ORIGINS': ','.join(origins),
            'recommendations': [
                'Use HTTPS in production',
                'Keep WebSocket and HTTP CORS synchronized',
                'Regularly audit CORS origins',
                'Remove unused origins'
            ]
        }


def validate_cors_on_startup():
    """Validate CORS configuration on application startup"""
    validator = CORSValidator()
    
    # Get environment
    environment = os.getenv('FLASK_ENV', 'development')
    if environment not in ['development', 'production']:
        environment = 'production'  # Default to production for security
    
    # Validate HTTP CORS
    cors_origins = os.getenv('CORS_ORIGINS', '')
    http_result = validator.validate_cors_origins(cors_origins, environment)
    
    # Validate WebSocket CORS
    websocket_origins = os.getenv('WEBSOCKET_CORS_ALLOWED_ORIGINS', '')
    ws_result = validator.get_websocket_cors_validation(websocket_origins, cors_origins)
    
    # Print results
    print(f"\n=== CORS Configuration Validation ({environment}) ===")
    
    if http_result['valid']:
        print("✅ HTTP CORS configuration is valid")
        print(f"   Allowed origins: {', '.join(http_result['origins'])}")
    else:
        print("❌ HTTP CORS configuration has errors:")
        for error in http_result['errors']:
            print(f"   - {error}")
    
    if http_result['warnings']:
        print("⚠️  HTTP CORS warnings:")
        for warning in http_result['warnings']:
            print(f"   - {warning}")
    
    if ws_result['valid']:
        print("✅ WebSocket CORS configuration is valid")
    else:
        print("❌ WebSocket CORS configuration has errors:")
        for error in ws_result['errors']:
            print(f"   - {error}")
    
    if ws_result['warnings']:
        print("⚠️  WebSocket CORS warnings:")
        for warning in ws_result['warnings']:
            print(f"   - {warning}")
    
    # Show recommendations
    all_recommendations = set(http_result['recommendations'] + ws_result['recommendations'])
    if all_recommendations:
        print("💡 Recommendations:")
        for rec in all_recommendations:
            print(f"   - {rec}")
    
    print("=" * 50)
    
    return {
        'http_cors': http_result,
        'websocket_cors': ws_result,
        'overall_valid': http_result['valid'] and ws_result['valid']
    }


# Export validator instance
cors_validator = CORSValidator()