"""
Audit Logger Service
Comprehensive logging of all security-relevant events
"""

import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from app.firebase_config import get_firestore_client
from app.models.audit_log import AuditLog


class AuditLogger:
    """Service for logging system events and sending security alerts"""
    
    def __init__(self):
        self.db = get_firestore_client()
        
        # Email configuration
        self.smtp_host = os.getenv('SMTP_HOST', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', 587))
        self.smtp_user = os.getenv('SMTP_USER')
        self.smtp_password = os.getenv('SMTP_PASSWORD')
        self.alert_email = os.getenv('ALERT_EMAIL', 'admin@example.com')
        self.email_enabled = os.getenv('EMAIL_NOTIFICATIONS_ENABLED', 'false').lower() == 'true'
    
    def log_event(
        self,
        event_type,
        user_id,
        action,
        resource,
        result,
        details=None,
        ip_address=None,
        severity='low'
    ):
        """
        Log a system event to Firestore
        
        Args:
            event_type (str): Type of event
            user_id (str): User ID
            action (str): Action description
            resource (str): Affected resource
            result (str): Result of action
            details (dict, optional): Additional details
            ip_address (str, optional): Client IP address
            severity (str): Severity level
            
        Returns:
            AuditLog: Created audit log object
        """
        try:
            # Create audit log
            audit_log = AuditLog(
                event_type=event_type,
                user_id=user_id,
                action=action,
                resource=resource,
                result=result,
                ip_address=ip_address,
                severity=severity
            )
            
            # Set details if provided
            if details:
                audit_log.set_details(details)
            
            # Validate
            is_valid, error_message = audit_log.validate()
            if not is_valid:
                print(f"Audit log validation failed: {error_message}")
                return None
            
            # Save to Firestore
            log_ref = self.db.collection('auditLogs').document(audit_log.log_id)
            log_ref.set(audit_log.to_dict())
            
            # Send alert for high-severity events
            if severity in ['high', 'critical']:
                self.send_alert(audit_log)
            
            return audit_log
        except Exception as e:
            print(f"Error logging event: {str(e)}")
            return None
    
    def log_access_request(self, request_data, decision, confidence_score, user_id, ip_address=None):
        """
        Log access request evaluation
        
        Args:
            request_data (dict): Access request data
            decision (str): Decision result
            confidence_score (float): Confidence score
            user_id (str): User ID
            ip_address (str, optional): Client IP address
        """
        result = 'success' if decision in ['granted', 'granted_with_mfa'] else 'denied'
        severity = 'low' if decision == 'granted' else 'medium' if decision == 'granted_with_mfa' else 'high'
        
        details = {
            'requestId': request_data.get('requestId'),
            'requestedResource': request_data.get('requestedResource'),
            'decision': decision,
            'confidenceScore': confidence_score,
            'intent': request_data.get('intent', '')[:100],  # Truncate for storage
            'duration': request_data.get('duration'),
            'urgency': request_data.get('urgency')
        }
        
        return self.log_event(
            event_type='access_request',
            user_id=user_id,
            action=f"Access request {decision}",
            resource=request_data.get('requestedResource', 'unknown'),
            result=result,
            details=details,
            ip_address=ip_address,
            severity=severity
        )
    
    def log_authentication(self, user_id, success, ip_address=None, details=None):
        """
        Log authentication attempt
        
        Args:
            user_id (str): User ID
            success (bool): Whether authentication was successful
            ip_address (str, optional): Client IP address
            details (dict, optional): Additional details
        """
        result = 'success' if success else 'failure'
        severity = 'low' if success else 'medium'
        action = 'Login successful' if success else 'Login failed'
        
        log_details = details or {}
        log_details['authMethod'] = log_details.get('authMethod', 'password')
        
        return self.log_event(
            event_type='authentication',
            user_id=user_id,
            action=action,
            resource='authentication_system',
            result=result,
            details=log_details,
            ip_address=ip_address,
            severity=severity
        )
    
    def log_admin_action(self, admin_id, action, target_user_id, details=None, ip_address=None):
        """
        Log administrative action
        
        Args:
            admin_id (str): Administrator user ID
            action (str): Action performed
            target_user_id (str): Target user ID
            details (dict, optional): Additional details
            ip_address (str, optional): Client IP address
        """
        log_details = details or {}
        log_details['targetUserId'] = target_user_id
        
        return self.log_event(
            event_type='admin_action',
            user_id=admin_id,
            action=action,
            resource=f"user:{target_user_id}",
            result='success',
            details=log_details,
            ip_address=ip_address,
            severity='medium'
        )
    
    def log_policy_change(self, admin_id, policy_id, action, changes=None, ip_address=None):
        """
        Log policy configuration change
        
        Args:
            admin_id (str): Administrator user ID
            policy_id (str): Policy ID
            action (str): Action performed (create, update, delete)
            changes (dict, optional): Changes made
            ip_address (str, optional): Client IP address
        """
        log_details = {
            'policyId': policy_id,
            'action': action
        }
        
        if changes:
            log_details['changes'] = changes
        
        return self.log_event(
            event_type='policy_change',
            user_id=admin_id,
            action=f"Policy {action}",
            resource=f"policy:{policy_id}",
            result='success',
            details=log_details,
            ip_address=ip_address,
            severity='high'
        )
    
    def log_mfa_event(self, user_id, action, success, ip_address=None, details=None):
        """
        Log MFA-related event
        
        Args:
            user_id (str): User ID
            action (str): MFA action (setup, verify, disable)
            success (bool): Whether action was successful
            ip_address (str, optional): Client IP address
            details (dict, optional): Additional details
        """
        result = 'success' if success else 'failure'
        severity = 'low' if success else 'high'
        
        log_details = details or {}
        log_details['mfaAction'] = action
        
        return self.log_event(
            event_type='mfa_event',
            user_id=user_id,
            action=f"MFA {action}",
            resource='mfa_system',
            result=result,
            details=log_details,
            ip_address=ip_address,
            severity=severity
        )
    
    def send_alert(self, audit_log):
        """
        Send email alert for high-severity events
        
        Args:
            audit_log (AuditLog): Audit log object
        """
        if not self.email_enabled:
            print(f"Email alerts disabled. Would send alert for: {audit_log.action}")
            return
        
        if not self.smtp_user or not self.smtp_password:
            print("SMTP credentials not configured. Cannot send alert email.")
            return
        
        try:
            # Create email message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[{audit_log.severity.upper()}] Security Alert: {audit_log.action}"
            msg['From'] = self.smtp_user
            msg['To'] = self.alert_email
            
            # Create email body
            text_body = f"""
Security Alert

Severity: {audit_log.severity.upper()}
Event Type: {audit_log.event_type}
User ID: {audit_log.user_id}
Action: {audit_log.action}
Resource: {audit_log.resource}
Result: {audit_log.result}
Timestamp: {audit_log.timestamp}
IP Address: {audit_log.ip_address or 'N/A'}

Details:
{self._format_details(audit_log.details)}

This is an automated security alert from the Zero Trust Security Framework.
"""
            
            html_body = f"""
<html>
<head></head>
<body>
    <h2 style="color: {'#d32f2f' if audit_log.severity == 'critical' else '#f57c00'};">Security Alert</h2>
    <table style="border-collapse: collapse; width: 100%;">
        <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Severity:</strong></td>
            <td style="padding: 8px; border: 1px solid #ddd;">{audit_log.severity.upper()}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Event Type:</strong></td>
            <td style="padding: 8px; border: 1px solid #ddd;">{audit_log.event_type}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>User ID:</strong></td>
            <td style="padding: 8px; border: 1px solid #ddd;">{audit_log.user_id}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Action:</strong></td>
            <td style="padding: 8px; border: 1px solid #ddd;">{audit_log.action}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Resource:</strong></td>
            <td style="padding: 8px; border: 1px solid #ddd;">{audit_log.resource}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Result:</strong></td>
            <td style="padding: 8px; border: 1px solid #ddd;">{audit_log.result}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Timestamp:</strong></td>
            <td style="padding: 8px; border: 1px solid #ddd;">{audit_log.timestamp}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>IP Address:</strong></td>
            <td style="padding: 8px; border: 1px solid #ddd;">{audit_log.ip_address or 'N/A'}</td></tr>
    </table>
    <h3>Details:</h3>
    <pre>{self._format_details(audit_log.details)}</pre>
    <p><em>This is an automated security alert from the Zero Trust Security Framework.</em></p>
</body>
</html>
"""
            
            # Attach both plain text and HTML versions
            part1 = MIMEText(text_body, 'plain')
            part2 = MIMEText(html_body, 'html')
            msg.attach(part1)
            msg.attach(part2)
            
            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
            
            print(f"Alert email sent for {audit_log.severity} severity event: {audit_log.action}")
        except Exception as e:
            print(f"Error sending alert email: {str(e)}")
    
    def _format_details(self, details):
        """
        Format details dictionary for email display
        
        Args:
            details (dict): Details dictionary
            
        Returns:
            str: Formatted details string
        """
        if not details:
            return "No additional details"
        
        formatted = []
        for key, value in details.items():
            formatted.append(f"  {key}: {value}")
        
        return "\n".join(formatted)
    
    def get_logs(self, filters=None, limit=100):
        """
        Retrieve audit logs with optional filtering
        
        Args:
            filters (dict, optional): Filter criteria
            limit (int): Maximum number of logs to return
            
        Returns:
            list: List of audit log dictionaries
        """
        try:
            logs_ref = self.db.collection('auditLogs')
            query = logs_ref
            
            # Apply filters
            if filters:
                if 'userId' in filters:
                    query = query.where('userId', '==', filters['userId'])
                
                if 'eventType' in filters:
                    query = query.where('eventType', '==', filters['eventType'])
                
                if 'severity' in filters:
                    query = query.where('severity', '==', filters['severity'])
                
                if 'result' in filters:
                    query = query.where('result', '==', filters['result'])
            
            # Order by timestamp descending
            query = query.order_by('timestamp', direction='DESCENDING').limit(limit)
            
            logs = []
            for doc in query.stream():
                log_data = doc.to_dict()
                # Convert timestamp to ISO format for JSON serialization
                if 'timestamp' in log_data and isinstance(log_data['timestamp'], datetime):
                    log_data['timestamp'] = log_data['timestamp'].isoformat()
                logs.append(log_data)
            
            return logs
        except Exception as e:
            print(f"Error retrieving logs: {str(e)}")
            return []


# Singleton instance
audit_logger = AuditLogger()

# Convenience function for backward compatibility
def log_audit_event(user_id, event_type, action, resource, result, details=None, ip_address=None, severity='low'):
    """Convenience function to log audit events"""
    return audit_logger.log_event(
        event_type=event_type,
        user_id=user_id,
        action=action,
        resource=resource,
        result=result,
        details=details,
        ip_address=ip_address,
        severity=severity
    )
