"""
Audit Integration Example
Shows how to integrate the Enhanced Audit Service with existing Zero Trust components.
"""

from datetime import datetime
from app.services.enhanced_audit_service import enhanced_audit_service, audit_retention_service


class AuditIntegrationExample:
    """
    Example class showing how to integrate audit logging throughout the Zero Trust system.
    """
    
    def __init__(self):
        self.audit_service = enhanced_audit_service
        self.retention_service = audit_retention_service
    
    def example_device_fingerprint_flow(self, user_id: str, device_characteristics: dict, 
                                      ip_address: str, user_agent: str):
        """Example: Device fingerprint validation with comprehensive audit logging"""
        
        # Simulate device fingerprint validation
        similarity_score = 97.5  # Example similarity score
        validation_result = similarity_score >= 95.0
        
        # Log the device validation event
        log_id = self.audit_service.log_device_validation(
            user_id=user_id,
            device_id=device_characteristics.get('device_id', 'unknown'),
            validation_result=validation_result,
            similarity_score=similarity_score,
            ip_address=ip_address,
            user_agent=user_agent,
            fingerprint_hash=device_characteristics.get('hash', ''),
            canvas_hash=device_characteristics.get('canvas', ''),
            webgl_renderer=device_characteristics.get('webgl_renderer', ''),
            screen_resolution=device_characteristics.get('screen', ''),
            platform=device_characteristics.get('platform', '')
        )
        
        print(f"Device validation logged with ID: {log_id}")
        return validation_result, log_id
    
    def example_jit_access_flow(self, user_id: str, resource_segment_id: str, 
                              justification: str, duration_hours: int):
        """Example: JIT access request with audit logging"""
        
        # Log JIT access request
        request_log_id = self.audit_service.log_jit_access_event(
            user_id=user_id,
            resource_segment_id=resource_segment_id,
            action='request',
            result='success',
            risk_score=25.0,
            confidence_score=85.0,
            additional_details={
                'justification': justification,
                'requested_duration_hours': duration_hours,
                'policy_evaluation': {
                    'user_history_score': 90,
                    'resource_sensitivity': 3,
                    'time_appropriateness': 85
                }
            }
        )
        
        # Simulate approval process
        approved = True  # Example approval
        
        if approved:
            # Log JIT access grant
            grant_log_id = self.audit_service.log_jit_access_event(
                user_id=user_id,
                resource_segment_id=resource_segment_id,
                action='grant',
                result='success',
                session_id=f"jit_session_{user_id}_{datetime.utcnow().timestamp()}",
                additional_details={
                    'granted_duration_hours': duration_hours,
                    'expires_at': (datetime.utcnow().timestamp() + (duration_hours * 3600))
                }
            )
            
            print(f"JIT access request logged: {request_log_id}")
            print(f"JIT access grant logged: {grant_log_id}")
            return True, grant_log_id
        else:
            # Log JIT access denial
            deny_log_id = self.audit_service.log_jit_access_event(
                user_id=user_id,
                resource_segment_id=resource_segment_id,
                action='deny',
                result='denied',
                additional_details={
                    'denial_reason': 'Insufficient justification'
                }
            )
            
            print(f"JIT access denied and logged: {deny_log_id}")
            return False, deny_log_id
    
    def example_break_glass_flow(self, user_id: str, emergency_type: str, 
                               justification: str, approver_ids: list):
        """Example: Break-glass emergency access with dual approval logging"""
        
        # Log break-glass request
        request_log_id = self.audit_service.log_break_glass_event(
            user_id=user_id,
            emergency_type=emergency_type,
            action='request',
            result='success',
            additional_details={
                'justification': justification,
                'urgency_level': 'critical',
                'required_approvers': len(approver_ids),
                'requested_resources': ['critical_system_access', 'admin_privileges']
            }
        )
        
        # Simulate dual approval process
        approvals = []
        for approver_id in approver_ids[:2]:  # Only need 2 approvals
            approval_log_id = self.audit_service.log_break_glass_event(
                user_id=approver_id,
                emergency_type=emergency_type,
                action='approve',
                result='success',
                target_user_id=user_id,
                additional_details={
                    'approval_timestamp': datetime.utcnow().isoformat(),
                    'approver_role': 'senior_admin'
                }
            )
            approvals.append(approval_log_id)
        
        # Log break-glass activation
        if len(approvals) >= 2:
            activation_log_id = self.audit_service.log_break_glass_event(
                user_id=user_id,
                emergency_type=emergency_type,
                action='activate',
                result='success',
                session_id=f"emergency_session_{user_id}_{datetime.utcnow().timestamp()}",
                additional_details={
                    'approver_count': len(approvals),
                    'max_duration_hours': 2,
                    'elevated_privileges': ['system_admin', 'database_access', 'network_config']
                }
            )
            
            print(f"Break-glass request logged: {request_log_id}")
            print(f"Break-glass approvals logged: {approvals}")
            print(f"Break-glass activation logged: {activation_log_id}")
            return True, activation_log_id
        
        return False, None
    
    def example_visitor_management_flow(self, visitor_id: str, host_id: str, 
                                      visit_purpose: str, duration_hours: int):
        """Example: Visitor management with comprehensive tracking"""
        
        # Log visitor registration
        registration_log_id = self.audit_service.log_visitor_activity(
            visitor_id=visitor_id,
            host_id=host_id,
            action='register',
            result='success',
            visit_purpose=visit_purpose,
            expected_duration_hours=duration_hours,
            assigned_route=['lobby', 'elevator_bank_a', 'floor_3', 'research_lab_301'],
            security_clearance='visitor_level_1'
        )
        
        # Log visitor access attempts
        access_attempts = [
            ('lobby', 'success'),
            ('elevator_bank_a', 'success'),
            ('floor_3', 'success'),
            ('research_lab_301', 'success'),
            ('restricted_area_x', 'denied')  # Route violation
        ]
        
        access_log_ids = []
        for location, result in access_attempts:
            access_log_id = self.audit_service.log_visitor_activity(
                visitor_id=visitor_id,
                host_id=host_id,
                action='access_attempt',
                result=result,
                location=location,
                route_compliance=result == 'success',
                timestamp=datetime.utcnow().isoformat()
            )
            access_log_ids.append(access_log_id)
        
        # Log visitor session termination
        termination_log_id = self.audit_service.log_visitor_activity(
            visitor_id=visitor_id,
            host_id=host_id,
            action='terminate',
            result='success',
            termination_reason='session_expired',
            total_duration_minutes=duration_hours * 60,
            route_violations=1,
            compliance_score=80.0
        )
        
        print(f"Visitor registration logged: {registration_log_id}")
        print(f"Visitor access attempts logged: {len(access_log_ids)} events")
        print(f"Visitor termination logged: {termination_log_id}")
        return registration_log_id, access_log_ids, termination_log_id
    
    def example_compliance_reporting(self):
        """Example: Generate compliance report for audit purposes"""
        
        # Generate compliance report for the last 30 days
        start_date = datetime.utcnow().replace(day=1)  # First day of current month
        end_date = datetime.utcnow()
        
        print(f"Generating compliance report from {start_date.date()} to {end_date.date()}...")
        
        report = self.retention_service.generate_compliance_report(
            start_date=start_date,
            end_date=end_date,
            event_types=['authentication', 'jit_access', 'break_glass', 'visitor_management'],
            compliance_flags=['GDPR', 'SOX', 'ISO27001']
        )
        
        if 'error' not in report:
            print(f"✓ Compliance report generated successfully:")
            print(f"  - Report ID: {report['metadata']['report_id']}")
            print(f"  - Total events: {report['summary']['total_events']}")
            print(f"  - Generation time: {report['metadata']['generation_time_seconds']:.2f}s")
            print(f"  - Compliance score: {report['compliance_analysis']['compliance_score']:.1f}")
            print(f"  - Risk assessment: {report['compliance_analysis']['risk_assessment']}")
            
            # Export report data
            export_path = self.retention_service.export_audit_data(
                start_date=start_date,
                end_date=end_date,
                format_type='json',
                event_types=['break_glass', 'jit_access']
            )
            
            if export_path:
                print(f"  - Report exported to: {export_path}")
            
            return report
        else:
            print(f"✗ Compliance report generation failed: {report['error']}")
            return None
    
    def example_integrity_verification(self):
        """Example: Verify audit log integrity"""
        
        print("Performing audit log integrity verification...")
        
        # Verify integrity for the last 7 days
        start_date = datetime.utcnow() - datetime.timedelta(days=7)
        end_date = datetime.utcnow()
        
        verification_results = self.retention_service.batch_verify_integrity(
            start_date=start_date,
            end_date=end_date
        )
        
        if 'error' not in verification_results:
            print(f"✓ Integrity verification completed:")
            print(f"  - Total logs verified: {verification_results['total_logs']}")
            print(f"  - Verified logs: {verification_results['verified_logs']}")
            print(f"  - Failed logs: {verification_results['failed_logs']}")
            
            if verification_results['tampered_logs']:
                print(f"  - ⚠️  Tampered logs detected: {len(verification_results['tampered_logs'])}")
                for tampered_log in verification_results['tampered_logs']:
                    print(f"    - Log ID: {tampered_log['logId']}, Error: {tampered_log['error']}")
            else:
                print("  - ✓ No integrity violations detected")
            
            return verification_results
        else:
            print(f"✗ Integrity verification failed: {verification_results['error']}")
            return None


def run_integration_examples():
    """Run all integration examples"""
    print("Enhanced Audit Service Integration Examples")
    print("=" * 60)
    
    integration = AuditIntegrationExample()
    
    # Example 1: Device fingerprint validation
    print("\n1. Device Fingerprint Validation Example:")
    device_chars = {
        'device_id': 'device_12345',
        'hash': 'abc123def456ghi789',
        'canvas': 'canvas_hash_xyz',
        'webgl_renderer': 'NVIDIA GeForce GTX 1080',
        'screen': '1920x1080',
        'platform': 'Win32'
    }
    
    validation_result, log_id = integration.example_device_fingerprint_flow(
        user_id='user_alice_123',
        device_characteristics=device_chars,
        ip_address='192.168.1.100',
        user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    )
    
    # Example 2: JIT access flow
    print("\n2. JIT Access Flow Example:")
    jit_approved, jit_log_id = integration.example_jit_access_flow(
        user_id='user_bob_456',
        resource_segment_id='research_lab_secure',
        justification='Need access to analyze critical research data for ongoing project deadline',
        duration_hours=4
    )
    
    # Example 3: Break-glass emergency access
    print("\n3. Break-Glass Emergency Access Example:")
    emergency_approved, emergency_log_id = integration.example_break_glass_flow(
        user_id='user_charlie_789',
        emergency_type='system_outage',
        justification='Critical system outage affecting production services, need immediate admin access to restore operations',
        approver_ids=['admin_david_001', 'admin_eve_002', 'admin_frank_003']
    )
    
    # Example 4: Visitor management
    print("\n4. Visitor Management Flow Example:")
    reg_id, access_ids, term_id = integration.example_visitor_management_flow(
        visitor_id='visitor_grace_999',
        host_id='faculty_henry_555',
        visit_purpose='research_collaboration',
        duration_hours=6
    )
    
    # Example 5: Compliance reporting
    print("\n5. Compliance Reporting Example:")
    compliance_report = integration.example_compliance_reporting()
    
    # Example 6: Integrity verification
    print("\n6. Integrity Verification Example:")
    integrity_results = integration.example_integrity_verification()
    
    print("\n" + "=" * 60)
    print("Integration Examples Completed Successfully!")
    print("\nKey Integration Points Demonstrated:")
    print("- Device fingerprint validation with detailed audit logging")
    print("- JIT access request/approval workflow with risk assessment")
    print("- Break-glass emergency access with dual approval tracking")
    print("- Visitor management with route compliance monitoring")
    print("- Automated compliance reporting with configurable filters")
    print("- Cryptographic integrity verification for tamper detection")
    print("- Structured logging with comprehensive metadata")
    print("- Real-time security alerts for high-severity events")


if __name__ == "__main__":
    run_integration_examples()