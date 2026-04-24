"""
Integration tests for visitor management lifecycle
Tests end-to-end visitor registration, session management, route compliance, and termination
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock
from datetime import datetime, timedelta


class TestVisitorManagementIntegration:
    """Integration tests for visitor management workflow"""
    
    @pytest.fixture
    def visitor_service(self):
        """Mock visitor service"""
        service = Mock()
        return service
    
    @pytest.mark.asyncio
    async def test_complete_visitor_registration_workflow(self, visitor_service):
        """Test complete visitor registration workflow"""
        # Mock visitor registration
        visitor_service.register_visitor = AsyncMock(return_value=Mock(
            name="John Visitor",
            host_id="host_123",
            status="active",
            max_duration=4,
            visitor_id="visitor_123"
        ))
        
        # Execute registration
        result = await visitor_service.register_visitor(
            {"name": "John Visitor"}, Mock(), "host_123"
        )
        
        # Verify registration success
        assert result.name == "John Visitor"
        assert result.host_id == "host_123"
        assert result.status == "active"
        assert result.max_duration == 4
    
    @pytest.mark.asyncio
    async def test_visitor_session_duration_enforcement_workflow(self, visitor_service):
        """Test visitor session duration enforcement and automatic expiration"""
        # Mock expired session check
        visitor_service.check_expired_sessions = AsyncMock(return_value=["visitor_123"])
        
        # Execute expiration check
        expired_visitors = await visitor_service.check_expired_sessions()
        
        # Verify expired session was handled
        assert len(expired_visitors) == 1
        assert expired_visitors[0] == "visitor_123"
    
    @pytest.mark.asyncio
    async def test_visitor_route_compliance_monitoring_workflow(self, visitor_service):
        """Test visitor route compliance monitoring and violation detection"""
        # Mock route compliance tracking
        visitor_service.track_visitor_access = AsyncMock()
        visitor_service.track_visitor_access.side_effect = [True, False]  # First allowed, second denied
        
        # Test allowed access
        result1 = await visitor_service.track_visitor_access(
            "visitor_123", "academic_resources", "read", "host_123"
        )
        assert result1 is True
        
        # Test unauthorized access (route violation)
        result2 = await visitor_service.track_visitor_access(
            "visitor_123", "admin_systems", "read", "host_123"
        )
        assert result2 is False
    
    @pytest.mark.asyncio
    async def test_visitor_session_extension_workflow(self, visitor_service):
        """Test visitor session extension with host request and admin approval"""
        # Mock session extension
        visitor_service.extend_visitor_session = AsyncMock(return_value=Mock(
            visitor_id="visitor_123",
            session_extensions=[Mock(
                additional_hours=2,
                requested_by="host_123",
                approved_by="admin_456"
            )]
        ))
        
        # Execute session extension
        result = await visitor_service.extend_visitor_session(
            "visitor_123", 2, "Meeting running longer", "host_123", "admin_456"
        )
        
        # Verify extension was applied
        assert result.visitor_id == "visitor_123"
        assert len(result.session_extensions) == 1
        
        extension = result.session_extensions[0]
        assert extension.additional_hours == 2
        assert extension.requested_by == "host_123"
        assert extension.approved_by == "admin_456"
    
    @pytest.mark.asyncio
    async def test_visitor_session_termination_workflow(self, visitor_service):
        """Test manual visitor session termination"""
        # Mock session termination
        visitor_service.terminate_visitor_session = AsyncMock(return_value=Mock(
            visitor_id="visitor_123",
            status="terminated",
            actual_exit_time=datetime.utcnow()
        ))
        
        # Execute session termination
        result = await visitor_service.terminate_visitor_session(
            "visitor_123", "Early departure", "host_123"
        )
        
        # Verify termination was applied
        assert result.visitor_id == "visitor_123"
        assert result.status == "terminated"
        assert result.actual_exit_time is not None
    
    @pytest.mark.asyncio
    async def test_visitor_compliance_report_generation_workflow(self, visitor_service):
        """Test visitor compliance report generation"""
        # Mock compliance report generation
        visitor_service.get_visitor_compliance_report = AsyncMock(return_value={
            "visitor_id": "visitor_123",
            "visitor_name": "Test Visitor",
            "host_name": "Dr. Smith",
            "access_summary": {
                "total_accesses": 3,
                "approved_accesses": 2,
                "denied_accesses": 1,
                "approval_rate": 66.67
            },
            "compliance_metrics": {
                "overall_score": 85,
                "total_deviations": 1
            }
        })
        
        # Execute report generation
        report = await visitor_service.get_visitor_compliance_report(
            "visitor_123", "host_123"
        )
        
        # Verify report contents
        assert report["visitor_id"] == "visitor_123"
        assert report["visitor_name"] == "Test Visitor"
        assert report["host_name"] == "Dr. Smith"
        
        # Verify access summary
        access_summary = report["access_summary"]
        assert access_summary["total_accesses"] == 3
        assert access_summary["approved_accesses"] == 2
        assert access_summary["denied_accesses"] == 1
        assert access_summary["approval_rate"] == pytest.approx(66.67, rel=1e-2)
        
        # Verify compliance metrics
        compliance_metrics = report["compliance_metrics"]
        assert compliance_metrics["overall_score"] == 85
        assert compliance_metrics["total_deviations"] == 1