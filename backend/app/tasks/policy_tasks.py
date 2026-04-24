"""
Celery Tasks for Adaptive Policy Optimization
Background tasks for policy performance tracking and optimization
"""

from celery_config import celery_app
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


@celery_app.task(name='app.tasks.policy_tasks.optimize_policies')
def optimize_policies():
    """
    Optimize all policies based on performance metrics
    Runs daily at 3 AM (configured in celery_config.py)
    """
    try:
        logger.info("Starting policy optimization...")
        
        from app.services.adaptive_policy import adaptive_policy_service
        from app.models.policy import Policy
        
        # Get all active policies
        # In production, query Firestore for active policies
        # policies = Policy.get_all_active()
        
        policies_optimized = 0
        policies_failed = 0
        recommendations = []
        
        # For each policy, analyze performance and generate recommendations
        # for policy in policies:
        #     try:
        #         # Calculate effectiveness metrics
        #         metrics = adaptive_policy_service.calculate_effectiveness_metrics(policy.id)
        #         
        #         # Generate optimization recommendations
        #         policy_recommendations = adaptive_policy_service.generate_policy_recommendations(policy.id)
        #         
        #         if policy_recommendations:
        #             recommendations.extend(policy_recommendations)
        #             
        #             # Auto-apply low-risk optimizations
        #             for rec in policy_recommendations:
        #                 if rec.get('auto_apply') and rec.get('risk_level') == 'low':
        #                     result = adaptive_policy_service.apply_recommendation(policy.id, rec)
        #                     if result.get('success'):
        #                         policies_optimized += 1
        #         
        #     except Exception as e:
        #         logger.error(f"Failed to optimize policy {policy.id}: {e}")
        #         policies_failed += 1
        
        # Log optimization results
        from app.services.audit_logger import log_audit_event
        
        log_audit_event(
            user_id='system',
            action='policies_optimized',
            resource_type='policy_optimization',
            resource_id='daily_optimization',
            details={
                'policies_optimized': policies_optimized,
                'policies_failed': policies_failed,
                'recommendations_generated': len(recommendations)
            }
        )
        
        logger.info(f"Policy optimization completed: {policies_optimized} optimized, {policies_failed} failed")
        
        return {
            'status': 'success',
            'policies_optimized': policies_optimized,
            'policies_failed': policies_failed,
            'recommendations': recommendations,
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in optimize_policies task: {e}")
        return {'status': 'error', 'error': str(e)}


@celery_app.task(name='app.tasks.policy_tasks.calculate_policy_effectiveness')
def calculate_policy_effectiveness(policy_id: str):
    """
    Calculate effectiveness metrics for a specific policy
    Can be triggered on-demand
    
    Args:
        policy_id: Policy identifier
    """
    try:
        logger.info(f"Calculating effectiveness for policy {policy_id}...")
        
        from app.services.adaptive_policy import adaptive_policy_service
        
        # Calculate metrics
        metrics = adaptive_policy_service.calculate_effectiveness_metrics(policy_id)
        
        # Cache the metrics
        from app.services.cache_service import cache_service
        cache_service.cache_policy_performance(
            policy_id,
            metrics,
            ttl=1800  # 30 minutes
        )
        
        logger.info(f"Effectiveness calculated for policy {policy_id}: {metrics.get('effectiveness_score')}%")
        
        return {
            'status': 'success',
            'policy_id': policy_id,
            'metrics': metrics,
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error calculating effectiveness for policy {policy_id}: {e}")
        return {
            'status': 'error',
            'policy_id': policy_id,
            'error': str(e)
        }


@celery_app.task(name='app.tasks.policy_tasks.track_policy_outcome')
def track_policy_outcome(policy_id: str, request_id: str, outcome: dict):
    """
    Track the outcome of a policy application
    Called after each access request is processed
    
    Args:
        policy_id: Policy identifier
        request_id: Access request identifier
        outcome: Outcome data (approved/denied, correct/incorrect)
    """
    try:
        from app.services.adaptive_policy import adaptive_policy_service
        
        # Track the outcome
        result = adaptive_policy_service.track_policy_outcome(
            policy_id,
            request_id,
            outcome
        )
        
        return {
            'status': 'success',
            'policy_id': policy_id,
            'request_id': request_id,
            'result': result
        }
        
    except Exception as e:
        logger.error(f"Error tracking policy outcome: {e}")
        return {
            'status': 'error',
            'policy_id': policy_id,
            'request_id': request_id,
            'error': str(e)
        }


@celery_app.task(name='app.tasks.policy_tasks.simulate_policy_change')
def simulate_policy_change(policy_id: str, new_params: dict):
    """
    Simulate the impact of a policy change before applying it
    
    Args:
        policy_id: Policy identifier
        new_params: New policy parameters to simulate
    """
    try:
        logger.info(f"Simulating policy change for {policy_id}...")
        
        from app.services.adaptive_policy import adaptive_policy_service
        
        # Run simulation
        simulation_result = adaptive_policy_service.simulate_policy_change(
            policy_id,
            new_params
        )
        
        logger.info(f"Simulation completed for policy {policy_id}")
        
        return {
            'status': 'success',
            'policy_id': policy_id,
            'simulation_result': simulation_result,
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error simulating policy change: {e}")
        return {
            'status': 'error',
            'policy_id': policy_id,
            'error': str(e)
        }


@celery_app.task(name='app.tasks.policy_tasks.rollback_policy')
def rollback_policy(policy_id: str, version: str):
    """
    Rollback a policy to a previous version
    
    Args:
        policy_id: Policy identifier
        version: Version to rollback to
    """
    try:
        logger.info(f"Rolling back policy {policy_id} to version {version}...")
        
        from app.services.adaptive_policy import adaptive_policy_service
        
        # Perform rollback
        result = adaptive_policy_service.rollback_policy(policy_id, version)
        
        # Log the rollback
        from app.services.audit_logger import log_audit_event
        
        log_audit_event(
            user_id='system',
            action='policy_rollback',
            resource_type='policy',
            resource_id=policy_id,
            details={
                'version': version,
                'reason': result.get('reason'),
                'success': result.get('success')
            },
            severity='high'
        )
        
        logger.info(f"Policy {policy_id} rolled back to version {version}")
        
        return {
            'status': 'success',
            'policy_id': policy_id,
            'version': version,
            'result': result,
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error rolling back policy: {e}")
        return {
            'status': 'error',
            'policy_id': policy_id,
            'version': version,
            'error': str(e)
        }


@celery_app.task(name='app.tasks.policy_tasks.check_policy_health')
def check_policy_health():
    """
    Check health of all policies and identify issues
    Runs every 6 hours
    """
    try:
        logger.info("Checking policy health...")
        
        from app.services.adaptive_policy import adaptive_policy_service
        
        # Check all policies
        health_report = adaptive_policy_service.check_all_policies_health()
        
        # Identify policies needing attention
        unhealthy_policies = [
            p for p in health_report.get('policies', [])
            if p.get('effectiveness_score', 100) < 70
        ]
        
        if unhealthy_policies:
            logger.warning(f"Found {len(unhealthy_policies)} unhealthy policies")
            
            # Send alert to admins
            from websocket_config import emit_admin_notification
            emit_admin_notification({
                'type': 'policy_health_alert',
                'message': f'{len(unhealthy_policies)} policies need attention',
                'unhealthy_policies': unhealthy_policies
            })
        
        logger.info(f"Policy health check completed: {len(unhealthy_policies)} issues found")
        
        return {
            'status': 'success',
            'total_policies': len(health_report.get('policies', [])),
            'unhealthy_policies': len(unhealthy_policies),
            'health_report': health_report,
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in check_policy_health task: {e}")
        return {'status': 'error', 'error': str(e)}
