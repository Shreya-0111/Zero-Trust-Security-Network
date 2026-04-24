import os
from celery import Celery

# Define Celery app
celery_app = Celery('shh_app')

# Configure Celery
# Using task_always_eager=True since Redis is not configured/used in this environment
celery_app.conf.update(
    broker_url=os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0'),
    result_backend=os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0'),
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_always_eager=True  # Execute tasks locally instead of sending to worker
)