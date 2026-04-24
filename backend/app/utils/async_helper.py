"""
Async Helper Utilities
Helper functions to handle async calls in synchronous Flask routes
"""

import asyncio
from functools import wraps
from typing import Any, Callable, Coroutine


def run_async(coro: Coroutine) -> Any:
    """
    Run an async coroutine in a synchronous context
    
    Args:
        coro: The coroutine to run
        
    Returns:
        The result of the coroutine
    """
    try:
        # Try to get the current event loop
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If loop is already running, we need to use a different approach
            # This can happen in some testing scenarios
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(asyncio.run, coro)
                return future.result()
        else:
            return loop.run_until_complete(coro)
    except RuntimeError:
        # No event loop exists, create a new one
        return asyncio.run(coro)


def async_route(f: Callable) -> Callable:
    """
    Decorator to allow async functions to be used as Flask routes
    
    Usage:
        @app.route('/example')
        @async_route
        async def example_route():
            result = await some_async_function()
            return jsonify(result)
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        coro = f(*args, **kwargs)
        return run_async(coro)
    return wrapper


def make_sync(async_func: Callable) -> Callable:
    """
    Convert an async function to a synchronous one
    
    Args:
        async_func: The async function to convert
        
    Returns:
        A synchronous wrapper function
    """
    @wraps(async_func)
    def sync_wrapper(*args, **kwargs):
        coro = async_func(*args, **kwargs)
        return run_async(coro)
    return sync_wrapper