"""
Connection Pool Service for Performance Optimization
Manages database and Redis connection pools for high-load scenarios
"""

import logging
import threading
import time
from typing import Optional, Dict, Any
from contextlib import contextmanager
from queue import Queue, Empty, Full
from firebase_admin import firestore
import redis
from redis_config import get_redis_client, REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD, is_redis_available

logger = logging.getLogger(__name__)

class ConnectionPool:
    """Generic connection pool implementation"""
    
    def __init__(self, create_connection_func, max_connections=20, min_connections=5, 
                 connection_timeout=30, idle_timeout=300):
        self.create_connection = create_connection_func
        self.max_connections = max_connections
        self.min_connections = min_connections
        self.connection_timeout = connection_timeout
        self.idle_timeout = idle_timeout
        
        self._pool = Queue(maxsize=max_connections)
        self._active_connections = 0
        self._lock = threading.RLock()
        self._connection_times = {}
        
        # Pre-populate with minimum connections
        self._initialize_pool()
        
        # Start cleanup thread
        self._cleanup_thread = threading.Thread(target=self._cleanup_idle_connections, daemon=True)
        self._cleanup_thread.start()
    
    def _initialize_pool(self):
        """Initialize pool with minimum connections"""
        for _ in range(self.min_connections):
            try:
                conn = self.create_connection()
                self._pool.put(conn, block=False)
                self._active_connections += 1
            except Exception as e:
                logger.error(f"Error initializing connection pool: {e}")
    
    def get_connection(self, timeout=None):
        """Get a connection from the pool"""
        timeout = timeout or self.connection_timeout
        
        try:
            # Try to get existing connection
            conn = self._pool.get(block=True, timeout=timeout)
            self._connection_times[id(conn)] = time.time()
            return conn
        except Empty:
            # Pool is empty, create new connection if under limit
            with self._lock:
                if self._active_connections < self.max_connections:
                    try:
                        conn = self.create_connection()
                        self._active_connections += 1
                        self._connection_times[id(conn)] = time.time()
                        return conn
                    except Exception as e:
                        logger.error(f"Error creating new connection: {e}")
                        raise
                else:
                    raise Exception("Connection pool exhausted")
    
    def return_connection(self, conn):
        """Return a connection to the pool"""
        if conn is None:
            return
        
        try:
            # Validate connection before returning
            if self._validate_connection(conn):
                self._pool.put(conn, block=False)
                self._connection_times[id(conn)] = time.time()
            else:
                # Connection is invalid, create a new one
                self._close_connection(conn)
                with self._lock:
                    self._active_connections -= 1
                    if id(conn) in self._connection_times:
                        del self._connection_times[id(conn)]
        except Full:
            # Pool is full, close the connection
            self._close_connection(conn)
            with self._lock:
                self._active_connections -= 1
                if id(conn) in self._connection_times:
                    del self._connection_times[id(conn)]
        except Exception as e:
            logger.error(f"Error returning connection to pool: {e}")
    
    def _validate_connection(self, conn):
        """Validate if connection is still usable"""
        # Override in subclasses
        return True
    
    def _close_connection(self, conn):
        """Close a connection"""
        # Override in subclasses
        pass
    
    def _cleanup_idle_connections(self):
        """Background thread to cleanup idle connections"""
        while True:
            try:
                time.sleep(60)  # Check every minute
                current_time = time.time()
                connections_to_remove = []
                
                # Check for idle connections
                for conn_id, last_used in list(self._connection_times.items()):
                    if current_time - last_used > self.idle_timeout:
                        connections_to_remove.append(conn_id)
                
                # Remove idle connections (keep minimum)
                if len(connections_to_remove) > 0 and self._active_connections > self.min_connections:
                    removed_count = 0
                    while (not self._pool.empty() and 
                           removed_count < len(connections_to_remove) and 
                           self._active_connections > self.min_connections):
                        try:
                            conn = self._pool.get(block=False)
                            if id(conn) in connections_to_remove:
                                self._close_connection(conn)
                                with self._lock:
                                    self._active_connections -= 1
                                    if id(conn) in self._connection_times:
                                        del self._connection_times[id(conn)]
                                removed_count += 1
                            else:
                                # Put back if not idle
                                self._pool.put(conn, block=False)
                        except (Empty, Full):
                            break
                    
                    if removed_count > 0:
                        logger.info(f"Cleaned up {removed_count} idle connections")
                        
            except Exception as e:
                logger.error(f"Error in connection cleanup: {e}")
    
    @contextmanager
    def get_connection_context(self):
        """Context manager for getting and returning connections"""
        conn = None
        try:
            conn = self.get_connection()
            yield conn
        finally:
            if conn:
                self.return_connection(conn)
    
    def get_stats(self):
        """Get pool statistics"""
        return {
            "active_connections": self._active_connections,
            "pool_size": self._pool.qsize(),
            "max_connections": self.max_connections,
            "min_connections": self.min_connections
        }


class FirestoreConnectionPool(ConnectionPool):
    """Firestore connection pool"""
    
    def __init__(self, max_connections=20, min_connections=5):
        super().__init__(
            create_connection_func=self._create_firestore_client,
            max_connections=max_connections,
            min_connections=min_connections
        )
    
    def _create_firestore_client(self):
        """Create a new Firestore client"""
        return firestore.client()
    
    def _validate_connection(self, conn):
        """Validate Firestore connection"""
        try:
            # Simple validation - try to access collections
            conn.collections()
            return True
        except Exception:
            return False


class RedisConnectionPool(ConnectionPool):
    """Redis connection pool"""
    
    def __init__(self, max_connections=30, min_connections=10):
        super().__init__(
            create_connection_func=self._create_redis_client,
            max_connections=max_connections,
            min_connections=min_connections
        )
    
    def _create_redis_client(self):
        """Create a new Redis client"""
        return redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            password=REDIS_PASSWORD if REDIS_PASSWORD else None,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True,
            health_check_interval=30,
            connection_pool=None  # Use our own pooling
        )
    
    def _validate_connection(self, conn):
        """Validate Redis connection"""
        try:
            conn.ping()
            return True
        except Exception:
            return False
    
    def _close_connection(self, conn):
        """Close Redis connection"""
        try:
            conn.close()
        except Exception:
            pass


class ConnectionPoolService:
    """Service for managing all connection pools"""
    
    def __init__(self):
        self._firestore_pool = None
        self._redis_pool = None
        self._initialized = False
        self._lock = threading.Lock()
    
    def initialize(self):
        """Initialize connection pools"""
        with self._lock:
            if self._initialized:
                return
            
            try:
                # Initialize Firestore pool
                self._firestore_pool = FirestoreConnectionPool(
                    max_connections=20,
                    min_connections=5
                )
                logger.info("Firestore connection pool initialized")
                
                # Initialize Redis pool
                if is_redis_available():
                    self._redis_pool = RedisConnectionPool(
                        max_connections=30,
                        min_connections=10
                    )
                    logger.info("Redis connection pool initialized")
                else:
                    logger.info("Redis not available, skipping connection pool initialization")
                
                self._initialized = True
                
            except Exception as e:
                logger.error(f"Error initializing connection pools: {e}")
                raise
    
    @contextmanager
    def get_firestore_connection(self):
        """Get Firestore connection from pool"""
        if not self._initialized:
            self.initialize()
        
        with self._firestore_pool.get_connection_context() as conn:
            yield conn
    
    @contextmanager
    def get_redis_connection(self):
        """Get Redis connection from pool"""
        if not self._initialized:
            self.initialize()
        
        with self._redis_pool.get_connection_context() as conn:
            yield conn
    
    def get_firestore_pool_stats(self):
        """Get Firestore pool statistics"""
        if self._firestore_pool:
            return self._firestore_pool.get_stats()
        return {}
    
    def get_redis_pool_stats(self):
        """Get Redis pool statistics"""
        if self._redis_pool:
            return self._redis_pool.get_stats()
        return {}
    
    def get_all_stats(self):
        """Get all connection pool statistics"""
        return {
            "firestore": self.get_firestore_pool_stats(),
            "redis": self.get_redis_pool_stats(),
            "initialized": self._initialized
        }


# Global connection pool service instance
connection_pool_service = ConnectionPoolService()

# DISABLE AUTOMATIC INITIALIZATION FOR FAST STARTUP
# Initialize only when needed (lazy loading)
import os
if os.getenv('FLASK_ENV') != 'development' and os.getenv('ENABLE_CONNECTION_POOLS', 'false').lower() == 'true':
    # Only initialize in production if explicitly enabled
    try:
        import signal
        
        def timeout_handler(signum, frame):
            raise TimeoutError("Connection pool initialization timed out")
        
        # Set a 5-second timeout for initialization (reduced from 10)
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(5)
        
        connection_pool_service.initialize()
        
        signal.alarm(0)  # Cancel the alarm
        print("Connection pools initialized")
    except TimeoutError:
        print("Connection pool initialization timed out - will initialize on first use")
    except Exception as e:
        print(f"Connection pool initialization failed: {e}")
else:
    print("Connection pools disabled for fast startup - will initialize on demand")