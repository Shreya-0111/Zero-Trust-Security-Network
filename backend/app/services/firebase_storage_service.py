"""
Firebase Cloud Storage Service
Handles file storage, audit log archival, and ML model storage
"""

import logging
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, BinaryIO
from firebase_admin import storage
from firebase_admin.exceptions import FirebaseError
from app.utils.error_handler import handle_service_error
from app.services.audit_logger import AuditLogger

logger = logging.getLogger(__name__)

class FirebaseStorageService:
    """Firebase Cloud Storage service for file management"""
    
    def __init__(self):
        self.bucket = storage.bucket()
        self.audit_logger = AuditLogger()
        
        # Storage paths
        self.paths = {
            'audit_archives': 'audit_archives/',
            'ml_models': 'ml_models/',
            'user_archives': 'user_archives/',
            'visitor_photos': 'visitor_photos/',
            'incident_reports': 'incident_reports/',
            'security_logs': 'security_logs/',
            'backups': 'backups/',
            'temp': 'temp/'
        }
    
    @handle_service_error
    def upload_file(self, file_data: bytes, file_path: str, content_type: str = 'application/octet-stream', metadata: Dict = None) -> Dict:
        """
        Upload file to Cloud Storage
        
        Args:
            file_data: File content as bytes
            file_path: Storage path for the file
            content_type: MIME type of the file
            metadata: Additional metadata
            
        Returns:
            Upload result with file info
        """
        try:
            blob = self.bucket.blob(file_path)
            
            # Set metadata if provided
            if metadata:
                blob.metadata = metadata
            
            # Upload file
            blob.upload_from_string(file_data, content_type=content_type)
            
            # Get file info
            file_info = {
                'name': blob.name,
                'size': blob.size,
                'contentType': blob.content_type,
                'timeCreated': blob.time_created,
                'updated': blob.updated,
                'md5Hash': blob.md5_hash,
                'crc32c': blob.crc32c,
                'downloadUrl': blob.generate_signed_url(timedelta(hours=1))
            }
            
            logger.info(f"Uploaded file to Cloud Storage: {file_path}")
            return {
                'success': True,
                'filePath': file_path,
                'fileInfo': file_info
            }
            
        except FirebaseError as e:
            logger.error(f"Firebase error uploading file: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error uploading file: {str(e)}")
            raise
    
    @handle_service_error
    def download_file(self, file_path: str) -> bytes:
        """
        Download file from Cloud Storage
        
        Args:
            file_path: Storage path of the file
            
        Returns:
            File content as bytes
        """
        try:
            blob = self.bucket.blob(file_path)
            
            if not blob.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            file_data = blob.download_as_bytes()
            
            logger.info(f"Downloaded file from Cloud Storage: {file_path}")
            return file_data
            
        except FirebaseError as e:
            logger.error(f"Firebase error downloading file: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error downloading file: {str(e)}")
            raise
    
    @handle_service_error
    def delete_file(self, file_path: str) -> bool:
        """
        Delete file from Cloud Storage
        
        Args:
            file_path: Storage path of the file
            
        Returns:
            Success status
        """
        try:
            blob = self.bucket.blob(file_path)
            
            if blob.exists():
                blob.delete()
                logger.info(f"Deleted file from Cloud Storage: {file_path}")
                return True
            else:
                logger.warning(f"File not found for deletion: {file_path}")
                return False
            
        except FirebaseError as e:
            logger.error(f"Firebase error deleting file: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error deleting file: {str(e)}")
            raise
    
    @handle_service_error
    def archive_audit_logs(self, audit_logs: List[Dict], archive_name: str = None) -> str:
        """
        Archive audit logs to Cloud Storage
        
        Args:
            audit_logs: List of audit log entries
            archive_name: Custom archive name (optional)
            
        Returns:
            Archive file path
        """
        try:
            if not archive_name:
                archive_name = f"audit_logs_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            
            archive_path = f"{self.paths['audit_archives']}{archive_name}"
            
            # Prepare archive data
            archive_data = {
                'archivedAt': datetime.utcnow().isoformat(),
                'totalLogs': len(audit_logs),
                'logs': audit_logs
            }
            
            # Convert to JSON and upload
            json_data = json.dumps(archive_data, default=str, indent=2)
            
            result = self.upload_file(
                file_data=json_data.encode('utf-8'),
                file_path=archive_path,
                content_type='application/json',
                metadata={
                    'type': 'audit_archive',
                    'logCount': str(len(audit_logs)),
                    'archivedAt': datetime.utcnow().isoformat()
                }
            )
            
            # Log the archival
            self.audit_logger.log_event(
                event_type="audit_log_archival",
                user_id="system",
                action="archive_audit_logs",
                resource="audit_logs",
                result="success",
                details={
                    "archive_path": archive_path,
                    "log_count": len(audit_logs)
                },
                severity="low"
            )
            
            logger.info(f"Archived {len(audit_logs)} audit logs to {archive_path}")
            return archive_path
            
        except Exception as e:
            logger.error(f"Error archiving audit logs: {str(e)}")
            raise
    
    @handle_service_error
    def store_ml_model(self, model_data: bytes, model_name: str, model_metadata: Dict) -> str:
        """
        Store ML model in Cloud Storage
        
        Args:
            model_data: Serialized model data
            model_name: Name of the model
            model_metadata: Model metadata
            
        Returns:
            Storage path of the model
        """
        try:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            model_path = f"{self.paths['ml_models']}{model_name}_{timestamp}.pkl"
            
            # Upload model
            result = self.upload_file(
                file_data=model_data,
                file_path=model_path,
                content_type='application/octet-stream',
                metadata={
                    'type': 'ml_model',
                    'modelName': model_name,
                    'uploadedAt': datetime.utcnow().isoformat(),
                    **model_metadata
                }
            )
            
            # Store metadata separately
            metadata_path = f"{self.paths['ml_models']}{model_name}_{timestamp}_metadata.json"
            metadata_json = json.dumps({
                'modelName': model_name,
                'modelPath': model_path,
                'uploadedAt': datetime.utcnow().isoformat(),
                'metadata': model_metadata
            }, default=str, indent=2)
            
            self.upload_file(
                file_data=metadata_json.encode('utf-8'),
                file_path=metadata_path,
                content_type='application/json'
            )
            
            logger.info(f"Stored ML model: {model_name} at {model_path}")
            return model_path
            
        except Exception as e:
            logger.error(f"Error storing ML model: {str(e)}")
            raise
    
    @handle_service_error
    def store_visitor_photo(self, photo_data: bytes, visitor_id: str, photo_type: str = 'profile') -> str:
        """
        Store visitor photo in Cloud Storage
        
        Args:
            photo_data: Photo data as bytes
            visitor_id: Visitor identifier
            photo_type: Type of photo (profile, id_document, etc.)
            
        Returns:
            Storage path of the photo
        """
        try:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            photo_path = f"{self.paths['visitor_photos']}{visitor_id}_{photo_type}_{timestamp}.jpg"
            
            result = self.upload_file(
                file_data=photo_data,
                file_path=photo_path,
                content_type='image/jpeg',
                metadata={
                    'type': 'visitor_photo',
                    'visitorId': visitor_id,
                    'photoType': photo_type,
                    'uploadedAt': datetime.utcnow().isoformat()
                }
            )
            
            logger.info(f"Stored visitor photo: {visitor_id} at {photo_path}")
            return photo_path
            
        except Exception as e:
            logger.error(f"Error storing visitor photo: {str(e)}")
            raise
    
    @handle_service_error
    def create_backup(self, backup_data: Dict, backup_type: str) -> str:
        """
        Create system backup in Cloud Storage
        
        Args:
            backup_data: Data to backup
            backup_type: Type of backup (users, policies, etc.)
            
        Returns:
            Backup file path
        """
        try:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            backup_path = f"{self.paths['backups']}{backup_type}_backup_{timestamp}.json"
            
            # Prepare backup data
            backup_content = {
                'backupType': backup_type,
                'createdAt': datetime.utcnow().isoformat(),
                'data': backup_data
            }
            
            json_data = json.dumps(backup_content, default=str, indent=2)
            
            result = self.upload_file(
                file_data=json_data.encode('utf-8'),
                file_path=backup_path,
                content_type='application/json',
                metadata={
                    'type': 'system_backup',
                    'backupType': backup_type,
                    'createdAt': datetime.utcnow().isoformat()
                }
            )
            
            logger.info(f"Created {backup_type} backup at {backup_path}")
            return backup_path
            
        except Exception as e:
            logger.error(f"Error creating backup: {str(e)}")
            raise
    
    @handle_service_error
    def list_files(self, prefix: str = '', max_results: int = 100) -> List[Dict]:
        """
        List files in Cloud Storage
        
        Args:
            prefix: Path prefix to filter files
            max_results: Maximum number of results
            
        Returns:
            List of file information
        """
        try:
            blobs = self.bucket.list_blobs(prefix=prefix, max_results=max_results)
            
            file_list = []
            for blob in blobs:
                file_info = {
                    'name': blob.name,
                    'size': blob.size,
                    'contentType': blob.content_type,
                    'timeCreated': blob.time_created,
                    'updated': blob.updated,
                    'md5Hash': blob.md5_hash,
                    'metadata': blob.metadata or {}
                }
                file_list.append(file_info)
            
            return file_list
            
        except FirebaseError as e:
            logger.error(f"Firebase error listing files: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error listing files: {str(e)}")
            raise
    
    @handle_service_error
    def cleanup_old_files(self, path_prefix: str, days_old: int = 90) -> int:
        """
        Clean up old files from Cloud Storage
        
        Args:
            path_prefix: Path prefix to clean up
            days_old: Delete files older than this many days
            
        Returns:
            Number of files deleted
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days_old)
            
            blobs = self.bucket.list_blobs(prefix=path_prefix)
            deleted_count = 0
            
            for blob in blobs:
                if blob.time_created and blob.time_created.replace(tzinfo=None) < cutoff_date:
                    try:
                        blob.delete()
                        deleted_count += 1
                        logger.info(f"Deleted old file: {blob.name}")
                    except Exception as e:
                        logger.error(f"Error deleting file {blob.name}: {str(e)}")
            
            if deleted_count > 0:
                # Log cleanup operation
                self.audit_logger.log_event(
                    event_type="storage_cleanup",
                    user_id="system",
                    action="cleanup_old_files",
                    resource="cloud_storage",
                    result="success",
                    details={
                        "path_prefix": path_prefix,
                        "deleted_count": deleted_count,
                        "days_old": days_old
                    },
                    severity="low"
                )
            
            logger.info(f"Cleaned up {deleted_count} old files from {path_prefix}")
            return deleted_count
            
        except Exception as e:
            logger.error(f"Error cleaning up old files: {str(e)}")
            raise
    
    @handle_service_error
    def get_storage_usage(self) -> Dict:
        """
        Get storage usage statistics
        
        Returns:
            Storage usage information
        """
        try:
            usage_stats = {}
            
            for category, prefix in self.paths.items():
                blobs = self.bucket.list_blobs(prefix=prefix)
                
                total_size = 0
                file_count = 0
                
                for blob in blobs:
                    if blob.size:
                        total_size += blob.size
                    file_count += 1
                
                usage_stats[category] = {
                    'fileCount': file_count,
                    'totalSize': total_size,
                    'totalSizeMB': round(total_size / (1024 * 1024), 2)
                }
            
            # Calculate total usage
            total_files = sum(stats['fileCount'] for stats in usage_stats.values())
            total_size = sum(stats['totalSize'] for stats in usage_stats.values())
            
            usage_stats['total'] = {
                'fileCount': total_files,
                'totalSize': total_size,
                'totalSizeMB': round(total_size / (1024 * 1024), 2),
                'totalSizeGB': round(total_size / (1024 * 1024 * 1024), 2)
            }
            
            return usage_stats
            
        except Exception as e:
            logger.error(f"Error getting storage usage: {str(e)}")
            raise
    
    @handle_service_error
    def generate_signed_url(self, file_path: str, expiration_hours: int = 1) -> str:
        """
        Generate signed URL for file access
        
        Args:
            file_path: Storage path of the file
            expiration_hours: URL expiration time in hours
            
        Returns:
            Signed URL
        """
        try:
            blob = self.bucket.blob(file_path)
            
            if not blob.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            signed_url = blob.generate_signed_url(
                expiration=timedelta(hours=expiration_hours),
                method='GET'
            )
            
            logger.info(f"Generated signed URL for {file_path}, expires in {expiration_hours} hours")
            return signed_url
            
        except FirebaseError as e:
            logger.error(f"Firebase error generating signed URL: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error generating signed URL: {str(e)}")
            raise