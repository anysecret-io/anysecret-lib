# File: anysecret/providers/cloud_storage_base.py

"""
Base class for cloud storage-based parameter managers.
Extends file-based providers to use cloud storage (S3, GCS, Azure Blob) as backend.

Design decisions:
- Reuses existing file format providers (.env, .json, .yaml, encrypted)
- Handles concurrent writes using ETags/generation numbers for optimistic locking
- Provides caching for performance
- Falls back gracefully on conflicts
"""

import asyncio
import json
import hashlib
from typing import Any, Dict, Optional, Tuple
from abc import abstractmethod
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class CloudStorageParameterManager:
    """
    Base class for cloud storage parameter managers.
    Extends file-based providers to work with cloud storage.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.cache_ttl = config.get('cache_ttl', 300)  # 5 minutes default
        self._cache = None
        self._cache_etag = None
        self._cache_timestamp = None
        
        # Conflict resolution settings
        self.max_retry_attempts = config.get('max_retry_attempts', 3)
        self.retry_delay = config.get('retry_delay', 0.5)
        
    @abstractmethod
    async def _download_content(self) -> Tuple[str, Optional[str]]:
        """
        Download content from cloud storage.
        Returns: (content, etag/generation_number)
        """
        pass
    
    @abstractmethod
    async def _upload_content(self, content: str, etag: Optional[str] = None) -> bool:
        """
        Upload content to cloud storage with optional ETag for optimistic locking.
        Returns: True if successful, False if conflict
        """
        pass
    
    @abstractmethod
    async def _exists(self) -> bool:
        """Check if the storage object exists"""
        pass
    
    def _is_cache_valid(self) -> bool:
        """Check if cached content is still valid"""
        if self._cache is None or self._cache_timestamp is None:
            return False
        
        cache_age = (datetime.now() - self._cache_timestamp).total_seconds()
        return cache_age < self.cache_ttl
    
    async def read_content(self) -> Dict[str, Any]:
        """
        Read content from cloud storage with caching.
        """
        # Check cache first
        if self._is_cache_valid():
            logger.debug("Using cached content")
            return self._cache
        
        try:
            # Download fresh content
            content, etag = await self._download_content()
            
            # Parse content based on format (will be overridden by specific format classes)
            parsed_content = self._parse_content(content)
            
            # Update cache
            self._cache = parsed_content
            self._cache_etag = etag
            self._cache_timestamp = datetime.now()
            
            return parsed_content
            
        except FileNotFoundError:
            # Initialize with empty content if file doesn't exist
            logger.info("Cloud storage object not found, initializing empty")
            return {}
        except Exception as e:
            logger.error(f"Failed to read from cloud storage: {e}")
            raise
    
    async def write_content(self, content: Dict[str, Any]) -> bool:
        """
        Write content to cloud storage with conflict resolution.
        Uses optimistic locking with ETags to handle concurrent writes.
        """
        serialized = self._serialize_content(content)
        
        for attempt in range(self.max_retry_attempts):
            try:
                # Get current ETag if we have cache
                current_etag = self._cache_etag if self._is_cache_valid() else None
                
                # Try to upload with ETag for optimistic locking
                success = await self._upload_content(serialized, current_etag)
                
                if success:
                    # Update cache on successful write
                    self._cache = content
                    self._cache_timestamp = datetime.now()
                    # Note: ETag will be updated on next read
                    return True
                else:
                    # Conflict detected, refresh and retry
                    logger.warning(f"Write conflict detected, attempt {attempt + 1}/{self.max_retry_attempts}")
                    
                    # Refresh cache with latest content
                    await self.read_content()
                    
                    # Merge changes (simple last-write-wins for now)
                    # More sophisticated merge strategies can be implemented
                    merged_content = self._merge_content(self._cache, content)
                    serialized = self._serialize_content(merged_content)
                    
                    # Wait before retry
                    await asyncio.sleep(self.retry_delay * (attempt + 1))
                    
            except Exception as e:
                logger.error(f"Write attempt {attempt + 1} failed: {e}")
                if attempt == self.max_retry_attempts - 1:
                    raise
                await asyncio.sleep(self.retry_delay * (attempt + 1))
        
        raise Exception(f"Failed to write after {self.max_retry_attempts} attempts")
    
    def _parse_content(self, content: str) -> Dict[str, Any]:
        """Parse content based on format. Override in subclasses."""
        return json.loads(content) if content else {}
    
    def _serialize_content(self, content: Dict[str, Any]) -> str:
        """Serialize content based on format. Override in subclasses."""
        return json.dumps(content, indent=2)
    
    def _merge_content(self, current: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merge strategy for conflict resolution.
        Default: simple merge with new values taking precedence.
        Can be overridden for more sophisticated strategies.
        """
        merged = current.copy()
        merged.update(new)
        return merged
    
    async def delete_storage(self) -> bool:
        """Delete the cloud storage object"""
        # Invalidate cache
        self._cache = None
        self._cache_etag = None
        self._cache_timestamp = None
        
        # Implement in subclasses
        raise NotImplementedError