# (C) Copyright 2005 Nuxeo SARL <http://nuxeo.com>
# Author: Florent Guillaume <fg@nuxeo.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#
# $Id$
"""
TimeoutCache

A simple thread-safe cache implementation that stores data globally.
Each cache is individually locked when accessed.
"""

from time import time
from threading import Lock

_CACHES = {}
_caches_lock = Lock()

class TimeoutCache(object):
    """TimeoutCache

    A simple thread-safe cache with timeout.

    Old entries that are never accessed are never purged.
    """

    def __init__(self, timeout=60):
        self._timeout = timeout
        self._lock = Lock()
        self._clear()

    def _clear(self):
        # Values stored in the cache are a tuple (value, orig_time)
        # where orig_time is the time the value was inserted.
        self._cache = {}

    def clear(self):
        """Clear the cache."""
        self._lock.acquire()
        try:
            self._clear()
        finally:
            self._lock.release()

    def setTimeout(self, timeout):
        """Set the timeout for new entries."""
        self._timeout = timeout

    def _getTimeout(self):
        return int(time()) + self._timeout

    def __getitem__(self, key):
        """Get an object from the cache.

        Returns None if not present or timeout expired.
        """
        self._lock.acquire()
        try:
            if not self._cache.has_key(key):
                return None
            value, orig_time = self._cache.get(key)
            now = int(time())
            if now < orig_time + self._timeout:
                return value
            else:
                # expire
                del self._cache[key]
                return None
        finally:
            self._lock.release()

    def __setitem__(self, key, value):
        """Set an object in the cache.

        Keep existing timeout if there already was an object.
        """
        self._lock.acquire()
        try:
            if not self._cache.has_key(key):
                orig_time = int(time())
            else:
                oldvalue, orig_time = self._cache.get(key)
            self._cache[key] = (value, orig_time)
        finally:
            self._lock.release()

    def __delitem__(self, key):
        """Delete an object from the cache."""
        self._lock.acquire()
        try:
            if self._cache.has_key(key):
                del self._cache[key]
        finally:
            self._lock.release()

    def delValues(self, val):
        """Delete all given values from the cache."""
        self._lock.acquire()
        try:
            todel = []
            for key, (value, orig_time) in self._cache.items():
                if value == val:
                    todel.append(key)
            for key in todel:
                del self._cache[key]
        finally:
            self._lock.release()

    def keysWithValidity(self):
        """Get the cache keys and their validity.

        Returns a list of (key, valid) where valid is True if the key is
        still valid (has not timed out).

        Does not expire old keys.
        """
        self._lock.acquire()
        try:
            now = int(time())
            timeout = self._timeout
            keyvalid = []
            for key, (value, orig_time) in self._cache.items():
                valid = now < orig_time + timeout
                keyvalid.append((key, valid))
            return keyvalid
        finally:
            self._lock.release()


def getCache(cache_key, constructor=None):
    """Get a global cache.

    If a constructor is provided, it will be called instead of
    TimeoutCache if a new cache instance is needed.
    """

    _caches_lock.acquire()
    try:
        cache = _CACHES.get(cache_key)
        if cache is None:
            if constructor is not None:
                cache = constructor()
            else:
                cache = TimeoutCache()
            _CACHES[cache_key] = cache
        return cache
    finally:
        _caches_lock.release()


def resetAllCaches():
    """Reset all caches, for unit tests."""
    global _CACHES
    _CACHES = {}
