"""
Short-lived shared snapshots for the live dashboard endpoints.

The dashboard asks for the live timeline, analysis and correlation at the
same moment, and each of those used to run every collector again (the
process collector alone takes seconds on Windows). Requests now share one
collection per source for a few seconds. Concurrent callers wait for the
collection already in flight instead of starting their own.

This cache is only used by the read-only live views. Script execution and
evidence sealing always collect fresh data.
"""

import os
import threading
import time
from typing import Any, Callable, Dict, Tuple

DEFAULT_TTL_SECONDS = float(os.getenv("JOCKY_LIVE_CACHE_SECONDS", "15"))

_entries: Dict[str, Tuple[float, Any]] = {}
_locks: Dict[str, threading.Lock] = {}
_registry_lock = threading.Lock()


def _lock_for(key: str) -> threading.Lock:
    with _registry_lock:
        return _locks.setdefault(key, threading.Lock())


def cached(key: str, collect: Callable[[], Any], ttl: float = DEFAULT_TTL_SECONDS) -> Any:
    """Return a snapshot younger than ttl seconds, collecting it if needed."""
    if ttl <= 0:
        return collect()
    now = time.monotonic()
    entry = _entries.get(key)
    if entry and now - entry[0] < ttl:
        return entry[1]
    with _lock_for(key):
        entry = _entries.get(key)  # another request may have filled it meanwhile
        if entry and time.monotonic() - entry[0] < ttl:
            return entry[1]
        value = collect()
        _entries[key] = (time.monotonic(), value)
        return value


def clear() -> None:
    _entries.clear()
