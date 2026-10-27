"""
Core Memory Protection and Ephemeral Security Subsystem
Provides POSIX memory locking (mlock) and guaranteed memory zeroization.
"""

import atexit
import ctypes
import os
import signal
import sys
from typing import Optional, Union

# POSIX mlock constants
MCL_CURRENT = 1
MCL_FUTURE = 2

_registered_buffers = []

def lock_process_memory() -> bool:
    """
    Lock process memory pages to prevent swapping to disk.
    Requires appropriate permissions or RLIMIT_MEMLOCK.
    """
    try:
        libc = ctypes.CDLL("libc.so.6")
        res = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
        return res == 0
    except Exception:
        return False

def zero_memory(target: Union[bytearray, memoryview, ctypes.Array]):
    """
    Explicitly overwrite a mutable memory buffer with zeros.
    """
    if isinstance(target, bytearray):
        for i in range(len(target)):
            target[i] = 0
    elif isinstance(target, memoryview):
        if not target.readonly:
            target[:] = b"\x00" * len(target)
    elif isinstance(target, ctypes.Array):
        ctypes.memset(ctypes.byref(target), 0, ctypes.sizeof(target))

class SecureBuffer:
    """
    Ephemeral memory buffer that locks its contents and ensures zeroization on release.
    """
    def __init__(self, data: bytes):
        self._length = len(data)
        self._buffer = (ctypes.c_char * self._length).from_buffer_copy(data)
        self._wiped = False
        
        # Register for automated shutdown cleanup
        _registered_buffers.append(self)
        
    def read(self) -> bytes:
        if self._wiped:
            raise ValueError("Accessing wiped SecureBuffer")
        return bytes(self._buffer)

    def wipe(self):
        if not self._wiped:
            ctypes.memset(ctypes.byref(self._buffer), 0, self._length)
            self._wiped = True

    def __del__(self):
        self.wipe()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.wipe()

def cleanup_all_buffers():
    """Wipes all active secure buffers in running memory."""
    for buf in _registered_buffers:
        try:
            buf.wipe()
        except Exception:
            pass
    _registered_buffers.clear()

def _signal_handler(signum, frame):
    cleanup_all_buffers()
    sys.exit(128 + signum)

# Register cleanups for graceful and abrupt termination
atexit.register(cleanup_all_buffers)
try:
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
except (ValueError, AttributeError):
    pass
