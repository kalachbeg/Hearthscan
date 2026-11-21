"""Make connect() report a refused port immediately on Windows.

When a SYN is answered with a reset, Windows quietly retries the connection
twice and only gives up after about two seconds. With short timeouts that turns
every closed port into an apparent timeout. Turning off SYN retransmissions for
the socket (SIO_TCP_INITIAL_RTO, available since Windows 8) makes the reset come
back at once, and a SYN that gets no answer fails after the RTT we pass in.
"""

from __future__ import annotations

import socket
import sys

available = False

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _SIO_TCP_INITIAL_RTO = 0x98000011
    _NO_SYN_RETRANSMISSIONS = 0xFE

    class _InitialRto(ctypes.Structure):
        _fields_ = (
            ("rtt", ctypes.c_ushort),
            ("max_syn_retransmissions", ctypes.c_ubyte),
        )

    try:
        _WSAIoctl = ctypes.WinDLL("ws2_32", use_last_error=True).WSAIoctl
    except (OSError, AttributeError):
        pass
    else:
        _WSAIoctl.argtypes = (
            ctypes.c_size_t,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
            ctypes.c_void_p,
        )
        _WSAIoctl.restype = ctypes.c_int
        available = True


def fail_fast(sock: socket.socket, timeout: float) -> bool:
    """Apply the setting to an unconnected socket. Returns False if it didn't take."""
    if not available:
        return False
    # 0 and 0xFFFF have special meanings ("default" and "unspecified").
    rtt = min(max(int(timeout * 1000), 1), 0xFFFE)
    params = _InitialRto(rtt, _NO_SYN_RETRANSMISSIONS)
    returned = wintypes.DWORD()
    result = _WSAIoctl(
        sock.fileno(),
        _SIO_TCP_INITIAL_RTO,
        ctypes.byref(params),
        ctypes.sizeof(params),
        None,
        0,
        ctypes.byref(returned),
        None,
        None,
    )
    return result == 0
