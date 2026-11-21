"""Socket settings only Windows needs.

Making connect() report a refused port at once: when a SYN is answered with a
reset, Windows quietly retries the connection twice and only gives up after
about two seconds. With short timeouts that turns every closed port into an
apparent timeout. Turning off SYN retransmissions for the socket
(SIO_TCP_INITIAL_RTO, available since Windows 8) makes the reset come back at
once, and a SYN that gets no answer fails after the RTT we pass in.

Keeping UDP sockets usable: an ICMP "port unreachable" for anything we sent
makes the next receive on the socket fail with WSAECONNRESET, and a discovery
sweep gets plenty of those. SIO_UDP_CONNRESET turns that off.
"""

from __future__ import annotations

import socket
import sys

available = False

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _SIO_TCP_INITIAL_RTO = 0x98000011
    _SIO_UDP_CONNRESET = 0x9800000C
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


def _ioctl(sock: socket.socket, code: int, value: ctypes.Structure | ctypes.c_int) -> bool:
    returned = wintypes.DWORD()
    result = _WSAIoctl(
        sock.fileno(),
        code,
        ctypes.byref(value),
        ctypes.sizeof(value),
        None,
        0,
        ctypes.byref(returned),
        None,
        None,
    )
    return result == 0


def fail_fast(sock: socket.socket, timeout: float) -> bool:
    """Apply the setting to an unconnected socket. Returns False if it didn't take."""
    if not available:
        return False
    # 0 and 0xFFFF have special meanings ("default" and "unspecified").
    rtt = min(max(int(timeout * 1000), 1), 0xFFFE)
    return _ioctl(sock, _SIO_TCP_INITIAL_RTO, _InitialRto(rtt, _NO_SYN_RETRANSMISSIONS))


def ignore_udp_resets(sock: socket.socket) -> bool:
    """Stop ICMP port unreachable from breaking receives on a UDP socket."""
    if not available:
        return False
    return _ioctl(sock, _SIO_UDP_CONNRESET, ctypes.c_int(0))
