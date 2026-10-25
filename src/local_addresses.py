"""Read assigned interface addresses in this process's network namespace.

Uses libc getifaddrs through the standard library; no hostname/DNS lookup,
private-subnet heuristic, iproute2 dependency, or additional capability.
"""
from __future__ import annotations

import ctypes
import ipaddress
import os
import socket
import sys


class _IfAddrs(ctypes.Structure):
    pass


_IfAddrs._fields_ = [
    ("next", ctypes.POINTER(_IfAddrs)),
    ("name", ctypes.c_char_p),
    ("flags", ctypes.c_uint),
    ("addr", ctypes.c_void_p),
    ("netmask", ctypes.c_void_p),
    ("ifu", ctypes.c_void_p),
    ("data", ctypes.c_void_p),
]


def get_local_addresses() -> frozenset[str]:
    if sys.platform not in {"linux", "darwin"}:
        raise OSError("local IP discovery requires Linux or macOS")
    libc = ctypes.CDLL(None, use_errno=True)
    getifaddrs = libc.getifaddrs
    getifaddrs.argtypes = [ctypes.POINTER(ctypes.POINTER(_IfAddrs))]
    getifaddrs.restype = ctypes.c_int
    freeifaddrs = libc.freeifaddrs
    freeifaddrs.argtypes = [ctypes.POINTER(_IfAddrs)]
    freeifaddrs.restype = None
    head = ctypes.POINTER(_IfAddrs)()
    if getifaddrs(ctypes.byref(head)) != 0:
        error = ctypes.get_errno()
        raise OSError(error, f"getifaddrs: {os.strerror(error)}")
    addresses = set()
    try:
        cursor = head
        while cursor:
            entry = cursor.contents
            if entry.addr:
                # BSD sockaddr starts with length/family bytes; Linux uses sa_family_t.
                header = ctypes.string_at(entry.addr, 2)
                family = header[1] if sys.platform == "darwin" else int.from_bytes(header, sys.byteorder)
                if family == socket.AF_INET:
                    packed = ctypes.string_at(entry.addr + 4, 4)
                elif family == socket.AF_INET6:
                    packed = ctypes.string_at(entry.addr + 8, 16)
                else:
                    cursor = entry.next
                    continue
                address = ipaddress.ip_address(packed)
                if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                    address = address.ipv4_mapped
                if not address.is_unspecified:
                    addresses.add(str(address))
            cursor = entry.next
    finally:
        freeifaddrs(head)
    if not addresses:
        raise OSError("getifaddrs returned no local IP addresses; refusing wildcard capture")
    return frozenset(addresses)
