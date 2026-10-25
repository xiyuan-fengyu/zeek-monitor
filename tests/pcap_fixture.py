"""Synthetic Ethernet/IP PCAP with real IP/TCP/UDP checksums; no packages required.

Expected counters are independently calculated from emitted IP packet lengths.
This is reproducible test traffic, NOT a production capture.
"""
from __future__ import annotations
import ipaddress
import json
from pathlib import Path
import struct
import sys

LISTEN = {
    "LISTEN_0": "tcp 100.64.0.20 443,8000-8100",
    "LISTEN_3": "udp 100.64.0.20 1234",
    "LISTEN_8": "tcp 100.64.0.21 443",
    "LISTEN_9": "tcp 2001:db8::20 443",
    "LISTEN_10": "udp 2001:db8::20 1234",
    "LISTEN_11": "tcp 100.64.0.20 443,8001-8002",  # duplicate/overlap
}
FORMAT = "$remote_addr|$remote_port|$protocol|$bytes_received|$bytes_sent|$session_time|$server_addr|$server_port"


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    value = sum(struct.unpack(f"!{len(data)//2}H", data))
    while value >> 16:
        value = (value & 0xffff) + (value >> 16)
    return (~value) & 0xffff


def packet(src, dst, sport, dport, proto, payload=b"", seq=0, ack=0, flags=0):
    src, dst = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    if proto == "tcp":
        protocol = 6
        transport = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
        check_offset = 16
    else:
        protocol = 17
        transport = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
        check_offset = 6
    if src.version == 4:
        pseudo = src.packed + dst.packed + struct.pack("!BBH", 0, protocol, len(transport))
        ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport), 0, 0, 64, protocol, 0, src.packed, dst.packed)
        ip_header = ip_header[:10] + struct.pack("!H", checksum(ip_header)) + ip_header[12:]
        ethertype = 0x0800
    else:
        pseudo = src.packed + dst.packed + struct.pack("!I3xB", len(transport), protocol)
        ip_header = struct.pack("!IHBB16s16s", 6 << 28, len(transport), protocol, 64, src.packed, dst.packed)
        ethertype = 0x86dd
    check = checksum(pseudo + transport) or 0xffff
    transport = transport[:check_offset] + struct.pack("!H", check) + transport[check_offset + 2:]
    frame = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01" + struct.pack("!H", ethertype) + ip_header + transport
    return frame, len(ip_header) + len(transport)


def create(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    # expected_server: orig, resp, or None (intentionally excluded).
    cases = [
        ("tcp", "100.64.0.11", 51001, "100.64.0.20", 443, "resp"),
        ("tcp", "100.64.0.20", 443, "100.64.0.11", 51002, "orig"),
        ("udp", "100.64.0.11", 51003, "100.64.0.20", 1234, "resp"),
        ("udp", "100.64.0.20", 1234, "100.64.0.11", 51004, "orig"),
        ("tcp", "100.64.0.21", 443, "100.64.0.20", 443, None),
        ("tcp", "100.64.0.11", 51005, "100.64.0.99", 443, None),
        ("tcp", "100.64.0.21", 51006, "100.64.0.20", 443, "resp"),
        ("tcp", "100.64.0.99", 443, "100.64.0.20", 443, "resp"),
        ("tcp", "100.64.0.11", 51007, "100.64.0.20", 8000, "resp"),
        ("tcp", "100.64.0.11", 51008, "100.64.0.20", 8100, "resp"),
        ("tcp", "100.64.0.11", 51009, "100.64.0.20", 7999, None),
        ("tcp", "100.64.0.11", 51010, "100.64.0.20", 8101, None),
        ("udp", "100.64.0.11", 51011, "100.64.0.20", 443, None),
        ("tcp", "2001:db8::11", 51012, "2001:db8::20", 443, "resp"),
        ("tcp", "2001:db8::20", 443, "2001:db8::11", 51013, "orig"),
        ("udp", "2001:db8::11", 51014, "2001:db8::20", 1234, "resp"),
        ("udp", "2001:db8::20", 1234, "2001:db8::11", 51015, "orig"),
        ("tcp", "100.64.0.20", 51016, "100.64.0.99", 443, None),
    ]
    expected = []
    frames = []
    for index, (proto, orig, op, resp, rp, server) in enumerate(cases):
        counters = [0, 0]
        if proto == "tcp":
            segments = [(0, b"", 1000, 0, 2), (1, b"", 2000, 1001, 18),
                        (0, b"", 1001, 2001, 16), (0, b"hello", 1001, 2001, 24),
                        (1, b"response!", 2001, 1006, 24), (0, b"", 1006, 2010, 17),
                        (1, b"", 2010, 1007, 17), (0, b"", 1007, 2011, 16)]
            duration = "0.600"
        else:
            segments = [(0, b"hello", 0, 0, 0), (1, b"response!", 0, 0, 0)]
            duration = "0.100"
        for n, (direction, payload, seq, ack, flags) in enumerate(segments):
            endpoints = (orig, resp, op, rp) if direction == 0 else (resp, orig, rp, op)
            frame, ip_len = packet(*endpoints, proto, payload, seq, ack, flags)
            counters[direction] += ip_len
            frames.append((1700000000 + index * 2, n * 100000, frame))
        if server:
            if server == "resp":
                remote, remote_port, server_ip, server_port = orig, op, resp, rp
                received, sent = counters
            else:
                remote, remote_port, server_ip, server_port = resp, rp, orig, op
                sent, received = counters
            expected.append(f"{remote}|{remote_port}|{proto.upper()}|{received}|{sent}|{duration}|{server_ip}|{server_port}")
    path = directory / "sessions.pcap"
    with path.open("wb") as f:
        f.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for sec, usec, frame in frames:
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)
    (directory / "expected.log").write_text("\n".join(sorted(expected)) + "\n")
    (directory / "manifest.json").write_text(json.dumps({"flows": len(cases), "expected_records": len(expected), "synthetic": True}, indent=2) + "\n")
    return path, expected


if __name__ == "__main__":
    create(sys.argv[1] if len(sys.argv) > 1 else ".artifacts/pcap")
