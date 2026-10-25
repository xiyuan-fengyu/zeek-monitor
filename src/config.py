"""Strict environment parsing and data-only Zeek configuration generation."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DEFAULT_FORMAT = (
    "$remote_addr:$remote_port - [$time_iso8601] $protocol "
    "in_bytes=$bytes_received out_bytes=$bytes_sent "
    "session_time=$session_time server=$server_addr:$server_port"
)


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    protocol: str
    address: str
    ranges: tuple[tuple[int, int], ...]


def parse_rules(env: Mapping[str, str]) -> tuple[Rule, ...]:
    grouped: dict[tuple[str, str], list[tuple[int, int]]] = {}
    keys = []
    for key in env:
        if key.startswith("LISTEN_"):
            if not re.fullmatch(r"LISTEN_[0-9]+", key):
                raise ConfigError(f"invalid rule name: {key}; expected LISTEN_<number>")
            keys.append(key)
    for key in sorted(keys, key=lambda k: (int(k[7:]), k)):
        parts = env[key].strip().split(maxsplit=2)
        if len(parts) != 3:
            raise ConfigError(f"{key}: expected 'tcp|udp IP port[,port-range]'")
        protocol, address, port_spec = parts
        protocol = protocol.lower()
        if protocol not in {"tcp", "udp"}:
            raise ConfigError(f"{key}: only tcp and udp are supported")
        try:
            if "%" in address:
                raise ValueError("scoped IPv6 addresses are not supported")
            parsed = ipaddress.ip_address(address)
            # Zeek represents IPv4-mapped IPv6 addresses as IPv4.
            if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
                parsed = parsed.ipv4_mapped
            address = str(parsed)
        except ValueError as exc:
            raise ConfigError(f"{key}: invalid exact IP address: {address}") from exc
        ranges = grouped.setdefault((protocol, address), [])
        for item in port_spec.split(","):
            match = re.fullmatch(r"\s*([0-9]+)\s*(?:-\s*([0-9]+)\s*)?", item)
            if not match:
                raise ConfigError(f"{key}: invalid port/range: {item!r}")
            start = int(match[1])
            end = int(match[2]) if match[2] else start
            if not 1 <= start <= end <= 65535:
                raise ConfigError(f"{key}: ports must satisfy 1 <= start <= end <= 65535")
            ranges.append((start, end))
    if not grouped:
        raise ConfigError("at least one LISTEN_<number> rule is required")
    result = []
    for (protocol, address), ranges in sorted(grouped.items()):
        merged: list[tuple[int, int]] = []
        for start, end in sorted(ranges):
            if merged and start <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
            else:
                merged.append((start, end))
        result.append(Rule(protocol, address, tuple(merged)))
    return tuple(result)


def boolean(env: Mapping[str, str], key: str, default: bool) -> bool:
    value = env.get(key, str(default)).lower()
    if value not in {"true", "false", "1", "0"}:
        raise ConfigError(f"{key}: expected true/false or 1/0")
    return value in {"true", "1"}


def seconds(env: Mapping[str, str], key: str, default: int) -> int:
    value = env.get(key, str(default))
    if not re.fullmatch(r"[0-9]+", value) or not 1 <= int(value) <= 86400:
        raise ConfigError(f"{key}: expected integer seconds in 1..86400")
    return int(value)


@dataclass(frozen=True)
class Config:
    rules: tuple[Rule, ...]
    log_format: str
    log_file: str
    interface: str
    timezone: ZoneInfo
    ignore_checksums: bool
    udp_timeout: int
    shutdown_timeout: int

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> Config:
        rules = parse_rules(env)
        interface = env.get("CAPTURE_INTERFACE", "eth0")
        if not re.fullmatch(r"[A-Za-z0-9_.:@-]+", interface) or interface.startswith("-"):
            raise ConfigError("CAPTURE_INTERFACE: expected one interface name")
        log_file = env.get("LOG_FILE", "/dev/stdout")
        if not log_file or any(c in log_file for c in "\x00\r\n"):
            raise ConfigError("LOG_FILE: expected a nonempty path without NUL/newlines")
        if log_file not in {"-", "/dev/stdout"}:
            log_file = str(Path(log_file).absolute())
        tz_name = env.get("TZ", "UTC")
        try:
            timezone = ZoneInfo(tz_name)
        except (ValueError, ZoneInfoNotFoundError) as exc:
            raise ConfigError(f"TZ: unknown IANA timezone: {tz_name!r}") from exc
        return cls(
            rules, env.get("LOG_FORMAT", DEFAULT_FORMAT), log_file, interface, timezone,
            boolean(env, "IGNORE_CHECKSUMS", True),
            seconds(env, "UDP_INACTIVITY_TIMEOUT", 60),
            seconds(env, "SHUTDOWN_TIMEOUT", 15),
        )


def zeek_config(config: Config) -> str:
    """No untrusted strings: addresses/protocols/counts are parsed before interpolation."""
    lines = ["# Generated; do not edit.", "redef Monitor::rules = table("]
    for rule in config.rules:
        address = f"[{rule.address}]" if ":" in rule.address else rule.address
        ranges = ", ".join(f"[$first={start}, $last={end}]" for start, end in rule.ranges)
        lines.append(f"    [{address}, {rule.protocol}] = vector({ranges}),")
    lines += [
        ");",
        f"redef udp_inactivity_timeout = {config.udp_timeout} secs;",
    ]
    return "\n".join(lines) + "\n"
