"""Whitelist template renderer and a reopenable, append-only line sink."""
from __future__ import annotations

import math
import os
import stat
import string
import sys
from datetime import datetime
from pathlib import Path
from typing import TextIO
from zoneinfo import ZoneInfo

from config import ConfigError

VARIABLES = frozenset({
    "remote_addr", "remote_port", "time_iso8601", "protocol", "bytes_sent",
    "bytes_received", "session_time", "server_addr", "server_port",
})


class LogFormatter:
    def __init__(self, template: str, timezone: ZoneInfo):
        if not template or any(ord(c) < 32 and c != "\t" for c in template):
            raise ConfigError("LOG_FORMAT: expected a nonempty single-line format (no control characters)")
        self.template = string.Template(template)
        if not self.template.is_valid():
            raise ConfigError("LOG_FORMAT: invalid $ syntax; use $name, ${name}, or $$ for literal $")
        unknown = set(self.template.get_identifiers()) - VARIABLES
        if unknown:
            raise ConfigError("LOG_FORMAT: unknown variable(s): " + ", ".join(sorted(unknown)))
        self.timezone = timezone

    def render(self, record: dict, now: datetime | None = None) -> str:
        # Records originate in our Zeek script, not from arbitrary packet payloads.
        values = {key: record[key] for key in VARIABLES - {"time_iso8601", "session_time"}}
        for key in ("bytes_sent", "bytes_received", "remote_port", "server_port"):
            value = values[key]
            if type(value) is not int or value < 0:
                raise ValueError(f"invalid {key} in Zeek record")
        for key in ("remote_addr", "server_addr"):
            if not isinstance(values[key], str) or any(c in values[key] for c in "\r\n\x00"):
                raise ValueError(f"invalid {key} in Zeek record")
        if values["protocol"] not in {"TCP", "UDP"}:
            raise ValueError("invalid protocol in Zeek record")
        duration = record["session_time"]
        if type(duration) not in {int, float} or not math.isfinite(duration) or duration < 0:
            raise ValueError("invalid session_time in Zeek record")
        values["session_time"] = f"{duration:.3f}"
        values["time_iso8601"] = (now or datetime.now(self.timezone)).astimezone(self.timezone).isoformat(timespec="seconds")
        return self.template.substitute(values)


class LogSink:
    def __init__(self, path: str):
        self.path = path
        self.is_stdout = path in {"-", "/dev/stdout"}
        self.stream: TextIO = sys.stdout if self.is_stdout else self._open()

    def _open(self) -> TextIO:
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        # O_NONBLOCK prevents a misconfigured FIFO from hanging startup/reopen.
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NONBLOCK, 0o640)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError("LOG_FILE must be a regular file, /dev/stdout, or -")
            return os.fdopen(fd, "a", encoding="utf-8", buffering=1)
        except BaseException:
            os.close(fd)
            raise

    def write(self, line: str) -> None:
        self.stream.write(line + "\n")
        self.stream.flush()

    def reopen(self) -> None:
        if not self.is_stdout:
            replacement = self._open()
            previous, self.stream = self.stream, replacement
            previous.close()

    def close(self) -> None:
        self.stream.flush()
        if not self.is_stdout:
            self.stream.close()
