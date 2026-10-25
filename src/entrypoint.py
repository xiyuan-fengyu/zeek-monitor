#!/usr/bin/env python3
"""PID 1 supervisor: validate, run Zeek, drain JSON, render, reap."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import time

from config import Config, ConfigError, zeek_config
from formatter import LogFormatter, LogSink

ROOT = Path(__file__).resolve().parent.parent
MAX_RECORD_BYTES = 65536


def diagnostic(message: str) -> None:
    print(f"[zeek-monitor] {message}", file=sys.stderr, flush=True)


def supervise(config: Config, formatter: LogFormatter, pcap: str | None) -> int:
    pending_signal = 0
    reopen = False
    child: subprocess.Popen | None = None
    sink: LogSink | None = None
    old_handlers = {}

    def stop(signum, _frame):
        nonlocal pending_signal
        pending_signal = pending_signal or signum

    def rotate(_signum, _frame):
        nonlocal reopen
        reopen = True

    for sig, handler in ((signal.SIGTERM, stop), (signal.SIGINT, stop), (signal.SIGHUP, rotate)):
        old_handlers[sig] = signal.signal(sig, handler)
    try:
        sink = LogSink(config.log_file)
        with tempfile.TemporaryDirectory(prefix="zeek-monitor-") as work:
            generated = Path(work) / "config.zeek"
            generated.write_text(zeek_config(config), encoding="utf-8")
            command = ["zeek", "-b"]
            if config.ignore_checksums:
                command.append("-C")
            command += ["-r", pcap] if pcap else ["-i", config.interface]
            command += [str(ROOT / "zeek" / "monitor.zeek"), str(generated)]
            diagnostic(f"starting Zeek; source={pcap or config.interface}; rule_groups={len(config.rules)}; output={config.log_file}")
            # No shell, no inherited script injection, and no unbounded producer queue.
            child_env = dict(os.environ)
            for name in ("ZEEKPATH", "ZEEK_PREFIXES", "ZEEK_SCRIPT_PREFIXES"):
                child_env.pop(name, None)
            child = subprocess.Popen(command, cwd=work, stdout=subprocess.PIPE,
                                     stderr=None, env=child_env, start_new_session=True)
            assert child.stdout is not None
            os.set_blocking(child.stdout.fileno(), False)
            buffered = bytearray()
            deadline = None
            eof = False
            ready = False
            forced = False
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                while not eof or child.poll() is None:
                    if pending_signal and deadline is None:
                        deadline = time.monotonic() + config.shutdown_timeout
                        diagnostic("stopping Zeek; draining final session records")
                        if child.poll() is None:
                            child.send_signal(pending_signal)
                    if deadline is not None and not forced and time.monotonic() >= deadline and child.poll() is None:
                        diagnostic("shutdown deadline exceeded; killing Zeek (records may be lost)")
                        child.kill()
                        forced = True
                    if reopen:
                        reopen = False
                        sink.reopen()
                        diagnostic("log file reopened")
                    for key, _ in selector.select(timeout=0.2):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(child.stdout)
                            eof = True
                            if buffered:
                                raise ValueError("truncated internal JSON record from Zeek")
                            continue
                        buffered.extend(chunk)
                        while b"\n" in buffered:
                            raw, _, remainder = buffered.partition(b"\n")
                            buffered = bytearray(remainder)
                            if len(raw) > MAX_RECORD_BYTES:
                                raise ValueError("oversized internal JSON record")
                            record = json.loads(raw)
                            if not isinstance(record, dict):
                                raise ValueError("internal Zeek record must be a JSON object")
                            if record.get("kind") == "ready":
                                if ready:
                                    raise ValueError("duplicate Zeek ready record")
                                ready = True
                                diagnostic("ready: Zeek scripts initialized")
                            elif record.get("kind") == "session" and ready:
                                sink.write(formatter.render(record))
                            else:
                                raise ValueError("unexpected internal record from Zeek")
                        if len(buffered) > MAX_RECORD_BYTES:
                            raise ValueError("oversized internal JSON record")
            code = child.wait()
            if forced:
                return 1
            if not ready and code == 0 and not pending_signal:
                raise ValueError("Zeek exited without initializing the monitor")
            if code:
                diagnostic(f"Zeek exited with status {code}")
            return code if code >= 0 else 128 - code
    finally:
        if child is not None:
            if child.poll() is None:
                child.terminate()
                try:
                    child.communicate(timeout=config.shutdown_timeout)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.communicate()
            if child.stdout:
                child.stdout.close()
        try:
            if sink:
                sink.close()
        finally:
            for sig, handler in old_handlers.items():
                signal.signal(sig, handler)


def main() -> int:
    parser = argparse.ArgumentParser(description="Passive Zeek server-perspective session logger")
    parser.add_argument("--read-pcap", metavar="PATH", help="offline replay instead of live capture")
    parser.add_argument("--check-config", action="store_true", help="validate environment and print generated Zeek configuration; no capture")
    args = parser.parse_args()
    os.umask(0o027)
    try:
        config = Config.from_env(os.environ)
        formatter = LogFormatter(config.log_format, config.timezone)
        if args.check_config:
            print(zeek_config(config), end="")
            return 0
        pcap = str(Path(args.read_pcap).resolve(strict=True)) if args.read_pcap else None
        return supervise(config, formatter, pcap)
    except (ConfigError, OSError, ValueError, KeyError, TypeError) as exc:
        diagnostic(f"fatal: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
