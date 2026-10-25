"""Process lifecycle tests with a fake executable; NOT Zeek acceptance tests."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RECORD = dict(kind="session", remote_addr="100.64.0.11", remote_port=51000,
              server_addr="100.64.0.20", server_port=443, protocol="TCP",
              bytes_sent=129, bytes_received=205, session_time=0.6)


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        executable = self.path / "zeek"
        executable.write_text(f'''#!{sys.executable}
import json, os, signal, sys, time
record = {RECORD!r}
mode = os.environ.get("FAKE_MODE", "normal")
def finish(sig, frame):
    print(json.dumps(record), flush=True)
    sys.exit(0)
signal.signal(signal.SIGTERM, finish)
signal.signal(signal.SIGINT, finish)
if mode == "hang":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
print('{{"kind":"ready"}}', flush=True)
if mode == "bad":
    print("not json", flush=True)
elif mode == "nonobject":
    print("[]", flush=True)
elif mode == "partial":
    print('{{"kind":', end="", flush=True)
    sys.exit(0)
elif mode == "fail":
    sys.exit(7)
elif mode == "normal":
    print(json.dumps(record), flush=True)
    sys.exit(0)
while True:
    time.sleep(0.1)
''')
        executable.chmod(0o755)
        self.env = dict(os.environ) | {"PATH": str(self.path) + os.pathsep + os.environ["PATH"],
            "LISTEN_0": "tcp 100.64.0.20 443", "LOG_FORMAT": "$bytes_received/$bytes_sent", "LOG_FILE": "-", "TZ": "UTC", "SHUTDOWN_TIMEOUT": "1"}
        self.command = [sys.executable, str(ROOT / "src/entrypoint.py")]

    def run_mode(self, mode):
        return subprocess.run(self.command, env=self.env | {"FAKE_MODE": mode}, text=True, capture_output=True, timeout=6)

    def test_normal_record(self):
        result = self.run_mode("normal")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "205/129\n")

    def test_child_failure_propagated(self):
        result = self.run_mode("fail")
        self.assertEqual(result.returncode, 7, result.stderr)

    def test_malformed_records_fail_closed(self):
        for mode in ("bad", "partial", "nonobject"):
            with self.subTest(mode=mode):
                result = self.run_mode(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertIn("fatal:", result.stderr)

    def spawn(self, mode):
        child = subprocess.Popen(self.command, env=self.env | {"FAKE_MODE": mode},
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def cleanup():
            if child.poll() is None:
                child.kill()
            child.communicate()
        self.addCleanup(cleanup)
        # Startup emits at most a few lines; test subprocess timeout protects normal runs.
        while True:
            line = child.stderr.readline()
            if "ready:" in line:
                break
            if not line:
                self.fail("supervisor exited before ready")
        return child

    def test_sigterm_drains_final_record(self):
        child = self.spawn("wait")
        child.send_signal(signal.SIGTERM)
        out, err = child.communicate(timeout=6)
        self.assertEqual(child.returncode, 0, err)
        self.assertEqual(out, "205/129\n")

    def test_hung_child_deadline_is_nonzero(self):
        child = self.spawn("hang")
        child.send_signal(signal.SIGTERM)
        out, err = child.communicate(timeout=6)
        self.assertEqual(child.returncode, 1, err)
        self.assertIn("deadline exceeded", err)


if __name__ == "__main__":
    unittest.main()
