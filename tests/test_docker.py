"""Opt-in real Zeek/container tests. Run: ZEEK_TEST_IMAGE=zeek-monitor:test python3 -m unittest discover -s tests -p test_docker.py -v"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from pcap_fixture import create, LISTEN, FORMAT
from config import Config, zeek_config
from formatter import LogFormatter

IMAGE = os.environ.get("ZEEK_TEST_IMAGE")
ROOT = Path(__file__).resolve().parents[1]


def docker(*args, check=True, timeout=60):
    return subprocess.run(["docker", *args], text=True, capture_output=True, check=check, timeout=timeout)


def environment(values):
    return [item for key, value in values.items() for item in ("-e", f"{key}={value}")]


def until(check, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.2)
    raise AssertionError("condition not satisfied before timeout")


@unittest.skipUnless(IMAGE, "set ZEEK_TEST_IMAGE to run real Docker/Zeek tests")
class DockerTests(unittest.TestCase):
    def test_offline_both_directions_exact_ip_bytes_and_exclusions(self):
        with tempfile.TemporaryDirectory(prefix="zeek-pcap-") as directory:
            _, expected = create(directory)
            result = docker("run", "--rm", "--network", "none", "--cap-drop", "ALL",
                            "--read-only", "--tmpfs", "/tmp",
                            "-v", f"{directory}:/fixtures:ro",
                            *environment(LISTEN | {"LOG_FORMAT": FORMAT, "IGNORE_CHECKSUMS": "false"}),
                            IMAGE, "--read-pcap", "/fixtures/sessions.pcap")
            self.assertEqual(sorted(result.stdout.splitlines()), sorted(expected), result.stderr)
            self.assertIn("ready:", result.stderr)

    def test_local_wildcard_family_isolation_and_additive_exact_rules(self):
        ipv4_rules = {
            "LISTEN_0": "tcp 0.0.0.0 443,8000-8100",
            "LISTEN_1": "udp 0.0.0.0 1234",
            # Exact rules must neither shadow wildcard ports nor duplicate output.
            "LISTEN_2": "tcp 100.64.0.20 8000,8443",
            "LISTEN_3": "udp 100.64.0.20 1234",
            "LISTEN_4": "tcp 0.0.0.0 443",
        }
        ipv6_rules = {"LISTEN_8": "tcp [::] 443", "LISTEN_9": "udp :: 1234"}
        # A synthetic snapshot for historical PCAP, NOT real interface discovery.
        local_hosts = {"100.64.0.20", "100.64.0.21", "2001:db8::20", "2001:db8::21"}
        with tempfile.TemporaryDirectory(prefix="zeek-local-wildcard-") as directory:
            _, expected = create(directory, extra_cases=[
                # Same ports on REMOTE LAN endpoints must still log.
                ("tcp", "2001:db8::11", 443, "2001:db8::20", 443, "resp"),
                ("udp", "2001:db8::11", 1234, "2001:db8::20", 1234, "resp"),
                ("udp", "100.64.0.11", 1234, "100.64.0.20", 1234, "resp"),
                # Both endpoints local with matching ports: exclude.
                ("udp", "100.64.0.21", 1234, "100.64.0.20", 1234, None),
                ("tcp", "2001:db8::21", 443, "2001:db8::20", 443, None),
                ("tcp", "127.0.0.1", 443, "127.0.0.2", 443, None),
                ("tcp", "127.0.0.2", 443, "100.64.0.20", 443, None),
                ("tcp", "::1", 443, "2001:db8::20", 443, None),
                # Both IPs local, but only one port matches: still log.
                ("tcp", "127.0.0.2", 61270, "127.0.0.1", 443, "resp"),
            ])
            ipv4_expected = [line for line in expected if ":" not in line.split("|")[0]]
            ipv6_expected = [line for line in expected if ":" in line.split("|")[0]]
            self.assertEqual((len(ipv4_expected), len(ipv6_expected)), (10, 6))
            for rules, wanted in ((ipv4_rules, ipv4_expected),
                                  (ipv6_rules, ipv6_expected),
                                  (ipv4_rules | ipv6_rules, expected)):
                with self.subTest(rules=rules):
                    Path(directory, "config.zeek").write_text(zeek_config(Config.from_env(rules), local_hosts))
                    result = docker("run", "--rm", "--network", "none", "--cap-drop", "ALL",
                                    "--read-only", "--tmpfs", "/tmp", "-w", "/tmp",
                                    "-v", f"{directory}:/fixtures:ro", "--entrypoint", "zeek", IMAGE,
                                    "-b", "-r", "/fixtures/sessions.pcap",
                                    "/opt/zeek-monitor/zeek/monitor.zeek", "/fixtures/config.zeek")
                    records = [json.loads(line) for line in result.stdout.splitlines()]
                    self.assertEqual(records.pop(0), {"kind": "ready"})
                    formatter = LogFormatter(FORMAT, ZoneInfo("UTC"))
                    self.assertEqual(sorted(formatter.render(record) for record in records), sorted(wanted), result.stderr)

    def test_no_default_logs_and_real_zeek_syntax(self):
        with tempfile.TemporaryDirectory(prefix="zeek-no-logs-") as directory:
            create(directory)
            Path(directory, "config.zeek").write_text(zeek_config(Config.from_env(LISTEN)))
            # Deliberately retain Zeek's workdir here to assert nothing was written.
            result = docker("run", "--rm", "--network", "none", "--cap-drop", "ALL",
                            "-v", f"{directory}:/fixtures:ro", "--entrypoint", "sh", IMAGE,
                            "-ec", "mkdir /tmp/check; cd /tmp/check; zeek -b -r /fixtures/sessions.pcap /opt/zeek-monitor/zeek/monitor.zeek /fixtures/config.zeek; test -z \"$(find . -type f -print)\"")
            records = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual(records[0], {"kind": "ready"})
            self.assertEqual(len(records), 13)

    def test_invalid_configuration_and_capture_failure_exit_nonzero(self):
        for env, text in (({}, "at least one"),
                          ({"LISTEN_0": "tcp 1.2.3.4 443", "LOG_FORMAT": "$unknown"}, "unknown variable"),
                          ({"LISTEN_0": "tcp 1.2.3.4 443", "CAPTURE_INTERFACE": "no-such-device"}, "Zeek exited"),
                          ({"LISTEN_0": "tcp 1.2.3.4 443", "LOG_FILE": "/proc/no/log"}, "fatal:")):
            with self.subTest(env=env):
                result = docker("run", "--rm", *environment(env), IMAGE, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertIn(text, result.stderr)

    def test_live_shared_network_rotation_shutdown_and_restart_append(self):
        self._live_shared_network_rotation_shutdown_and_restart_append(wildcard=False)

    def test_live_wildcard_shared_network(self):
        self._live_shared_network_rotation_shutdown_and_restart_append(wildcard=True)

    def _live_shared_network_rotation_shutdown_and_restart_append(self, wildcard):
        suffix = uuid.uuid4().hex[:10]
        network, target, monitor = (f"zeek-test-{name}-{suffix}" for name in ("net", "server", "monitor"))
        service = r'''
import socket, threading, time

def serve(port, udp=False):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    if not udp:
        sock.listen()
    def loop():
        while True:
            if udp:
                data, address = sock.recvfrom(65535)
                sock.sendto(b"response!", address)
            else:
                conn, address = sock.accept()
                with conn:
                    conn.recv(65535)
                    conn.sendall(b"response!")
    threading.Thread(target=loop, daemon=True).start()
for port in (18080, 18082):
    serve(port)
serve(18081, True)
print("READY", flush=True)
while True:
    time.sleep(1)
'''
        try:
            docker("network", "create", network)
            docker("run", "-d", "--name", target, "--network", network, "--cap-drop", "ALL",
                   "--entrypoint", "python3", IMAGE, "-u", "-c", service)
            until(lambda: "READY" in docker("logs", target).stdout)
            server_ip = json.loads(docker("inspect", target).stdout)[0]["NetworkSettings"]["Networks"][network]["IPAddress"]
            with tempfile.TemporaryDirectory(prefix="zeek-live-") as directory:
                access = Path(directory, "access.log")
                rule_ip = "0.0.0.0" if wildcard else server_ip
                settings = {"LISTEN_0": f"tcp {rule_ip} 18080", "LISTEN_1": f"udp {rule_ip} 18081",
                            "LOG_FORMAT": FORMAT, "LOG_FILE": "/logs/access.log", "UDP_INACTIVITY_TIMEOUT": "2"}

                def start():
                    docker("run", "-d", "--name", monitor, "--network", f"container:{target}",
                           "--cap-drop", "ALL", "--cap-add", "NET_RAW", "--read-only", "--tmpfs", "/tmp",
                           "-v", f"{directory}:/logs", *environment(settings), IMAGE)
                    until(lambda: "ready:" in docker("logs", monitor).stderr)

                def send(udp=False, port=None, source_port=None):
                    port = port or (18081 if udp else 18080)
                    code = f'''import socket
s = socket.socket(socket.AF_INET, {"socket.SOCK_DGRAM" if udp else "socket.SOCK_STREAM"})
s.settimeout(5)
if {source_port!r} is not None:
    s.bind(("0.0.0.0", {source_port!r}))
s.connect(({server_ip!r}, {port}))
s.sendall(b"hello")
assert s.recv(100) == b"response!"
s.close()
'''
                    docker("run", "--rm", "--network", network, "--cap-drop", "ALL", "--entrypoint", "python3", IMAGE, "-c", code)

                def lines():
                    return access.read_text().splitlines() if access.exists() else []

                def stop():
                    docker("stop", "--time", "25", monitor)
                    status = json.loads(docker("inspect", monitor).stdout)[0]["State"]
                    self.assertEqual(status["ExitCode"], 0, docker("logs", monitor).stderr)

                start()
                send()
                send(udp=True)
                # These remote containers share the LAN but are NOT local IPs.
                # A same-numbered source port must not trigger both-server exclusion.
                send(source_port=18080)
                send(udp=True, source_port=18081)
                send(port=18082)  # same IP, unmonitored port: must not appear
                until(lambda: len(lines()) == 4, timeout=20)
                first = lines()
                self.assertEqual({line.split("|")[1] for line in first if line.split("|")[1] in {"18080", "18081"}}, {"18080", "18081"})
                self.assertEqual({line.split("|")[2] for line in first}, {"TCP", "UDP"})
                udp_fields = next(line.split("|") for line in first if "|UDP|" in line)
                self.assertEqual(udp_fields[3:5], ["33", "37"])
                for line in first:
                    fields = line.split("|")
                    self.assertEqual(fields[-2], server_ip)
                    self.assertNotEqual(fields[0], server_ip)
                    self.assertGreater(int(fields[3]), 5)
                    self.assertGreater(int(fields[4]), 9)
                rotated = access.with_suffix(".old")
                access.rename(rotated)
                docker("kill", "--signal", "HUP", monitor)
                until(lambda: "log file reopened" in docker("logs", monitor).stderr)
                send(udp=True)
                stop()  # stop before UDP inactivity timeout: final record must drain
                self.assertEqual(len(lines()), 1)
                self.assertEqual(rotated.read_text().splitlines(), first)
                docker("rm", monitor)
                start()
                send(udp=True)
                stop()
                self.assertEqual(len(lines()), 2)  # append, never truncate on restart
                self.assertEqual(sorted(p.name for p in Path(directory).iterdir()), ["access.log", "access.old"])
        finally:
            docker("rm", "-f", monitor, target, check=False)
            docker("network", "rm", network, check=False)


if __name__ == "__main__":
    unittest.main()
