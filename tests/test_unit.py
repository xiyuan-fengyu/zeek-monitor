import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import patch
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from config import Config, ConfigError, parse_rules, zeek_config
from formatter import LogFormatter, LogSink


class ConfigurationTests(unittest.TestCase):
    def test_sort_gaps_merge_and_protocol_isolation(self):
        rules = parse_rules({"LISTEN_10": "TCP 100.64.0.20 443,8000-8100",
                             "LISTEN_2": "tcp 100.64.0.20 8100-8102, 442 - 444",
                             "LISTEN_99": "udp 100.64.0.20 443"})
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0].ranges, ((442, 444), (8000, 8102)))
        self.assertEqual(rules[1].protocol, "udp")

    def test_ipv6_normalization(self):
        self.assertEqual(parse_rules({"LISTEN_0": "tcp 2001:0DB8::1 1-65535"})[0].address, "2001:db8::1")
        self.assertEqual(parse_rules({"LISTEN_0": "tcp ::ffff:100.64.0.20 443"})[0].address, "100.64.0.20")

    def test_wildcard_normalization_merge_and_generation(self):
        config = Config.from_env({
            "LISTEN_0": "tcp 0.0.0.0 443,8000-8100",
            "LISTEN_2": "tcp 0.0.0.0 8100-8101",
            "LISTEN_3": "udp 0:0:0:0:0:0:0:0 1234",
            "LISTEN_4": "udp [::] 1234,1235",
            "LISTEN_5": "tcp 100.64.0.20 8443",
        })
        rules = {(r.protocol, r.address): r.ranges for r in config.rules}
        self.assertEqual(rules, {
            ("tcp", "0.0.0.0"): ((443, 443), (8000, 8101)),
            ("udp", "::"): ((1234, 1235),),
            ("tcp", "100.64.0.20"): ((8443, 8443),),
        })
        generated = zeek_config(config, {"100.64.0.20", "2001:db8::20"})
        self.assertIn("Monitor::local_hosts = {100.64.0.20, [2001:db8::20]}", generated)
        self.assertIn("[0.0.0.0, tcp]", generated)
        self.assertIn("[[::], udp]", generated)
        self.assertIn("[100.64.0.20, tcp]", generated)

    def test_local_discovery_only_for_wildcard_and_fails_closed(self):
        with patch("config.get_local_addresses", side_effect=OSError("discovery failed")) as discover:
            zeek_config(Config.from_env({"LISTEN_0": "tcp 100.64.0.20 443"}))
            discover.assert_not_called()
            with self.assertRaisesRegex(OSError, "discovery failed"):
                zeek_config(Config.from_env({"LISTEN_0": "tcp 0.0.0.0 443"}))
        with patch("config.get_local_addresses", return_value={"100.64.0.20", "2001:db8::20"}) as discover:
            generated = zeek_config(Config.from_env({"LISTEN_0": "tcp [::] 443"}))
            self.assertIn("Monitor::local_hosts = {100.64.0.20, [2001:db8::20]}", generated)
            discover.assert_called_once_with()

    def test_invalid_rules(self):
        for spec in ("", "tcp", "tcp 1.2.3.4", "sctp 1.2.3.4 80", "tcp localhost 80",
                     "tcp 1.2.3.0/24 80", "tcp fe80::1%eth0 80", "tcp 1.2.3.4 0",
                     "tcp 1.2.3.4 65536", "tcp 1.2.3.4 2-1", "tcp 1.2.3.4 80,",
                     "tcp 1.2.3.4 -1", "tcp 1.2.3.4 80;system(x)", "tcp [0.0.0.0] 443", "tcp [::]junk 443"):
            with self.subTest(spec=spec), self.assertRaises(ConfigError):
                parse_rules({"LISTEN_0": spec})
        for env in ({}, {"LISTEN_X": "tcp 1.2.3.4 80"}):
            with self.assertRaises(ConfigError):
                parse_rules(env)

    def test_defaults_and_generated_config(self):
        config = Config.from_env({"LISTEN_7": "udp 2001:db8::1 100-200"})
        self.assertEqual(config.interface, "eth0")
        self.assertTrue(config.ignore_checksums)
        generated = zeek_config(config)
        self.assertIn("[[2001:db8::1], udp] = vector([$first=100, $last=200])", generated)
        self.assertIn("udp_inactivity_timeout = 60 secs", generated)

    def test_bad_environment_options(self):
        for key, value in (("CAPTURE_INTERFACE", "-i eth0"), ("CAPTURE_INTERFACE", ""),
                           ("LOG_FILE", ""), ("LOG_FILE", "x\ny"), ("TZ", "Not/AZone"),
                           ("IGNORE_CHECKSUMS", "yes"), ("UDP_INACTIVITY_TIMEOUT", "0"),
                           ("SHUTDOWN_TIMEOUT", "1.5")):
            with self.subTest(key=key), self.assertRaises(ConfigError):
                Config.from_env({"LISTEN_0": "tcp 1.2.3.4 80", key: value})


class FormatTests(unittest.TestCase):
    def setUp(self):
        self.record = dict(remote_addr="100.64.0.11", remote_port=61270,
                           server_addr="100.64.0.20", server_port=443,
                           protocol="TCP", bytes_sent=8940, bytes_received=1250,
                           session_time=2.3512)

    def test_all_variables_and_timezone(self):
        fmt = LogFormatter("$remote_addr:$remote_port [$time_iso8601] $protocol $bytes_sent $bytes_received $session_time $server_addr:$server_port", ZoneInfo("Asia/Shanghai"))
        line = fmt.render(self.record, datetime(2026, 10, 25, tzinfo=timezone.utc))
        self.assertEqual(line, "100.64.0.11:61270 [2026-10-25T08:00:00+08:00] TCP 8940 1250 2.351 100.64.0.20:443")

    def test_braces_and_literal_dollar_no_recursive_substitution(self):
        fmt = LogFormatter("${protocol}suffix $$remote_addr", ZoneInfo("UTC"))
        self.assertEqual(fmt.render(self.record), "TCPsuffix $remote_addr")

    def test_bad_templates(self):
        for value in ("", "$missing", "$", "${protocol", "$()", "$protocol\n", "a\r", "a\0"):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                LogFormatter(value, ZoneInfo("UTC"))

    def test_bad_records(self):
        for key, value in (("session_time", float("nan")), ("session_time", -1),
                           ("session_time", True), ("bytes_sent", 1.1),
                           ("protocol", "HTTP"), ("remote_addr", "foo\nbar")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                LogFormatter("$protocol", ZoneInfo("UTC")).render(self.record | {key: value})


class SinkTests(unittest.TestCase):
    def test_append_reopen_and_flush(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested/access.log"
            sink = LogSink(str(path))
            sink.write("one")
            self.assertEqual(path.read_text(), "one\n")
            rotated = path.with_suffix(".old")
            path.rename(rotated)
            sink.reopen()
            sink.write("two")
            sink.close()
            sink = LogSink(str(path))
            sink.write("three")
            sink.close()
            self.assertEqual(rotated.read_text(), "one\n")
            self.assertEqual(path.read_text(), "two\nthree\n")

    def test_stdout_not_closed(self):
        out = io.StringIO()
        with patch("sys.stdout", out):
            sink = LogSink("-")
            sink.write("one")
            sink.reopen()
            sink.close()
        self.assertEqual(out.getvalue(), "one\n")

    def test_fifo_does_not_hang(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "pipe")
            os.mkfifo(path)
            with self.assertRaises((OSError, ValueError)):
                LogSink(path)


if __name__ == "__main__":
    unittest.main()
