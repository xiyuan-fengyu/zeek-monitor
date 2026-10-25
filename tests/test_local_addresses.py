"""Actual read-only discovery plus fail-closed error handling."""
import ctypes
import errno
import ipaddress
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from local_addresses import get_local_addresses


class LocalAddressTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform in {"linux", "darwin"}, "getifaddrs platform")
    def test_actual_namespace_has_loopback_and_only_exact_ips(self):
        addresses = get_local_addresses()
        self.assertIn("127.0.0.1", addresses)
        self.assertTrue(all(not ipaddress.ip_address(a).is_unspecified for a in addresses))

    def test_discovery_error_propagates(self):
        libc = MagicMock()
        libc.getifaddrs.return_value = -1
        with patch("local_addresses.ctypes.CDLL", return_value=libc), patch("local_addresses.ctypes.get_errno", return_value=errno.EPERM):
            with self.assertRaises(OSError) as error:
                get_local_addresses()
        self.assertEqual(error.exception.errno, errno.EPERM)
        libc.freeifaddrs.assert_not_called()

    def test_empty_list_fails_closed_and_freed(self):
        libc = MagicMock()
        libc.getifaddrs.return_value = 0
        with patch("local_addresses.ctypes.CDLL", return_value=libc):
            with self.assertRaisesRegex(OSError, "no local IP addresses"):
                get_local_addresses()
        libc.freeifaddrs.assert_called_once()
