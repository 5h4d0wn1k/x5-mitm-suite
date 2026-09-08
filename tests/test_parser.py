"""Parser tests: every subcommand, safety defaults, argument validation."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'firmware'))

from mitm_suite import cli


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.parser = cli.build_parser()

    def parse(self, argv):
        return self.parser.parse_args(argv)

    def test_arp_subcommand(self):
        args = self.parse(
            ["arp", "--iface", "wlan0", "--gateway", "192.0.2.1", "192.0.2.50"]
        )
        self.assertEqual(args.command, "arp")
        self.assertEqual(args.target, "192.0.2.50")
        self.assertEqual(args.gateway, "192.0.2.1")
        self.assertEqual(args.iface, "wlan0")
        self.assertFalse(args.apply, "apply must default to False (dry-run safe)")
        self.assertFalse(args.no_pcap)

    def test_dns_subcommand(self):
        args = self.parse(["dns", "--iface", "wlan0", "bank.lab", "192.0.2.53"])
        self.assertEqual(args.command, "dns")
        self.assertEqual(args.fqdn, "bank.lab")
        self.assertEqual(args.redirect_ip, "192.0.2.53")
        self.assertFalse(args.apply)

    def test_http_subcommand(self):
        args = self.parse(["http", "--iface", "wlan0"])
        self.assertEqual(args.command, "http")
        self.assertFalse(args.apply)
        self.assertFalse(args.sslstrip)

    def test_https_split_subcommand(self):
        args = self.parse(["https-split", "--iface", "wlan0"])
        self.assertEqual(args.command, "https-split")
        self.assertTrue(args.sslstrip)

    def test_monitor_subcommand(self):
        args = self.parse(["monitor"])
        self.assertEqual(args.command, "monitor")
        self.assertFalse(args.apply)

    def test_restore_subcommand(self):
        args = self.parse(["restore"])
        self.assertEqual(args.command, "restore")
        self.assertFalse(args.dry_run)
        args = self.parse(["restore", "--iface", "wlan0", "--dry-run"])
        self.assertEqual(args.iface, "wlan0")
        self.assertTrue(args.dry_run)

    def test_selftest_subcommand(self):
        args = self.parse(["self-test"])
        self.assertEqual(args.command, "self-test")

    def test_metrics_subcommand(self):
        args = self.parse(["metrics"])
        self.assertEqual(args.command, "metrics")

    def test_missing_required_positional(self):
        with self.assertRaises(SystemExit):
            self.parse(["arp", "--iface", "wlan0"])
        with self.assertRaises(SystemExit):
            self.parse(["dns", "--iface", "wlan0", "bank.lab"])

    def test_unknown_flag_rejected(self):
        with self.assertRaises(SystemExit):
            self.parse(["restore", "--bogus"])
        with self.assertRaises(SystemExit):
            self.parse(["http", "--nope"])

    def test_no_command_rejected(self):
        with self.assertRaises(SystemExit):
            self.parse([])


if __name__ == "__main__":
    unittest.main()