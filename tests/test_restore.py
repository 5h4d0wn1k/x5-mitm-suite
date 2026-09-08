"""Restore-command tests: arg validation, preview plan, state file lifecycle."""

import contextlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'firmware'))

from mitm_suite import restore as restore_mod
from mitm_suite.cli import build_parser
from mitm_suite.restore import validate_restore_args
from mitm_suite.statefile import LabState


class RestoreArgValidationTests(unittest.TestCase):
    def test_restore_parses_with_and_without_iface(self):
        parser = build_parser()
        args = parser.parse_args(["restore"])
        self.assertEqual(args.command, "restore")
        self.assertIsNone(args.iface)
        args = parser.parse_args(["restore", "--iface", "wlan0", "--dry-run"])
        self.assertEqual(args.iface, "wlan0")
        self.assertTrue(args.dry_run)

    def test_validate_restore_args_ok(self):
        self.assertEqual(validate_restore_args(None), [])
        self.assertEqual(validate_restore_args("wlan0"), [])

    def test_validate_restore_args_rejects_bogus_iface(self):
        errors = validate_restore_args("definitely-not-an-iface-xyz")
        self.assertEqual(len(errors), 1)
        self.assertIn("not present", errors[0])

    def test_restore_rejects_unexpected_positional(self):
        parser = build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["restore", "192.0.2.50"])


class RestorePlanTests(unittest.TestCase):
    def test_build_restore_plan_is_read_only(self):
        plan = restore_mod.build_restore_plan(None)
        self.assertIn("marker_rules_pending", plan)
        self.assertIn("ip_forward_prior", plan)
        self.assertIn("state_file", plan)
        self.assertIsInstance(plan["marker_rules_pending"], list)

    def test_preview_restore_is_safe_without_root(self):
        # preview must never require root or modify state
        with contextlib.redirect_stdout(io.StringIO()):
            restore_mod.preview_restore(None)

    def test_dry_run_execute_is_safe_without_root(self):
        with contextlib.redirect_stdout(io.StringIO()):
            summary = restore_mod.execute_restore(dry_run=True)
        self.assertTrue(summary["dry_run"])

    def test_rule_line_to_delete_argv(self):
        argv = restore_mod.delete_rule_for(
            "-A PREROUTING -i wlan0 -m comment --comment "
            '"x5-mitm-suite:http" -p tcp --dport 80 -j REDIRECT --to-ports 8080'
        )
        self.assertIsNotNone(argv)
        self.assertEqual(argv[0], "iptables")
        self.assertEqual(argv[1:4], ["-t", "nat", "-D"])
        self.assertIn("--comment", argv)


class LabStateTests(unittest.TestCase):
    def test_state_save_load_clear(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / ".state.json")
            state = LabState(path)
            self.assertIsNone(state.load())
            state.save(
                iface="wlan0",
                command="http",
                markers=["x5-mitm-suite:http"],
                ip_forward_prior=None,
            )
            loaded = state.load()
            self.assertEqual(loaded["iface"], "wlan0")
            self.assertEqual(loaded["markers"], ["x5-mitm-suite:http"])
            state.clear()
            self.assertIsNone(state.load())


if __name__ == "__main__":
    unittest.main()