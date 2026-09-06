"""SQLite store round-trip tests (events + credential captures)."""

import tempfile
import unittest
from pathlib import Path

from mitm_suite.store import ResultStore


class StoreTests(unittest.TestCase):
    def test_event_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "mitm.db")
            with ResultStore(db) as store:
                event_id = store.record_event(
                    "arp", "arp_spoof_start", "info", {"gateway": "192.0.2.1"}
                )
                store.record_event(
                    "http", "credential_capture", "warn", {"kind": "form_post"}
                )
                events = store.query_events()
                self.assertGreaterEqual(event_id, 1)
                self.assertEqual(len(events), 2)
                self.assertEqual(events[0]["payload"]["kind"], "form_post")
                self.assertEqual(events[1]["module"], "arp")
                self.assertEqual(store.count_events(), 2)
                self.assertEqual(store.count_events("http"), 1)

    def test_capture_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "mitm.db")
            with ResultStore(db) as store:
                cap_id = store.record_capture(
                    kind="form_post",
                    username="admin",
                    password="labpass",
                    url="http://192.0.2.50/login",
                    remote="192.0.2.60",
                )
                captures = store.query_captures()
                self.assertGreaterEqual(cap_id, 1)
                self.assertEqual(len(captures), 1)
                self.assertEqual(captures[0]["username"], "admin")
                self.assertEqual(captures[0]["password"], "labpass")
                self.assertEqual(captures[0]["url"], "http://192.0.2.50/login")
                self.assertEqual(store.count_captures(), 1)

    def test_module_filtering(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "mitm.db")
            with ResultStore(db) as store:
                store.record_event("dns", "dns_spoof", "info", {"fqdn": "bank.lab"})
                store.record_event("monitor", "arp_pair_seen", "info", {})
                self.assertEqual(store.count_events("dns"), 1)
                self.assertEqual(store.count_events("monitor"), 1)
                self.assertEqual(store.count_events("http"), 0)


if __name__ == "__main__":
    unittest.main()