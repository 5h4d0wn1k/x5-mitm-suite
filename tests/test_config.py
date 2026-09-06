"""Config tests: lab-placeholder defaults, YAML-subset + JSON parsing, validation."""

import json
import tempfile
import unittest
from pathlib import Path

from mitm_suite import config as config_mod
from mitm_suite.config import ConfigError, load_config


class DefaultsTests(unittest.TestCase):
    def test_defaults_are_documented_lab_placeholders(self):
        self.assertEqual(config_mod.DEFAULT_CONFIG["gateway"], "192.0.2.1")
        self.assertEqual(config_mod.DEFAULT_CONFIG["target"], "192.0.2.50")
        self.assertEqual(config_mod.DEFAULT_CONFIG["iface"], "wlan0")
        self.assertEqual(config_mod.DEFAULT_CONFIG["ssid"], "lab-ap")

    def test_defaults_validate(self):
        ok, errors, _ = config_mod.validate_config(dict(config_mod.DEFAULT_CONFIG))
        self.assertTrue(ok, msg=f"default config invalid: {errors}")
        self.assertEqual(errors, [])

    def test_no_real_world_identifiers_in_defaults(self):
        for key in ("gateway", "target", "dns_upstream"):
            self.assertTrue(
                config_mod.DEFAULT_CONFIG[key].startswith("19"),
                f"{key} must stay in documentation ranges",
            )


class YAMLSubsetTests(unittest.TestCase):
    def test_parse_flat_mapping(self):
        text = """# comment
        gateway: 192.0.2.1
        iface: wlan0
        ssid: 'lab-ap'
        proxy_port: 8080
        arp_interval: 2.0
        pcap_enabled: true
        """
        doc = config_mod.parse_yaml_subset(text)
        self.assertEqual(doc["gateway"], "192.0.2.1")
        self.assertEqual(doc["iface"], "wlan0")
        self.assertEqual(doc["ssid"], "lab-ap")
        self.assertEqual(doc["proxy_port"], 8080)
        self.assertEqual(doc["arp_interval"], 2.0)
        self.assertTrue(doc["pcap_enabled"])

    def test_inline_comment_stripped(self):
        doc = config_mod.parse_yaml_subset("gateway: 192.0.2.1   # lab gw\n")
        self.assertEqual(doc["gateway"], "192.0.2.1")

    def test_rejects_unsupported_structure(self):
        with self.assertRaises(ConfigError):
            config_mod.parse_yaml_subset("dns: {nested: 1}\n")
        with self.assertRaises(ConfigError):
            config_mod.parse_yaml_subset("no_colon_here\n")


class LoadTests(unittest.TestCase):
    def test_missing_file_falls_back_to_defaults(self):
        config = load_config("/nonexistent/mitm.yaml")
        self.assertEqual(config["gateway"], "192.0.2.1")

    def test_json_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mitm.json"
            path.write_text(json.dumps({"gateway": "192.0.2.9", "iface": "eth9"}))
            config = load_config(str(path))
            self.assertEqual(config["gateway"], "192.0.2.9")
            self.assertEqual(config["iface"], "eth9")
            self.assertEqual(config["target"], "192.0.2.50", "unset keys keep defaults")

    def test_yaml_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mitm.yaml"
            path.write_text("gateway: 192.0.2.10\ntarget: 192.0.2.60\n")
            config = load_config(str(path))
            self.assertEqual(config["gateway"], "192.0.2.10")
            self.assertEqual(config["target"], "192.0.2.60")
            self.assertEqual(config["ssid"], "lab-ap")

    def test_invalid_ip_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.yaml"
            path.write_text("gateway: not-an-ip\n")
            with self.assertRaises(ConfigError):
                load_config(str(path))

    def test_invalid_type_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.yaml"
            path.write_text("dns_port: 'lots'\n")
            with self.assertRaises(ConfigError):
                load_config(str(path))


if __name__ == "__main__":
    unittest.main()