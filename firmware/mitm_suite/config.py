"""Configuration loading, validation and defaults for mitm_suite.

Config files are loaded from JSON (stdlib) or YAML. Full YAML is only
available when PyYAML is installed (optional dependency); a small built-in
subset loader handles the flat ``key: value`` mapping used by the shipped
``config/mitm.yaml`` so the tool stays stdlib-only.

Defaults use DOCUMENTATION LAB PLACEHOLDERS only (RFC 5737 ``192.0.2.0/24``
range, ``lab-ap``, ``wlan0``). Never commit real IPs, MACs or SSIDs.
"""

from __future__ import annotations

import ast
import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:  # optional dependency
    import yaml  # type: ignore
except ImportError:  # pragma: no cover - exercised when PyYAML is absent
    yaml = None  # type: ignore

DEFAULT_CONFIG_PATH = Path("config/mitm.yaml")

DEFAULT_CONFIG: Dict[str, Any] = {
    # network role (documentation-lab values only)
    "gateway": "192.0.2.1",       # lab AP gateway
    "target": "192.0.2.50",       # lab victim host
    "iface": "wlan0",             # lab interface
    "ssid": "lab-ap",             # lab AP SSID (metadata only)
    # DNS
    "dns_upstream": "192.0.2.53", # lab resolver to forward non-spoofed queries
    "dns_port": 5353,             # local fake-resolver listen port
    # HTTP proxy
    "proxy_host": "0.0.0.0",
    "proxy_port": 8080,
    # storage / logging (all gitignored)
    "db_path": "logs/mitm.db",
    "log_path": "logs/mitm.log",
    "events_path": "logs/mitm-events.jsonl",
    "captures_dir": "captures",
    "pcap_path": "captures/mitm-capture.pcap",
    "pcap_enabled": True,
    # ARP
    "arp_interval": 2.0,
    "arp_count": 0,
    # metrics
    "metrics_bucket_seconds": 60,
}

_STRING_KEYS = {
    "gateway", "target", "iface", "ssid", "dns_upstream", "proxy_host",
    "db_path", "log_path", "events_path", "captures_dir", "pcap_path",
}
_IP_KEYS = {"gateway", "target", "dns_upstream"}
_INT_KEYS = {"dns_port", "proxy_port", "arp_count", "metrics_bucket_seconds"}
_FLOAT_KEYS = {"arp_interval"}
_BOOL_KEYS = {"pcap_enabled"}

_KNOWN_KEYS = _STRING_KEYS | _IP_KEYS | _INT_KEYS | _FLOAT_KEYS | _BOOL_KEYS

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class ConfigError(Exception):
    """Raised when a configuration file cannot be parsed or validated."""


def _strip_yaml_comment(value: str) -> str:
    """Strip a trailing `` # ...`` comment that is outside quotes."""
    value = value.rstrip()
    if not value:
        return value
    if value[0] in "\"'":
        quote = value[0]
        for i in range(1, len(value)):
            if value[i] == quote and value[i - 1] != "\\":
                return value[: i + 1].strip()
        return value.strip()
    idx = value.find(" #")
    if idx >= 0:
        return value[:idx].strip()
    return value.strip()


def _coerce_scalar(raw: str) -> Any:
    value = _strip_yaml_comment(raw)
    if value in ("true", "True", "TRUE", "on", "yes"):
        return True
    if value in ("false", "False", "FALSE", "off", "no"):
        return False
    if value in ("null", "Null", "NULL", "~", ""):
        return None
    if value[:1] in "\"'" and value[-1:] == value[:1]:
        try:
            return ast.literal_eval(value)
        except (SyntaxError, ValueError):
            return value[1:-1]
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    if re.fullmatch(r"-?\d+\.\d+", value):
        return float(value)
    return value


def parse_yaml_subset(text: str) -> Dict[str, Any]:
    """Parse the flat ``key: value`` YAML subset used by config/mitm.yaml.

    Full YAML requires PyYAML; this loader deliberately covers the flat
    mapping documented for this project (comments, quoted values, scalars).
    """
    doc: Dict[str, Any] = {}
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line[0] in "-[]{}|>" or "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise ConfigError(
                f"config line {lineno}: built-in parser supports flat "
                f"'key: value' mappings only (install PyYAML for full YAML)"
            )
        if ":" not in line:
            raise ConfigError(f"config line {lineno}: expected 'key: value'")
        key, _, value = line.partition(":")
        key = key.strip().strip("\"'")
        if not key:
            raise ConfigError(f"config line {lineno}: empty key")
        value = value.strip()
        if value and value[0] in "[{":
            raise ConfigError(
                f"config line {lineno}: nested mapping/list unsupported by the "
                f"built-in parser (install PyYAML for full YAML)"
            )
        doc[key] = _coerce_scalar(value)
    return doc


def _load_doc(path: Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"{path}: invalid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ConfigError(f"{path}: JSON root must be a mapping")
        return parsed
    if yaml is not None:
        try:
            parsed = yaml.safe_load(text)
        except Exception as exc:  # yaml.YAMLError — keep stdlib-import compatible
            raise ConfigError(f"{path}: invalid YAML: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ConfigError(f"{path}: YAML root must be a mapping")
        return parsed
    return parse_yaml_subset(text)


def validate_config(config: Dict[str, Any]) -> Tuple[bool, List[str], List[str]]:
    """Validate a config mapping. Returns ``(ok, errors, warnings)``."""
    errors: List[str] = []
    warnings: List[str] = []
    for key, value in config.items():
        if key not in _KNOWN_KEYS:
            warnings.append(f"unknown config key '{key}' ignored")
            continue
        if key in _STRING_KEYS and not isinstance(value, str):
            errors.append(f"config key '{key}' must be a string")
        elif key in _IP_KEYS and not isinstance(value, str):
            errors.append(f"config key '{key}' must be an IP string")
        elif key in _IP_KEYS:
            try:
                ipaddress.ip_address(value)
            except ValueError:
                errors.append(f"config key '{key}' is not a valid IP: {value!r}")
        elif key in _INT_KEYS:
            if not isinstance(value, int) or isinstance(value, bool):
                errors.append(f"config key '{key}' must be an integer")
            elif key in ("dns_port", "proxy_port") and not (1 <= value <= 65535):
                errors.append(f"config key '{key}' out of range: {value}")
        elif key in _FLOAT_KEYS:
            try:
                fv = float(value)
            except (TypeError, ValueError):
                fv = -1.0
            if fv <= 0:
                errors.append(f"config key '{key}' must be a positive number")
        elif key in _BOOL_KEYS and not isinstance(value, bool):
            errors.append(f"config key '{key}' must be a boolean")
        if key in ("gateway", "target", "dns_upstream") and isinstance(value, str):
            # Only warn for clearly-public addresses (lab-only reminder).
            try:
                ipaddress.IPv4Address(value)
            except ValueError:
                continue
            if not _IP_RE.match(value):
                continue
            if value.startswith(("192.0.2.", "198.51.100.", "203.0.113.")):
                continue
            warnings.append(
                f"config '{key}={value}' is not in a documentation-lab range — "
                f"ensure this is your OWN lab network"
            )
    return (not errors, errors, warnings)


def resolve_config_path(path: Optional[str] = None) -> Path:
    if path:
        return Path(path).expanduser()
    env = os.environ.get("MITM_CONFIG")
    if env:
        return Path(env).expanduser()
    return Path(DEFAULT_CONFIG_PATH)


def load_config(path: Optional[str] = None, log=None) -> Dict[str, Any]:
    """Load config file over defaults and validate. Raises ConfigError."""
    cfg_path = resolve_config_path(path)
    config = dict(DEFAULT_CONFIG)
    if cfg_path.is_file():
        loaded = _load_doc(cfg_path)
        config.update(loaded)
        ok, errors, warnings = validate_config(config)
        for warning in warnings:
            if log:
                log.warning(warning)
        if not ok:
            raise ConfigError(f"{cfg_path}: {'; '.join(errors)}")
        if log:
            log.info("config loaded from %s", cfg_path)
    elif log:
        log.info(
            "config file %s not found — using embedded documentation-lab defaults",
            cfg_path,
        )
    ok, errors, warnings = validate_config(config)
    for warning in warnings:
        if log:
            log.warning(warning)
    if not ok:
        raise ConfigError(f"defaults: {'; '.join(errors)}")
    return config