"""Persistent lab-state file so ``mitm restore`` can undo a prior apply run.

The state file records exactly what an applied run changed (markers + prior
``ip_forward`` value) so cleanup is deterministic and idempotent, supporting
the "restore reliability over 20 restarts" metric.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_STATE_FILE = "logs/.mitm-state.json"


def state_path(path: Optional[str] = None) -> Path:
    if path:
        return Path(path).expanduser()
    env = os.environ.get("MITM_STATE_FILE")
    if env:
        return Path(env).expanduser()
    return Path(DEFAULT_STATE_FILE)


class LabState:
    """Load/save/clear for the single lab-state JSON file."""

    _lock = threading.Lock()

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = state_path(path)
        if str(self.path) != DEFAULT_STATE_FILE:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)

    def save(
        self,
        iface: str,
        command: str,
        markers: List[str],
        ip_forward_prior: Optional[str],
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        record = {
            "pid": os.getpid(),
            "iface": iface,
            "command": command,
            "markers": markers,
            "ip_forward_prior": ip_forward_prior,
            "extra": extra or {},
        }
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            self.path.write_text(
                json.dumps(record, separators=(",", ":")), encoding="utf-8"
            )

    def load(self) -> Optional[Dict[str, Any]]:
        if not self.path.is_file():
            return None
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def clear(self) -> None:
        with self._lock:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass

    def __enter__(self) -> "LabState":
        return self

    def __exit__(self, *exc) -> None:
        pass