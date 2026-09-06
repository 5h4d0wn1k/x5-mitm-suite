"""Structured logging (file + stdout) and JSONL event emission."""

from __future__ import annotations

import json
import logging
import sys
import threading
from pathlib import Path
from typing import Any, Dict, Optional

from .config import DEFAULT_CONFIG

LOGGER_NAME = "mitm"


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def setup_logging(
    log_path: str = DEFAULT_CONFIG["log_path"],
    level: str = "info",
    console: bool = True,
) -> logging.Logger:
    """Configure the ``mitm`` logger: file always, stdout/stderr optionally."""
    ensure_dir(Path(log_path).parent)
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False
    logger.handlers.clear()

    fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    if console:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(fmt)
        logger.addHandler(console_handler)
    return logger


class EventWriter:
    """Appends JSON-Lines events to a file. Thread-safe."""

    def __init__(self, events_path: str = DEFAULT_CONFIG["events_path"]) -> None:
        self._path = Path(events_path)
        ensure_dir(self._path.parent)
        self._lock = threading.Lock()
        self._fh = open(self._path, "a", encoding="utf-8")

    def emit(
        self,
        module: str,
        event: str,
        level: str = "info",
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        record = {
            "ts": _now(),
            "module": module,
            "event": event,
            "level": level,
            "payload": payload or {},
        }
        line = json.dumps(record, separators=(",", ":"))
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()
        return record

    def close(self) -> None:
        with self._lock:
            self._fh.close()

    def __enter__(self) -> "EventWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _now() -> str:
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")