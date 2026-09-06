"""Minimal pcap (libpcap classic format) writer. Stdlib-only."""

from __future__ import annotations

import struct
import threading
import time
from pathlib import Path
from typing import Optional

from .config import DEFAULT_CONFIG

_PCAP_GLOBAL = struct.pack(
    "<IHHiIII",
    0xA1B2C3D4,  # magic (little-endian)
    2,           # major
    4,           # minor
    0,           # thiszone
    0,           # sigfigs
    65535,       # snaplen
    1,           # linktype = Ethernet
)


class PcapWriter:
    """Appends Ethernet-encapsulated frames to a classic pcap file."""

    def __init__(self, pcap_path: str = DEFAULT_CONFIG["pcap_path"]) -> None:
        self.path = str(pcap_path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._fh = open(self.path, "wb")
        self._fh.write(_PCAP_GLOBAL)
        self._fh.flush()
        self._frames = 0

    def write(self, data: bytes, ts: Optional[float] = None) -> None:
        if not data:
            return
        t = ts if ts is not None else time.time()
        sec, usec = int(t), int((t - int(t)) * 1_000_000)
        header = struct.pack("<IIII", sec, usec, len(data), len(data))
        with self._lock:
            self._fh.write(header)
            self._fh.write(data)
            self._fh.flush()
            self._frames += 1

    @property
    def frame_count(self) -> int:
        return self._frames

    def close(self) -> None:
        with self._lock:
            self._fh.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()