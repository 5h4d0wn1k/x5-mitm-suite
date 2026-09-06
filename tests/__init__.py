"""Make the ``firmware/`` package importable from the repo root."""
import os
import sys

_FIRMWARE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "firmware"
)
if _FIRMWARE not in sys.path:
    sys.path.insert(0, _FIRMWARE)