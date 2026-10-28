"""
state_manager.py — Persistent state for processed hashes and run history.

Keeps track of every SHA256 hash the pipeline has ever processed (downloaded,
scanned, or analysed) so that future runs never re-process the same sample.
Also maintains an append-only run history log.
"""

import json
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger("vt_pipeline.state")


def _ensure_dir(path: str) -> None:
    """Create parent directory if it doesn't exist."""
    os.makedirs(os.path.dirname(path), exist_ok=True)


# ── Processed hashes ────────────────────────────────────────────────────────

def load_processed_hashes(data_dir: str) -> set:
    """Load the set of previously processed SHA256 hashes."""
    path = os.path.join(data_dir, "processed_hashes.json")
    if not os.path.exists(path):
        logger.info("No processed_hashes.json found — starting fresh")
        return set()
    try:
        with open(path, "r") as fh:
            data = json.load(fh)
        hashes = set(data.get("hashes", []))
        logger.info("Loaded %d previously processed hashes", len(hashes))
        return hashes
    except Exception as exc:
        logger.warning("Failed to load processed_hashes.json: %s — starting fresh", exc)
        return set()


def save_processed_hashes(data_dir: str, hashes: set) -> None:
    """Persist the full set of processed SHA256 hashes."""
    path = os.path.join(data_dir, "processed_hashes.json")
    _ensure_dir(path)
    payload = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(hashes),
        "hashes": sorted(hashes),
    }
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(payload, fh, indent=2)
    os.replace(tmp, path)
    logger.info("Saved %d processed hashes", len(hashes))


# ── Run history ─────────────────────────────────────────────────────────────

def append_run_history(data_dir: str, entry: dict) -> None:
    """Append a single run-result entry to run_history.json."""
    path = os.path.join(data_dir, "run_history.json")
    _ensure_dir(path)

    history = []
    if os.path.exists(path):
        try:
            with open(path, "r") as fh:
                history = json.load(fh)
        except Exception:
            history = []

    entry.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    history.append(entry)

    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(history, fh, indent=2)
    os.replace(tmp, path)
    logger.debug("Appended run history entry for family=%s", entry.get("family"))
