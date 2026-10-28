#!/usr/bin/env python3
"""
update_yara_export.py — Daily YARA export updater.

Downloads the latest YARA export from Z-Intel Plus and updates the local
yara_exports directory with any new or changed rule files.

Designed to run daily via cron (e.g. at 1 AM), so that the VT Pipeline
(which runs at 2 AM) always scans against the freshest YARA rules.

Usage
-----
    python3 update_yara_export.py
    python3 update_yara_export.py --config /path/to/config.yaml
"""

import argparse
import io
import logging
import os
import re
import sys
import zipfile
from datetime import datetime

import requests
import yaml

logger = logging.getLogger("update_yara_export")


def setup_logging(log_dir: str) -> str:
    os.makedirs(log_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"yara_export_{ts}.log")
    fmt = logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(fh)
    root.addHandler(ch)
    return log_file


def load_config(config_path: str) -> dict:
    with open(config_path, "r") as fh:
        return yaml.safe_load(fh)


def get_latest_export_id(api_url: str, api_key: str):
    """Query Z-Intel for the latest completed YARA export ID."""
    url = f"{api_url}/coverage/yara-exports/"
    headers = {"accept": "application/json", "Authorization": f"Api-Key {api_key}"}
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        for item in resp.json().get("data", {}).get("results", []):
            if item.get("status") == "completed":
                eid = str(item["id"]).strip()
                logger.info("Latest export: id=%s (%s)", eid, item.get("created_date", "?"))
                return eid
        logger.warning("No completed exports found")
        return None
    except Exception as exc:
        logger.error("Failed to fetch export list: %s", exc)
        return None


def get_last_cached_id(cache_dir: str) -> str:
    """Return the export ID from the most recent cached export_<id>.zip, or ''."""
    pat = re.compile(r"^export_(\d+)\.zip$")
    if not os.path.isdir(cache_dir):
        return ""
    for fn in sorted(os.listdir(cache_dir), reverse=True):
        m = pat.match(fn)
        if m:
            return m.group(1)
    return ""


def download_and_update(export_id, api_url, api_key, unzip_location, cache_dir):
    """Download export ZIP and update local YARA files. Returns True if updated."""
    if get_last_cached_id(cache_dir) == export_id:
        logger.info("Export %s already cached — up to date", export_id)
        return False

    url = f"{api_url}/coverage/yara-exports/{export_id}/download/"
    headers = {"accept": "application/json", "Authorization": f"Api-Key {api_key}"}
    logger.info("Downloading export %s", export_id)
    try:
        resp = requests.get(url, headers=headers, timeout=300)
        if resp.status_code != 200:
            logger.error("Download failed (HTTP %d)", resp.status_code)
            return False
    except Exception as exc:
        logger.error("Download failed: %s", exc)
        return False

    # Cache the zip (remove old ones)
    os.makedirs(cache_dir, exist_ok=True)
    for old in os.listdir(cache_dir):
        if old.startswith("export_") and old.endswith(".zip"):
            try: os.remove(os.path.join(cache_dir, old))
            except OSError: pass
    with open(os.path.join(cache_dir, f"export_{export_id}.zip"), "wb") as fh:
        fh.write(resp.content)

    # Extract and update only changed files
    os.makedirs(unzip_location, exist_ok=True)
    updated, skipped = 0, 0
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        for name in zf.namelist():
            if "." not in name:
                continue
            dest = os.path.join(unzip_location, name)
            new_content = zf.read(name)
            if os.path.exists(dest):
                with open(dest, "rb") as ef:
                    if ef.read() == new_content:
                        skipped += 1
                        continue
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as out:
                out.write(new_content)
            updated += 1

    logger.info("Done: %d updated, %d unchanged", updated, skipped)
    return updated > 0


def main():
    parser = argparse.ArgumentParser(description="Update YARA export from Z-Intel Plus")
    parser.add_argument("--config", "-c",
        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml"))
    args = parser.parse_args()

    cfg = load_config(args.config)
    log_dir = cfg.get("paths", {}).get("pipeline_logs_dir", "logs")
    setup_logging(log_dir)

    zintel_cfg = cfg.get("zintel", {})
    api_url = zintel_cfg.get("api_url", "https://z-intel-plus.corp.zscaler.com/api")
    api_key = zintel_cfg.get("api_key", "")

    yara_cfg = cfg.get("yara_export", {})
    unzip_location = yara_cfg.get("unzip_location", "")
    cache_dir = yara_cfg.get("export_cache_dir",
                             cfg.get("paths", {}).get("pipeline_data_dir", "data"))

    if not api_key:
        logger.error("No Zintel API key"); sys.exit(1)
    if not unzip_location:
        logger.error("No unzip_location configured"); sys.exit(1)

    logger.info("YARA export updater — unzip=%s cache=%s", unzip_location, cache_dir)

    export_id = get_latest_export_id(api_url, api_key)
    if not export_id:
        logger.error("Could not find latest export"); sys.exit(1)

    download_and_update(export_id, api_url, api_key, unzip_location, cache_dir)
    logger.info("Done")


if __name__ == "__main__":
    main()
