"""
vt_search.py — VirusTotal Intelligence search and sample download.

Uses the official `vt-cli` binary to search VT Intelligence and download
samples by SHA256 hash.
"""

import json
import logging
import os
import subprocess

logger = logging.getLogger("vt_pipeline.vt_search")


def search_family(vt_cli_path: str, query: str, limit: int = 20) -> list:
    """
    Run a VT Intelligence search and return a list of file metadata dicts.

    Each dict contains at least: sha256, md5, meaningful_name, size, type_tag.

    Parameters
    ----------
    vt_cli_path : str
        Absolute path to the ``vt`` CLI binary.
    query : str
        VT Intelligence search query string.
    limit : int
        Maximum number of results to return.

    Returns
    -------
    list[dict]
        List of result dicts parsed from vt-cli JSON output.
    """
    cmd = [
        vt_cli_path, "search", query,
        "--limit", str(limit),
        "--format", "json",
    ]
    logger.info("VT search: %s (limit=%d)", query, limit)
    logger.debug("Command: %s", " ".join(cmd))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        logger.error("VT search timed out after 300s")
        return []
    except FileNotFoundError:
        logger.error("vt-cli binary not found at: %s", vt_cli_path)
        return []

    if proc.returncode != 0:
        logger.error("VT search failed (rc=%d): %s", proc.returncode, proc.stderr.strip())
        return []

    results = []
    stdout = proc.stdout.strip()
    if not stdout:
        logger.info("VT search returned 0 results")
        return results

    # vt-cli --json outputs one JSON object per line (JSONL)
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            # vt-cli sometimes outputs an array instead of JSONL
            try:
                arr = json.loads(stdout)
                if isinstance(arr, list):
                    for item in arr:
                        results.append(_normalise_vt_result(item))
                    logger.info("VT search returned %d results", len(results))
                    return results
            except json.JSONDecodeError:
                pass
            logger.warning("Skipping unparseable VT output line")
            continue
        results.append(_normalise_vt_result(obj))

    logger.info("VT search returned %d results", len(results))
    return results


def _normalise_vt_result(obj: dict) -> dict:
    """Extract relevant fields from a vt-cli JSON result object."""
    attrs = obj.get("attributes", obj)
    return {
        "sha256": attrs.get("sha256", obj.get("id", "")),
        "md5": attrs.get("md5", ""),
        "sha1": attrs.get("sha1", ""),
        "meaningful_name": attrs.get("meaningful_name", ""),
        "size": attrs.get("size", 0),
        "type_tag": attrs.get("type_tag", ""),
        "times_submitted": attrs.get("times_submitted", 0),
        "last_analysis_stats": attrs.get("last_analysis_stats", {}),
    }


def download_samples(
    vt_cli_path: str,
    hashes: list,
    dest_dir: str,
) -> list:
    """
    Download samples by SHA256 hash into *dest_dir*.

    Returns a list of dicts ``{sha256, path, success}``.

    Parameters
    ----------
    vt_cli_path : str
        Absolute path to the ``vt`` CLI binary.
    hashes : list[str]
        SHA256 hashes to download.
    dest_dir : str
        Directory to save downloaded files into.

    Returns
    -------
    list[dict]
        Download results with keys: sha256, path, success.
    """
    os.makedirs(dest_dir, exist_ok=True)
    results = []

    for sha in hashes:
        dest_path = os.path.join(dest_dir, sha)
        if os.path.exists(dest_path):
            logger.debug("Sample already on disk: %s", sha)
            results.append({"sha256": sha, "path": dest_path, "success": True})
            continue

        cmd = [
            vt_cli_path, "download", sha,
            "--output", dest_dir,
        ]
        logger.info("Downloading %s", sha)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )
            # vt-cli saves as <hash> or <hash>.zip in the output dir
            if proc.returncode == 0:
                # Check common naming patterns vt-cli uses
                found = False
                for candidate in [dest_path, dest_path + ".zip"]:
                    if os.path.exists(candidate):
                        dest_path = candidate
                        found = True
                        break
                if not found:
                    # Search for any file containing the hash prefix
                    for f in os.listdir(dest_dir):
                        if f.startswith(sha[:16]):
                            dest_path = os.path.join(dest_dir, f)
                            found = True
                            break
                if found:
                    logger.info("Downloaded %s (%d bytes)", sha, os.path.getsize(dest_path))
                    results.append({"sha256": sha, "path": dest_path, "success": True})
                else:
                    logger.error("Download returned 0 but file not found for %s", sha)
                    results.append({"sha256": sha, "path": dest_path, "success": False})
            else:
                logger.error(
                    "Download failed for %s (rc=%d): %s",
                    sha, proc.returncode, proc.stderr.strip(),
                )
                results.append({"sha256": sha, "path": dest_path, "success": False})
        except subprocess.TimeoutExpired:
            logger.error("Download timed out for %s", sha)
            results.append({"sha256": sha, "path": dest_path, "success": False})
        except FileNotFoundError:
            logger.error("vt-cli binary not found at: %s", vt_cli_path)
            results.append({"sha256": sha, "path": dest_path, "success": False})
            break  # no point trying more if the binary is missing

    downloaded = sum(1 for r in results if r["success"])
    logger.info("Downloaded %d / %d samples", downloaded, len(hashes))
    return results
