"""
zintel_client.py — Z-Intel Plus API client for case creation.

Creates research cases on Zintel with artifacts (ZIP files) attached,
using multipart form-data upload.
"""

import logging
import os

import requests

logger = logging.getLogger("vt_pipeline.zintel_client")


class ZintelClient:
    """Thin client for the Z-Intel Plus REST API."""

    def __init__(self, api_url: str, api_key: str):
        """
        Parameters
        ----------
        api_url : str
            Base API URL, e.g. ``https://z-intel-plus.corp.zscaler.com/api``.
        api_key : str
            API key (sent as ``Api-Key <key>`` in the Authorization header).
        """
        self.api_url = api_url.rstrip("/")
        self.headers = {
            "accept": "application/json",
            "Authorization": f"Api-Key {api_key}",
        }

    # ── Case creation ───────────────────────────────────────────────────

    def create_case(
        self,
        name: str,
        source_id: int,
        comments: str,
        assign_to: int = None,
        assignment_type: str = "user",
        associated_md5s: list = None,
        artifact_path: str = None,
    ) -> dict:
        """
        Create a new research case, optionally with an artifact ZIP.

        Parameters
        ----------
        name : str
            Case name / title.
        source_id : int
            Source enum (6 = VirusTotal).
        comments : str
            Case comments / description.
        assign_to : int, optional
            Zintel user ID to assign the case to.
        assignment_type : str
            ``"user"`` or ``"group"``.
        associated_md5s : list[str], optional
            List of MD5 hashes to associate with the case.
        artifact_path : str, optional
            Path to a ZIP file to attach as an artifact.

        Returns
        -------
        dict
            ``{"success": bool, "case_id": int or None, "message": str, "raw": dict}``
        """
        url = f"{self.api_url}/research/cases/"

        # Build multipart form data
        form_data = {
            "name": (None, name),
            "source": (None, str(source_id)),
            "comments": (None, comments),
        }

        if assign_to is not None:
            form_data["assign_to"] = (None, str(assign_to))
            form_data["assignment_type"] = (None, assignment_type)

        if associated_md5s:
            md5_str = ",".join(associated_md5s)
            form_data["associated_md5"] = (None, md5_str)

        files_to_send = []
        artifact_fh = None

        if artifact_path and os.path.isfile(artifact_path):
            artifact_fh = open(artifact_path, "rb")
            files_to_send.append(
                ("artifacts", (os.path.basename(artifact_path), artifact_fh, "application/zip"))
            )

        logger.info("Creating Zintel case: %s", name)
        logger.debug("  assign_to=%s, source=%d, artifact=%s", assign_to, source_id, artifact_path)

        try:
            resp = requests.post(
                url,
                headers=self.headers,
                files={**form_data, **dict(files_to_send)} if files_to_send else form_data,
                timeout=120,
            )
            resp_data = resp.json()

            if resp.status_code in (200, 201):
                data = resp_data.get("data", resp_data)
                case_id = data.get("case_id")
                msg = data.get("message", "OK")
                logger.info("Case created successfully: case_id=%s — %s", case_id, msg)
                return {
                    "success": True,
                    "case_id": case_id,
                    "message": msg,
                    "raw": resp_data,
                }
            else:
                logger.error(
                    "Case creation failed (HTTP %d): %s",
                    resp.status_code, resp_data,
                )
                return {
                    "success": False,
                    "case_id": None,
                    "message": str(resp_data),
                    "raw": resp_data,
                }

        except requests.RequestException as exc:
            logger.error("HTTP error creating case: %s", exc)
            return {
                "success": False,
                "case_id": None,
                "message": str(exc),
                "raw": {},
            }
        finally:
            if artifact_fh:
                artifact_fh.close()

    # ── Case info ───────────────────────────────────────────────────────

    def get_case(self, case_id: int) -> dict:
        """Fetch details for a case by ID."""
        url = f"{self.api_url}/research/cases/{case_id}/"
        try:
            resp = requests.get(url, headers=self.headers, timeout=30)
            return resp.json().get("data", resp.json())
        except Exception as exc:
            logger.error("Failed to fetch case %d: %s", case_id, exc)
            return {}

    def get_case_artifacts(self, case_id: int) -> list:
        """Fetch the list of artifacts attached to a case."""
        url = f"{self.api_url}/research/cases/{case_id}/artifacts/"
        try:
            resp = requests.get(url, headers=self.headers, timeout=30)
            return resp.json().get("data", [])
        except Exception as exc:
            logger.error("Failed to fetch artifacts for case %d: %s", case_id, exc)
            return []
