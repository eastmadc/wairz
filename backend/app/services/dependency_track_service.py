"""Service for pushing SBOMs to Dependency-Track."""

import base64
import json
import logging

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)


class DependencyTrackService:
    """Push CycloneDX SBOMs to a Dependency-Track instance."""

    def __init__(self) -> None:
        settings = get_settings()
        self.base_url = settings.dependency_track_url.rstrip("/")
        self.api_key = settings.dependency_track_api_key

    @property
    def is_configured(self) -> bool:
        return bool(self.base_url and self.api_key)

    async def push_sbom(
        self,
        sbom_json: dict,
        project_name: str,
        project_version: str = "1.0",
    ) -> dict:
        """Push a CycloneDX SBOM to Dependency-Track.

        Uses autoCreate=true so the project is created if it doesn't exist.
        Returns the DT processing token.
        """
        if not self.is_configured:
            raise ValueError(
                "Dependency-Track not configured. "
                "Set DEPENDENCY_TRACK_URL and DEPENDENCY_TRACK_API_KEY."
            )

        headers = {"X-Api-Key": self.api_key}

        # DT expects the BOM as a base64-encoded CycloneDX JSON string
        bom_bytes = json.dumps(sbom_json).encode()
        bom_b64 = base64.b64encode(bom_bytes).decode()

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.put(
                f"{self.base_url}/api/v1/bom",
                headers=headers,
                json={
                    "projectName": project_name,
                    "projectVersion": project_version,
                    "autoCreate": True,
                    "bom": bom_b64,
                },
            )
            resp.raise_for_status()
            return resp.json()
