from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class HardwareFirmwareBlobResponse(BaseModel):
    """One detected hardware firmware blob."""

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: uuid.UUID
    firmware_id: uuid.UUID
    blob_path: str
    partition: str | None = None
    blob_sha256: str
    file_size: int
    category: str
    vendor: str | None = None
    format: str
    version: str | None = None
    signed: str = "unknown"
    signature_algorithm: str | None = None
    cert_subject: str | None = None
    chipset_target: str | None = None
    driver_references: list[str] | None = None
    sbom_component_id: uuid.UUID | None = None
    metadata: dict = Field(validation_alias="metadata_", default_factory=dict)
    detection_source: str
    detection_confidence: str = "medium"
    created_at: datetime


class HardwareFirmwareListResponse(BaseModel):
    """Paginated list of hardware firmware blobs."""

    blobs: list[HardwareFirmwareBlobResponse]
    total: int


class HardwareFirmwareFilter(BaseModel):
    """Filter criteria for listing hardware firmware blobs."""

    category: str | None = None
    vendor: str | None = None
    signed_only: bool | None = None
