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


# ---------------------------------------------------------------------------
# Phase 3 — driver <-> firmware graph schemas
# ---------------------------------------------------------------------------


class FirmwareEdgeResponse(BaseModel):
    """One edge in the driver <-> firmware graph.

    ``firmware_blob_path`` is ``None`` when the driver requests firmware that
    is not present in the extracted image (an unresolved / missing
    reference).
    """

    model_config = ConfigDict(from_attributes=True)

    driver_path: str
    firmware_name: str
    firmware_blob_path: str | None = None
    source: str  # kmod_modinfo | vmlinux_strings | dtb_firmware_name


class FirmwareEdgesResponse(BaseModel):
    """Response for the ``/component-map/firmware-edges``-style overlay."""

    edges: list[FirmwareEdgeResponse]
    kmod_drivers: int
    dtb_sources: int
    unresolved_count: int


class FirmwareDriverResponse(BaseModel):
    """Driver (kmod / vmlinux / DTB source) with its firmware dependencies."""

    model_config = ConfigDict(from_attributes=True)

    driver_path: str
    format: str  # ko | vmlinux | dtb
    firmware_deps: list[str]  # requested firmware names (both resolved + unresolved)
    firmware_blobs: list[str]  # resolved blob paths
    total: int  # count of firmware_deps


class FirmwareDriversListResponse(BaseModel):
    drivers: list[FirmwareDriverResponse]
    total: int
