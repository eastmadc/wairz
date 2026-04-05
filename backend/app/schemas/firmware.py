import uuid
from datetime import datetime

from pydantic import BaseModel


class FirmwareUploadResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    original_filename: str | None
    sha256: str
    file_size: int | None
    version_label: str | None = None
    created_at: datetime


class FirmwareUpdate(BaseModel):
    version_label: str | None = None


class BinaryInfoResponse(BaseModel):
    """Structured binary analysis results (stored as JSONB on Firmware)."""
    format: str | None = None
    architecture: str | None = None
    endianness: str | None = None
    bits: int | None = None
    is_static: bool | None = None
    is_pie: bool | None = None
    interpreter: str | None = None
    dependencies: list[str] = []
    entry_point: int | None = None
    file_size: int | None = None
    extracted_filename: str | None = None


class FirmwareDetailResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    project_id: uuid.UUID
    original_filename: str | None
    sha256: str
    file_size: int | None
    architecture: str | None
    endianness: str | None
    os_info: str | None
    extracted_path: str | None = None
    kernel_path: str | None
    version_label: str | None = None
    unpack_log: str | None
    unpack_stage: str | None = None
    unpack_progress: int | None = None
    binary_info: BinaryInfoResponse | None = None
    created_at: datetime


# ── Firmware Image Metadata schemas ──


class FirmwareSectionResponse(BaseModel):
    offset: int
    size: int | None
    type: str
    description: str


class UBootHeaderResponse(BaseModel):
    magic: str
    header_crc: str
    timestamp: int
    data_size: int
    load_address: str
    entry_point: str
    data_crc: str
    os_type: str
    architecture: str
    image_type: str
    compression: str
    name: str


class MTDPartitionResponse(BaseModel):
    name: str
    offset: int | None
    size: int


class FirmwareMetadataResponse(BaseModel):
    file_size: int
    sections: list[FirmwareSectionResponse] = []
    uboot_header: UBootHeaderResponse | None = None
    uboot_env: dict[str, str] = {}
    mtd_partitions: list[MTDPartitionResponse] = []
