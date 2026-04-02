"""Pydantic schemas for device acquisition endpoints."""

from pydantic import BaseModel, ConfigDict, Field


class DeviceInfo(BaseModel):
    serial: str
    model: str | None = None
    device: str | None = None
    transport_id: str | None = None
    state: str = "device"


class DeviceBridgeStatus(BaseModel):
    connected: bool
    bridge_host: str | None = None
    bridge_port: int | None = None
    error: str | None = None


class DeviceListResponse(BaseModel):
    devices: list[DeviceInfo]


class PartitionInfo(BaseModel):
    name: str
    size: int | None = None


class DeviceDetailResponse(BaseModel):
    device: DeviceInfo
    getprop: dict[str, str] = {}
    partitions: list[str] = []
    partition_sizes: list[PartitionInfo] = []
    device_metadata: dict | None = None


class DumpPartitionRequest(BaseModel):
    device_id: str = Field(..., description="ADB serial number")
    partitions: list[str] = Field(..., min_length=1, description="Partition names to dump")


class DumpPartitionStatus(BaseModel):
    partition: str
    status: str  # pending, active, complete, failed, skipped
    bytes_written: int = 0
    total_bytes: int | None = None
    progress_percent: float | None = None
    throughput_mbps: float | None = None
    size: int | None = None
    error: str | None = None
    path: str | None = None


class DumpStatusResponse(BaseModel):
    status: str  # idle, dumping, complete, failed
    device_id: str | None = None
    partitions: list[DumpPartitionStatus] = []
    error: str | None = None


class DumpImportRequest(BaseModel):
    device_id: str = Field(..., description="ADB serial number")
    version_label: str | None = None


class DumpImportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    firmware_id: str
    device_metadata: dict | None = None
    message: str
