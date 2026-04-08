import uuid
from datetime import datetime

from pydantic import BaseModel


class AttackSurfaceEntryResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    project_id: uuid.UUID
    firmware_id: uuid.UUID
    binary_path: str
    binary_name: str
    architecture: str | None = None
    file_size: int | None = None
    attack_surface_score: int
    score_breakdown: dict = {}
    is_setuid: bool = False
    is_network_listener: bool = False
    is_cgi_handler: bool = False
    has_dangerous_imports: bool = False
    dangerous_imports: list = []
    input_categories: list = []
    auto_findings_generated: bool = False
    created_at: datetime


class AttackSurfaceScanRequest(BaseModel):
    path: str | None = None
    force_rescan: bool = False


class AttackSurfaceSummary(BaseModel):
    total_binaries: int = 0
    critical_count: int = 0  # score >= 75
    high_count: int = 0      # score >= 50
    medium_count: int = 0    # score >= 25
    low_count: int = 0       # score < 25
    top_categories: list[str] = []


class AttackSurfaceScanResponse(BaseModel):
    entries: list[AttackSurfaceEntryResponse]
    summary: AttackSurfaceSummary
    cached: bool = False
