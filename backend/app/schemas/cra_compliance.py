import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class CraStatus(str, Enum):
    in_progress = "in_progress"
    complete = "complete"
    exported = "exported"


class RequirementStatus(str, Enum):
    pass_ = "pass"
    fail = "fail"
    partial = "partial"
    not_tested = "not_tested"
    not_applicable = "not_applicable"


class CraAssessmentCreate(BaseModel):
    product_name: str | None = None
    product_version: str | None = None
    assessor_name: str | None = None
    firmware_id: uuid.UUID | None = None


class CraRequirementUpdate(BaseModel):
    status: RequirementStatus | None = None
    manual_notes: str | None = None
    manual_evidence: str | None = None


class CraRequirementResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    assessment_id: uuid.UUID
    requirement_id: str
    requirement_title: str
    annex_part: int
    status: str
    auto_populated: bool
    evidence_summary: str | None
    finding_ids: list = Field(default_factory=list)
    tool_sources: list = Field(default_factory=list)
    manual_notes: str | None
    manual_evidence: str | None
    related_cwes: list = Field(default_factory=list)
    related_cves: list = Field(default_factory=list)
    assessed_at: datetime | None
    updated_at: datetime


class CraAssessmentResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    project_id: uuid.UUID
    firmware_id: uuid.UUID | None
    assessor_name: str | None
    product_name: str | None
    product_version: str | None
    overall_status: str
    auto_pass_count: int
    auto_fail_count: int
    manual_count: int
    not_tested_count: int
    created_at: datetime
    updated_at: datetime
    requirement_results: list[CraRequirementResponse] = Field(default_factory=list)


class CraAssessmentListResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    project_id: uuid.UUID
    firmware_id: uuid.UUID | None
    assessor_name: str | None
    product_name: str | None
    product_version: str | None
    overall_status: str
    auto_pass_count: int
    auto_fail_count: int
    manual_count: int
    not_tested_count: int
    created_at: datetime
    updated_at: datetime


class Article14Notification(BaseModel):
    notification_type: str = "actively_exploited_vulnerability"
    product: dict = Field(default_factory=dict)
    vulnerability: dict = Field(default_factory=dict)
    timeline: dict = Field(default_factory=dict)
    mitigation: dict = Field(default_factory=dict)
    contact: dict = Field(default_factory=dict)
