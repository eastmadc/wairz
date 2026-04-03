"""Pydantic schemas for firmware comparison endpoints."""

import uuid

from pydantic import BaseModel


class FirmwareDiffRequest(BaseModel):
    firmware_a_id: uuid.UUID
    firmware_b_id: uuid.UUID


class BinaryDiffRequest(BaseModel):
    firmware_a_id: uuid.UUID
    firmware_b_id: uuid.UUID
    binary_path: str


class FileDiffEntryResponse(BaseModel):
    path: str
    status: str
    size_a: int | None = None
    size_b: int | None = None
    perms_a: str | None = None
    perms_b: str | None = None


class FirmwareDiffResponse(BaseModel):
    added: list[FileDiffEntryResponse] = []
    removed: list[FileDiffEntryResponse] = []
    modified: list[FileDiffEntryResponse] = []
    permissions_changed: list[FileDiffEntryResponse] = []
    total_files_a: int = 0
    total_files_b: int = 0
    truncated: bool = False


class FunctionDiffEntryResponse(BaseModel):
    name: str
    status: str
    size_a: int | None = None
    size_b: int | None = None


class BinaryInfoResponse(BaseModel):
    file_size: int = 0
    arch: str | None = None
    bits: int | None = None
    endian: str | None = None


class BinaryDiffResponse(BaseModel):
    binary_path: str
    functions_added: list[FunctionDiffEntryResponse] = []
    functions_removed: list[FunctionDiffEntryResponse] = []
    functions_modified: list[FunctionDiffEntryResponse] = []
    info_a: dict = {}
    info_b: dict = {}


class TextDiffRequest(BaseModel):
    firmware_a_id: uuid.UUID
    firmware_b_id: uuid.UUID
    file_path: str


class TextDiffResponse(BaseModel):
    path: str
    diff: str
    lines_added: int = 0
    lines_removed: int = 0
    truncated: bool = False
    error: str | None = None
