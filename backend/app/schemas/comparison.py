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
    hash_a: str | None = None
    hash_b: str | None = None


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
    hash_a: str | None = None
    hash_b: str | None = None
    addr_a: int | None = None
    addr_b: int | None = None


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
    sections_a: list[dict] = []
    sections_b: list[dict] = []
    sections_changed: list[dict] = []
    imports_added: list[str] = []
    imports_removed: list[str] = []
    exports_added: list[str] = []
    exports_removed: list[str] = []
    basic_block_stats: dict | None = None


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


class InstructionDiffRequest(BaseModel):
    firmware_a_id: uuid.UUID
    firmware_b_id: uuid.UUID
    binary_path: str
    function_name: str


class InstructionDiffResponse(BaseModel):
    function_name: str
    arch: str = ""
    diff_text: str = ""
    lines_added: int = 0
    lines_removed: int = 0
    error: str | None = None


class DecompilationDiffRequest(BaseModel):
    firmware_a_id: uuid.UUID
    firmware_b_id: uuid.UUID
    binary_path: str
    function_name: str
    context_lines: int = 5


class DecompilationDiffResponse(BaseModel):
    function_name: str
    binary_path: str
    source_a: str = ""
    source_b: str = ""
    diff_text: str = ""
    lines_added: int = 0
    lines_removed: int = 0
    error: str | None = None
