"""Tests for shared FastAPI router dependencies."""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.models.firmware import Firmware
from app.routers.deps import resolve_firmware


def _make_firmware(
    firmware_id: uuid.UUID | None = None,
    project_id: uuid.UUID | None = None,
    extracted_path: str | None = "/extracted/root",
) -> Firmware:
    """Create a Firmware ORM object with sensible defaults for testing."""
    fw = MagicMock(spec=Firmware)
    fw.id = firmware_id or uuid.uuid4()
    fw.project_id = project_id or uuid.uuid4()
    fw.extracted_path = extracted_path
    return fw


class TestResolveFirmware:
    """Tests for the resolve_firmware dependency."""

    @pytest.fixture
    def mock_db(self):
        return AsyncMock()

    async def test_returns_firmware_by_id(self, mock_db):
        """When firmware_id is provided and matches project, firmware is returned."""
        project_id = uuid.uuid4()
        firmware_id = uuid.uuid4()
        fw = _make_firmware(firmware_id=firmware_id, project_id=project_id)

        with patch("app.routers.deps.FirmwareService") as MockSvc:
            instance = MockSvc.return_value
            instance.get_by_id = AsyncMock(return_value=fw)

            result = await resolve_firmware(
                project_id=project_id,
                firmware_id=firmware_id,
                db=mock_db,
            )

        assert result is fw
        instance.get_by_id.assert_awaited_once_with(firmware_id)

    async def test_returns_firmware_by_project(self, mock_db):
        """When firmware_id is None, falls back to get_by_project."""
        project_id = uuid.uuid4()
        fw = _make_firmware(project_id=project_id)

        with patch("app.routers.deps.FirmwareService") as MockSvc:
            instance = MockSvc.return_value
            instance.get_by_project = AsyncMock(return_value=fw)

            result = await resolve_firmware(
                project_id=project_id,
                firmware_id=None,
                db=mock_db,
            )

        assert result is fw
        instance.get_by_project.assert_awaited_once_with(project_id)

    async def test_404_when_firmware_id_not_found(self, mock_db):
        """When get_by_id returns None, raises 404."""
        with patch("app.routers.deps.FirmwareService") as MockSvc:
            instance = MockSvc.return_value
            instance.get_by_id = AsyncMock(return_value=None)

            with pytest.raises(HTTPException) as exc_info:
                await resolve_firmware(
                    project_id=uuid.uuid4(),
                    firmware_id=uuid.uuid4(),
                    db=mock_db,
                )

        assert exc_info.value.status_code == 404
        assert "Firmware not found" in exc_info.value.detail

    async def test_404_when_firmware_belongs_to_different_project(self, mock_db):
        """When firmware exists but belongs to a different project, raises 404."""
        project_id = uuid.uuid4()
        other_project_id = uuid.uuid4()
        firmware_id = uuid.uuid4()
        fw = _make_firmware(firmware_id=firmware_id, project_id=other_project_id)

        with patch("app.routers.deps.FirmwareService") as MockSvc:
            instance = MockSvc.return_value
            instance.get_by_id = AsyncMock(return_value=fw)

            with pytest.raises(HTTPException) as exc_info:
                await resolve_firmware(
                    project_id=project_id,
                    firmware_id=firmware_id,
                    db=mock_db,
                )

        assert exc_info.value.status_code == 404
        assert "Firmware not found" in exc_info.value.detail

    async def test_404_when_no_firmware_for_project(self, mock_db):
        """When no firmware_id given and project has no firmware, raises 404."""
        with patch("app.routers.deps.FirmwareService") as MockSvc:
            instance = MockSvc.return_value
            instance.get_by_project = AsyncMock(return_value=None)

            with pytest.raises(HTTPException) as exc_info:
                await resolve_firmware(
                    project_id=uuid.uuid4(),
                    firmware_id=None,
                    db=mock_db,
                )

        assert exc_info.value.status_code == 404
        assert "No firmware uploaded" in exc_info.value.detail

    async def test_400_when_firmware_not_unpacked(self, mock_db):
        """When firmware exists but extracted_path is None, raises 400."""
        project_id = uuid.uuid4()
        firmware_id = uuid.uuid4()
        fw = _make_firmware(
            firmware_id=firmware_id,
            project_id=project_id,
            extracted_path=None,
        )

        with patch("app.routers.deps.FirmwareService") as MockSvc:
            instance = MockSvc.return_value
            instance.get_by_id = AsyncMock(return_value=fw)

            with pytest.raises(HTTPException) as exc_info:
                await resolve_firmware(
                    project_id=project_id,
                    firmware_id=firmware_id,
                    db=mock_db,
                )

        assert exc_info.value.status_code == 400
        assert "not yet unpacked" in exc_info.value.detail

    async def test_400_when_project_firmware_not_unpacked(self, mock_db):
        """When falling back to project lookup and firmware is not unpacked, raises 400."""
        project_id = uuid.uuid4()
        fw = _make_firmware(project_id=project_id, extracted_path=None)

        with patch("app.routers.deps.FirmwareService") as MockSvc:
            instance = MockSvc.return_value
            instance.get_by_project = AsyncMock(return_value=fw)

            with pytest.raises(HTTPException) as exc_info:
                await resolve_firmware(
                    project_id=project_id,
                    firmware_id=None,
                    db=mock_db,
                )

        assert exc_info.value.status_code == 400
        assert "not yet unpacked" in exc_info.value.detail
