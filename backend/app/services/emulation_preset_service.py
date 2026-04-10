"""Service for managing emulation preset CRUD operations.

Extracted from emulation_service.py to reduce file size.
"""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.emulation_preset import EmulationPreset


class EmulationPresetService:
    """Manages emulation preset CRUD operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_preset(
        self,
        project_id: UUID,
        name: str,
        mode: str,
        description: str | None = None,
        binary_path: str | None = None,
        arguments: str | None = None,
        architecture: str | None = None,
        port_forwards: list[dict] | None = None,
        kernel_name: str | None = None,
        init_path: str | None = None,
        pre_init_script: str | None = None,
        stub_profile: str = "none",
    ) -> EmulationPreset:
        """Create a new emulation preset for a project."""
        preset = EmulationPreset(
            project_id=project_id,
            name=name,
            description=description,
            mode=mode,
            binary_path=binary_path,
            arguments=arguments,
            architecture=architecture,
            port_forwards=port_forwards or [],
            kernel_name=kernel_name,
            init_path=init_path,
            pre_init_script=pre_init_script,
            stub_profile=stub_profile,
        )
        self.db.add(preset)
        await self.db.flush()
        return preset

    async def list_presets(self, project_id: UUID) -> list[EmulationPreset]:
        """List all emulation presets for a project."""
        result = await self.db.execute(
            select(EmulationPreset)
            .where(EmulationPreset.project_id == project_id)
            .order_by(EmulationPreset.created_at.desc())
        )
        return list(result.scalars().all())

    async def get_preset(self, preset_id: UUID) -> EmulationPreset:
        """Get a single emulation preset by ID."""
        result = await self.db.execute(
            select(EmulationPreset).where(EmulationPreset.id == preset_id)
        )
        preset = result.scalar_one_or_none()
        if not preset:
            raise ValueError("Preset not found")
        return preset

    async def update_preset(
        self, preset_id: UUID, updates: dict
    ) -> EmulationPreset:
        """Update an existing emulation preset."""
        preset = await self.get_preset(preset_id)
        for key, value in updates.items():
            if value is not None and hasattr(preset, key):
                setattr(preset, key, value)
        await self.db.flush()
        return preset

    async def delete_preset(self, preset_id: UUID) -> None:
        """Delete an emulation preset."""
        preset = await self.get_preset(preset_id)
        await self.db.delete(preset)
        await self.db.flush()
