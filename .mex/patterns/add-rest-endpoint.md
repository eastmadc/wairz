---
name: add-rest-endpoint
description: Add a new FastAPI REST endpoint under /api/v1/projects/{project_id}/... with service, schema, and router wiring.
triggers:
  - "add endpoint"
  - "new endpoint"
  - "add route"
  - "new router"
  - "rest api"
edges:
  - target: context/architecture.md
    condition: to understand the router → service → model layering
  - target: context/conventions.md
    condition: for router/service naming, schemas-in-schemas/, `_endpoint` suffix rules
  - target: patterns/docker-rebuild-backend-worker.md
    condition: after code changes, to correctly rebuild backend + worker
last_updated: 2026-04-17
---

# Add REST Endpoint

## Context
Read `context/architecture.md` + `context/conventions.md`. Routers are thin; all logic lives in a service. Pydantic schemas live in `app/schemas/`, never inline in routers.

## Steps

1. Create or extend `backend/app/schemas/<resource>.py` with the request/response models:
   ```python
   from pydantic import BaseModel, ConfigDict

   class MyResourceCreate(BaseModel):
       name: str

   class MyResourceResponse(BaseModel):
       model_config = ConfigDict(from_attributes=True)
       id: uuid.UUID
       name: str
   ```

2. If new, create `backend/app/models/<resource>.py` with the SQLAlchemy model. UUID PK with dual defaults:
   ```python
   id: Mapped[uuid.UUID] = mapped_column(
       primary_key=True, default=uuid.uuid4, server_default=func.gen_random_uuid()
   )
   ```
   Then generate a migration: `docker compose exec backend alembic revision --autogenerate -m "add <resource>"`.

3. Create or extend `backend/app/services/<resource>_service.py` with the business logic. Async functions taking an `AsyncSession`.

4. Create or extend `backend/app/routers/<resource>.py`:
   ```python
   router = APIRouter(prefix="/api/v1/projects/{project_id}/<resource>", tags=["<resource>"])

   @router.post("", response_model=MyResourceResponse, status_code=201)
   async def create_my_resource_endpoint(  # _endpoint suffix if name collides with service
       project_id: uuid.UUID,
       data: MyResourceCreate,
       db: AsyncSession = Depends(get_db),
   ):
       return await my_service.create(db, project_id=project_id, data=data)
   ```

5. Register in `backend/app/main.py`: add the import and `app.include_router(<resource>.router)`.

6. Add a frontend client at `frontend/src/api/<resource>.ts` that wraps the Axios instance from `src/api/client.ts`.

7. If the response enum has new values, update every `Record<SourceType, ...>` in `frontend/src/` (Learned Rule #9).

8. Rebuild both: `docker compose up -d --build backend worker`. Verify `curl http://localhost:8000/docs`.

## Gotchas

- **Name collision with service function:** Python rebinds. Add `_endpoint` suffix to the router function (Learned Rule #10).
- **Inline Pydantic models in the router file:** forward-reference issues with ORM relationships; violates convention (Learned Rule #12). Always use `app/schemas/`.
- **Response schema mismatch:** missing / extra fields vs the ORM model cause silent 500s (Learned Rule #4). Read the schema, construct the return dict to match.
- **Forgot `from_attributes=True`:** `response_model=...` can't map from an ORM row.
- **Did not regenerate migration** after adding a model: container startup fails on next boot.
- **Did not rebuild worker:** Alembic may not find the new revision; background jobs silently stall (Learned Rule #8).
- **Path traversal:** if the endpoint accepts a file path inside firmware, validate via `app/utils/sandbox.py::validate_path`. Never `os.path.join(extracted_path, user_input)`.

## Verify

- [ ] `backend/app/main.py` imports and includes the router.
- [ ] Pydantic schemas live under `app/schemas/`, nothing inline in the router.
- [ ] Router endpoint function is suffixed `_endpoint` if it shares a name with an imported service function.
- [ ] Response schema fields match the ORM model exactly.
- [ ] Alembic migration exists if a model was added; applied on next worker boot.
- [ ] `docker compose up -d --build backend worker` ran (both, not just one).
- [ ] `curl http://localhost:8000/docs` shows the new route.
- [ ] Frontend client added if the UI will call it.

## Debug

- **500 on call:** schema/model mismatch. Run `docker compose logs backend` and compare the exception to the Pydantic model.
- **404 but route should exist:** check `app/main.py` include_router and FastAPI's `/docs`.
- **Route 404s only inside Docker:** backend image is stale; rebuild with `--build`.
- **Frontend calls fail CORS:** confirm `CORS_ORIGINS` includes the frontend origin.

## Update Scaffold
- [ ] Update `.mex/ROUTER.md` "Current Project State" if a new user-facing capability landed.
- [ ] If a new resource introduced domain depth (e.g. payments, auth, complex workflow), consider a new `context/<domain>.md`.
