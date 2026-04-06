# Plan: WebSocket/SSE Event Bus (5.6) — COMPLETED

**Priority:** Medium | **Effort:** Small-Medium | **Status:** completed (2026-04-06)

## Goal

Replace frontend polling with push notifications for: unpacking progress, emulation status, fuzzing stats, assessment progress.

## Current State

- **SSE endpoint exists**: `GET /api/v1/projects/{project_id}/events` in `routers/events.py`
- **Redis pub/sub already wired**: `EventService` publishes to Redis channels
- **Frontend polls on intervals**:
  - EmulationPage: 2s interval (line 161)
  - FuzzingPage: 5s interval (line 106)
  - ProjectDetailPage: 2s interval (line 91)
- **WebSocket already used** for terminal proxy in `routers/terminal.py`

## Approach: Extend SSE (Not WebSocket)

SSE is simpler and sufficient since data flows server→client only. The existing SSE endpoint + Redis pub/sub backbone just needs:
1. Frontend to consume SSE instead of polling
2. Backend to emit events for all state changes (not just emulation)

## Changes Required

### Backend (~3h)
- Extend `EventService` to publish events for: unpack progress, fuzzing stats, assessment progress
- Add event types to existing SSE endpoint
- Emit events from: `unpack_firmware()`, `FuzzingService`, `AssessmentService`

### Frontend (~4h)
- Create `useEventStream` hook (wraps EventSource API)
- Replace `setInterval` in EmulationPage, FuzzingPage, ProjectDetailPage
- Type event payloads in TypeScript

### Testing (~2h)
- Verify SSE reconnection on disconnect
- Verify event delivery latency vs polling

## Key Files

- `backend/app/routers/events.py` — existing SSE endpoint
- `backend/app/services/event_service.py` — Redis pub/sub
- `frontend/src/pages/EmulationPage.tsx` (replace setInterval)
- `frontend/src/pages/FuzzingPage.tsx` (replace setInterval)
- `frontend/src/pages/ProjectDetailPage.tsx` (replace setInterval)
- New: `frontend/src/hooks/useEventStream.ts`
