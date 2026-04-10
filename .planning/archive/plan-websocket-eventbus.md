# Plan: WebSocket/SSE Event Bus (5.6) -- COMPLETED

**Priority:** Medium | **Effort:** Small-Medium | **Status:** completed (2026-04-06, session 11)

## Summary

SSE-based real-time event push implemented. Frontend polling replaced with EventSource connections. Redis pub/sub backbone delivers events from backend services to connected browsers.

This plan is retained for reference. No further work needed.

## What Was Delivered

### Backend
- `routers/events.py` -- SSE endpoint at `GET /api/v1/projects/{project_id}/events`
- `services/event_service.py` -- Redis pub/sub event publishing
- Events published for: unpacking, emulation, fuzzing, device acquisition, assessment, VulHunt
- Keepalive ping every 15 seconds to prevent proxy/browser timeouts
- Event type filtering via `?types=unpacking,emulation` query parameter

### Frontend
- `hooks/useEventStream.ts` -- React hook wrapping native EventSource API
- EmulationPage, FuzzingPage, ProjectDetailPage all consume SSE events
- Polling reduced to 5-10s fallback (for reconnection resilience)
- TypeScript event payload types

## Architecture Notes

**Why SSE (not WebSocket):**
- Data flows server->client only (status updates, progress notifications)
- SSE auto-reconnects natively (EventSource API handles reconnection)
- Works through HTTP proxies without upgrade negotiation
- Simpler than WebSocket for unidirectional data
- WebSocket already used separately for terminal proxy (`routers/terminal.py`) where bidirectional is needed

**Event Types:**
- `unpacking` -- firmware extraction progress/completion
- `emulation` -- emulation session status changes
- `fuzzing` -- fuzzing campaign statistics updates
- `device` -- device acquisition bridge status
- `assessment` -- security assessment phase progress
- `vulhunt` -- VulHunt sidecar scan progress

**Redis Pub/Sub Channel Pattern:** `project:{project_id}:events`

## Key Files

- `backend/app/routers/events.py` -- SSE endpoint
- `backend/app/services/event_service.py` -- Redis pub/sub publisher
- `frontend/src/hooks/useEventStream.ts` -- React EventSource hook
- `frontend/src/pages/EmulationPage.tsx` (uses useEventStream)
- `frontend/src/pages/FuzzingPage.tsx` (uses useEventStream)
- `frontend/src/pages/ProjectDetailPage.tsx` (uses useEventStream)

## Future Improvements (not planned)

- **Event replay:** Store last N events in Redis for clients that reconnect (currently they miss events during disconnection)
- **Typed event schemas:** Generate TypeScript types from Pydantic event schemas (currently manually maintained)
- **Event batching:** Coalesce rapid-fire events (e.g., 10 fuzzing stats updates/second) into batched updates
- **Microsoft fetch-event-source:** Replace native EventSource if POST-with-payload SSE is ever needed (native EventSource only supports GET)
