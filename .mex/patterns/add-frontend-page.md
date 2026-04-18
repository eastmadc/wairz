---
name: add-frontend-page
description: Add a new React page under /projects/:projectId/... with Zustand state, Axios client, and polling for long-running backend ops.
triggers:
  - "add page"
  - "new page"
  - "new route"
  - "frontend"
  - "react page"
edges:
  - target: context/stack.md
    condition: for React 19, Vite, Zustand, shadcn/ui, react-router-dom v7 conventions
  - target: context/conventions.md
    condition: for frontend structure (pages vs components vs api vs stores) and Record<> exhaustiveness
  - target: patterns/add-rest-endpoint.md
    condition: when the page needs a new backend endpoint to call
last_updated: 2026-04-17
---

# Add Frontend Page

## Context
Frontend is React 19 + TypeScript 5.9 + Vite 6. Pages live in `frontend/src/pages/`, API clients in `frontend/src/api/`, Zustand stores in `frontend/src/stores/`. Long-running backend ops are driven by `useEffect + setInterval` polling (2s), canonical examples: `EmulationPage.tsx`, `FuzzingPage.tsx`, `ProjectDetailPage.tsx`.

## Steps

1. Create `frontend/src/pages/MyFeaturePage.tsx`:
   ```tsx
   import { useParams } from "react-router-dom";

   export default function MyFeaturePage() {
     const { projectId } = useParams<{ projectId: string }>();
     // ...
     return <div>...</div>;
   }
   ```

2. Register the route in `frontend/src/App.tsx` — add a `<Route path="projects/:projectId/myfeature" element={<MyFeaturePage />} />` (or the pattern already used in the file).

3. Create `frontend/src/api/myFeature.ts` that wraps the Axios instance from `src/api/client.ts`. Do NOT create a new Axios instance per file.

4. If the page needs shared state across components or pages, add a Zustand store at `frontend/src/stores/myFeatureStore.ts` mirroring `projectStore.ts` / `explorerStore.ts`.

5. For long-running ops (backend status that changes over time):
   ```tsx
   useEffect(() => {
     const tick = async () => { /* fetch + setState */ };
     tick();
     const h = setInterval(tick, 2000);
     return () => clearInterval(h);
   }, [projectId]);
   ```
   Clean up on unmount. Some features (emulation, events) publish SSE via the Redis event bus — prefer that when available, fall back to polling if Redis is down.

6. Types live in `frontend/src/types/`. If the backend has a new enum/source, update every `Record<{TypeName}, ...>` map — TypeScript will NOT error on missing keys at runtime, but lookups return `undefined` and crash the page (Learned Rule #9). Add `?? fallback` defensively.

7. Lint + typecheck: `cd frontend && npm run lint && npm run build`.

## Gotchas

- **Blank page after a backend enum change:** a `Record<SourceType, Config>` map doesn't include the new value. Grep `Record<` across `frontend/src/` and add the key.
- **Double fetch / stale state:** forgotten cleanup in `useEffect` polling. Return the clearInterval.
- **SSE leak:** forgetting to `EventSource.close()` in cleanup. Several pages have had this bug (see recent commit 197a920 "12 frontend bug fixes").
- **Shared Axios misuse:** a new file creating its own `axios.create()` bypasses the auth header interceptor. Always import the client.
- **Large lists:** if the page shows >1000 items (files, findings, components), use `react-arborist` (virtual tree) or list virtualization — firmware has 10K+ file nodes.
- **Route typo:** React Router v7 uses outlet-nesting; match the pattern in `App.tsx` exactly.

## Verify

- [ ] `App.tsx` registers the new route.
- [ ] API calls go through `src/api/<name>.ts`, not inline Axios.
- [ ] No new `axios.create()` calls; all use `src/api/client.ts`.
- [ ] `useEffect` intervals are cleared on unmount; `EventSource`s are closed.
- [ ] Every `Record<UnionType, ...>` referenced is exhaustive for current backend values.
- [ ] `npm run build` (includes `tsc -b`) passes with no errors.
- [ ] `npm run lint` passes.
- [ ] Playwright spec added if the page has a user flow (see `frontend/tests`).

## Debug

- **`undefined is not an object` at runtime:** a `Record<>` lookup returned `undefined`. Add `?? fallback`.
- **Polling never stops after navigation away:** missing cleanup in `useEffect`.
- **Data never updates despite backend change:** stale store; check you used the Zustand selector (`useStore(s => s.data)`), not captured state at mount.

## Update Scaffold
- [ ] If the feature required a new backend integration (new SSE channel, new long-running op pattern), note it in `context/architecture.md`.
- [ ] Update `.mex/ROUTER.md` "Current Project State" if this adds a major user-facing page.
