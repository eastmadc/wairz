# Patterns: Comparison Export Feature (Session 37)

> Extracted: 2026-04-14
> Campaign: none (in-session feature addition)
> Postmortem: none

## Successful Patterns

### 1. Client-side JSON export for already-loaded data
- **Description:** When comparison results are already in React state (`fsDiff`, `binDiff`, `textDiff`), export them directly as a JSON blob from the browser. No backend endpoint needed — avoids re-running expensive diff computations.
- **Evidence:** Implemented in ComparisonPage.tsx `handleDownloadReport()` — uses `Blob` + `URL.createObjectURL` + programmatic `<a>` click
- **Applies when:** Any page that displays computed results the user might want to save. If the data is already in state, export client-side. Only add a backend export endpoint when the data needs server-side generation (e.g., SBOM export needs format conversion).

### 2. Incremental report composition
- **Description:** The export includes whatever diff data has been loaded so far — filesystem diff always, binary diff and text diff only if the user drilled into them. Uses spread with conditional inclusion: `...(binDiff ? { binary_diff: binDiff } : {})`.
- **Evidence:** ComparisonPage.tsx — report object conditionally includes `binary_diff` and `text_diff` only when present
- **Applies when:** Export features where the user may have explored different levels of detail. Include what they've seen rather than forcing a full computation.

### 3. Filename from data context, not IDs
- **Description:** Download filename uses firmware filenames stripped of extension (`comparison-DPCS10_260403-1601-vs-DPCS10_260413-1709.json`) rather than UUIDs. Falls back to truncated UUID if filename unavailable.
- **Evidence:** `handleDownloadReport()` uses `fwALabel?.original_filename?.replace(/\.[^.]+$/, '')`
- **Applies when:** Any file download — use human-readable context in filenames, not opaque IDs

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Client-side export, no backend endpoint | Data already in browser state; avoids re-running 5-minute diff computation | Clean, fast, zero backend changes |
| JSON format only (no CSV) | Comparison data is hierarchical (nested diffs, function lists) — CSV would lose structure | Appropriate for the data shape |
| Button appears only after results load | No point showing export before comparison runs | Clean UX — `{fsDiff && <Button>}` conditional |
