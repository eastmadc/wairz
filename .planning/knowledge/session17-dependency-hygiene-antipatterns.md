# Anti-patterns: Session 17 — Dependency Hygiene

> Extracted: 2026-04-07
> Campaigns: UEFI Firmware Support (completed)

## Failed Patterns

### 1. Adding Tool Code Without Declaring Dependency
- **What was done:** Android APK analysis tools (android.py, androguard_service.py) were implemented with full handler code, service layer, and REST whitelist — but androguard was never added to pyproject.toml.
- **Failure mode:** Tool registered and appeared in UI, but returned "Androguard is not installed" every time. Silent feature breakage.
- **Evidence:** Session 17 — user reported analyze_apk failing. Three packages total were missing (androguard, lz4, setools).
- **How to avoid:** When adding a new tool that imports a third-party package, add the package to pyproject.toml in the same commit. Run the tool end-to-end in Docker before marking it done.

### 2. Using `docker compose restart` After Image Changes
- **What was done:** Rebuilt the Docker image with new dependencies, then ran `docker compose restart backend`.
- **Failure mode:** Container restarted with the OLD image. New dependency was not available.
- **Evidence:** Session 17 — androguard import failed after restart, only succeeded after `docker compose up -d`.
- **How to avoid:** Always use `docker compose up -d <service>` (not `restart`) after building new images. `restart` only restarts the existing container; `up -d` recreates it with the latest image.

### 3. Installing apt Python Packages for a Different Python Version
- **What was done:** Added `python3-setools` via apt in Dockerfile, expecting it to be available in the Python 3.12 uv venv.
- **Failure mode:** Package installed for system Python 3.13 (Debian Trixie), invisible to the 3.12 venv. Compiled .so extensions are version-specific.
- **Evidence:** `dpkg -L python3-setools` showed files in `/usr/lib/python3/dist-packages/` but `import setools` failed in venv.
- **How to avoid:** Only use apt Python packages if: (a) the app uses system Python, or (b) the package is pure Python and you symlink it. For compiled packages, build from source against the correct Python or accept graceful degradation.

### 4. bg-transparent on Native Select Elements in Dark Theme
- **What was done:** Used Tailwind `bg-transparent` on a `<select>` element with no explicit colors on `<option>` elements.
- **Failure mode:** Browser renders native `<option>` dropdown with OS default white background, but text color was inherited from dark theme (white/light). Result: white text on white background.
- **Evidence:** Session 17 — user reported "white background with white text, yuck" on Export SBOM format dropdown.
- **How to avoid:** Always use `bg-background text-foreground` (not `bg-transparent`) on `<select>` elements, and add the same classes to `<option>` elements for dark theme compatibility.
