# Anti-patterns: x86_64 Multi-Platform Deployment (Session 33)

> Extracted: 2026-04-13
> Source: Session work — deploying Wairz stack from ARM64 Kali to x86_64 Ubuntu VM

## Failed Patterns

### 1. Assuming pip Package Provides CLI Binary
- **What was done:** `pip3 install binwalk3` was the only binwalk installation step in the Dockerfile. The assumption was that the pip package provides the `binwalk3` CLI.
- **Failure mode:** The binwalk3 pip package (`binwalk3==3.1.3`) only ships a Windows `.exe` binary in its `binwalk_bin/` directory. On Linux, the Python bindings fall back to searching PATH for `binwalk3` or `binwalk`, which didn't exist. The unpack pipeline silently fell through to unblob.
- **Evidence:** `binwalk3 failed: [Errno 2] No such file or directory: 'binwalk3'` in unpack log. Worker completed but with degraded extraction.
- **How to avoid:** When a Python package wraps a native binary, always verify the binary is actually installed by running `which <binary>` or `<binary> --version` in the container. For binwalk3 specifically: the Rust CLI must be built from source on Linux.

### 2. Silent Fallback Masking Missing Tools
- **What was done:** The Dockerfile RUN step used `|| echo "WARN: ..."` which catches the Rust build failure silently. The image builds "successfully" but the binary is missing.
- **Failure mode:** Docker build reports success. The missing tool is only discovered at runtime when a user uploads firmware and the unpack log shows the fallback path was taken.
- **Evidence:** First build completed without error, but `binwalk3` was absent. Only discovered when checking the unpack log for the test firmware.
- **How to avoid:** After any tool installation step that uses `|| echo "WARN"`, add a verification step that checks the binary exists and is executable. Consider whether a missing tool should be a build failure or a warning — for critical tools, remove the fallback.

### 3. Missing Build Dependencies for Rust Crates
- **What was done:** Added Rust toolchain + cargo build for binwalk3, but only installed `build-essential` and `git` (already present in the base image). Missing `pkg-config` and `libfontconfig1-dev`.
- **Failure mode:** Rust build panicked at `yeslogic-fontconfig-sys` crate: "Could not run `pkg-config --libs --cflags fontconfig`". The entire cargo build failed due to a transitive dependency on fontconfig for image rendering support.
- **Evidence:** `thread 'main' panicked at yeslogic-fontconfig-sys-6.0.0/build.rs` in the build output.
- **How to avoid:** When adding a Rust project to a Dockerfile, first test the build in an isolated container matching the base image (`docker run --rm python:3.12-slim bash -c '...'`). Rust crates with `-sys` suffixes typically require system library development packages.

### 4. Cache Invalidation from Mid-Dockerfile Insertion
- **What was done:** Inserted the binwalk3 Rust build step early in the Dockerfile (after the system deps, before Ghidra). This invalidated ALL subsequent layers.
- **Failure mode:** The rebuild had to re-download Ghidra (~550MB), re-compile UEFIExtract, re-install all pip packages, and re-compile keystone-engine from source. Total rebuild took ~10 minutes instead of ~1 minute if the step had been placed later.
- **Evidence:** Build cache dropped from 4.3GB to 472MB after the insertion. Every step after the binwalk3 layer needed to be rebuilt.
- **How to avoid:** When adding new build steps to an existing Dockerfile, place them as late as possible in the layer order to maximize cache reuse. If a tool is independent of later steps, consider a multi-stage build where it's built in a separate stage and COPY'd in.
