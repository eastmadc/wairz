# Anti-patterns: Docker Image Optimization

> Extracted: 2026-04-14
> Campaign: .planning/campaigns/completed/docker-image-optimization.md

## Failed Patterns

### 1. JDK-to-JRE without verifying tool requirements
- **What was done:** Changed `openjdk-21-jdk-headless` to `openjdk-21-jre-headless` and `eclipse-temurin:17-jdk-jammy` to `eclipse-temurin:17-jre-jammy`, assuming Ghidra only needs a runtime.
- **Failure mode:** Ghidra's `launch.sh` explicitly requires a JDK (passes `jdk` as the java-type parameter). `analyzeHeadless` fails at startup with "Unable to prompt user for JDK path".
- **Evidence:** Decision Log #1 — tested and reverted in Phase 1
- **How to avoid:** Before switching JDK→JRE, check the tool's launch scripts for JDK requirements. For Ghidra specifically: `grep -i jdk /opt/ghidra/support/launch.properties` shows "Ghidra requires a JDK to launch."

### 2. Trusting Dockerfile comments over runtime verification
- **What was done:** The UEFIExtract build block had a comment: "cmake/qt6 are kept because purging them removes shared libs UEFIExtract needs." This was accepted without verification for multiple sessions.
- **Failure mode:** The comment was wrong. `ldd /usr/local/bin/UEFIExtract` shows no Qt dependencies. ~400 MB of cmake+qt6 packages were carried in the final image unnecessarily.
- **Evidence:** Decision Log #2 — verified with ldd, then safely multi-staged
- **How to avoid:** Always verify Dockerfile comments about runtime dependencies with `ldd <binary>` before accepting them as truth. Comments rot faster than code.

### 3. Removing build tools without checking downstream consumers
- **What was done:** Moved cmake+qt6 to a builder stage for UEFIExtract, removing cmake from the final image. Did not check what else in the Dockerfile depended on cmake.
- **Failure mode:** `keystone-engine` (installed later via pip with `--no-binary :all:`) requires cmake for its source build. Qiling installation silently failed.
- **Evidence:** Phase 2 build output showed "WARN: Qiling install failed" — caught during verification
- **How to avoid:** Before removing any build tool from a Dockerfile, grep the entire file for other consumers. For cmake specifically: any `pip install --no-binary :all:` package that uses CMakeLists.txt will need it.
