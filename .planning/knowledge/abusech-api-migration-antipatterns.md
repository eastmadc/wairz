# Anti-patterns: abuse.ch API Migration Fix (Session Debugging)

> Extracted: 2026-04-13
> Source: debugging session — not a formal campaign

## Failed Patterns

### 1. Assuming public APIs stay public forever
- **What was done:** Original code documented "Works without an API key" and had no fallback for when auth becomes required.
- **Failure mode:** All MalwareBazaar and ThreatFox lookups silently returned zero results for months (401 errors caught and swallowed).
- **Evidence:** Docstrings said "No API key required", but APIs now return 401 without Auth-Key header.
- **How to avoid:** For external API integrations, log the actual HTTP status code at WARNING level (not just swallow errors). Add periodic health checks or at minimum log "0 results from N lookups" as a signal that something is wrong.

### 2. Wrong auth mechanism for MalwareBazaar
- **What was done:** Auth key was sent as a form field (`data["api_key"] = key`) instead of the `Auth-Key` HTTP header.
- **Failure mode:** Even with a valid key, MalwareBazaar would have returned 401 because it expects the header format.
- **Evidence:** Testing with `headers={"Auth-Key": key}` returned 403 "unknown_auth_key" (correct rejection of test key), while form field returned 401 regardless.
- **How to avoid:** When integrating with an API, verify the auth mechanism by testing with an intentionally wrong key — a 403 "invalid key" proves the auth channel is correct; a 401 "unauthorized" means the auth isn't being received at all.

### 3. Not following redirects / not validating endpoint liveness
- **What was done:** YARAify v2 GET endpoint was deprecated and returns 301 → HTML docs page. httpx doesn't follow redirects by default, so code got 301 and returned empty results.
- **Failure mode:** Silent failure — no YARA rule matches ever returned.
- **Evidence:** `httpx.get()` returned 301, Location header pointed to `https://yaraify.abuse.ch/api/` (HTML page, not JSON API).
- **How to avoid:** When an API returns 301, don't just follow the redirect — the redirect target may not be a compatible endpoint (in this case it was an HTML docs page). Instead, check if the API has a new version/endpoint.
