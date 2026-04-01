# Known Issues: Vulnerability UI + Data Quality

> Documented: 2026-04-01
> Source: Android firmware SBOM vuln scan (2,106 CVEs)

## Issue 1: Vulnerability list limited to 100 entries
- **Symptom:** Tab shows "2106" but only displays 100 entries
- **Cause:** list_vulnerabilities endpoint has `limit=100` default pagination
- **Fix options:**
  - A) Increase default limit (simple but impacts performance)
  - B) Add pagination controls to the frontend (load more / infinite scroll)
  - C) Add frontend pagination with page numbers
- **Recommended:** B — infinite scroll, loading more as user scrolls

## Issue 2: Noisy CVE matches (Adobe Flash in Android results)
- **Symptom:** Adobe Flash Player CVEs from 2015 appear in Android 15 results
  (e.g., CVE-2015-3105, CVE-2015-3104, CVE-2015-5575)
- **Cause:** Grype's CPE matching is broad — `cpe:2.3:o:google:android:15`
  matches CVEs that have "Android" or "android" anywhere in their CPE/description.
  Flash Player CVEs mention "Android" as a platform but aren't Android OS vulns.
- **Impact:** ~20-30 false positive Flash CVEs inflate the critical/high count
- **Fix options:**
  - A) Post-filter Grype results to remove CVEs where the matched CPE vendor
    doesn't match (Flash = adobe, not google)
  - B) Use Grype's `--only-fixed` or `--exclude` flags
  - C) Add a CPE vendor filter in grype_service.py after parsing results
  - D) Let users mark as false_positive (already supported in UI)
- **Recommended:** C — filter by matching vendor (google) in post-processing

## Issue 3: Descriptions truncated / hard to read
- **Symptom:** Long CVE descriptions displayed in a narrow table column
- **Fix:** Expandable rows or side panel for full CVE details
