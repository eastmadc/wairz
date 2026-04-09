# Session 21 Anti-Patterns (Regex False Positives)

**Type:** pitfall
**Source:** session-21
**Applies to:** regex-based static analysis, credential detection, network dependency scanning

## SMB/CIFS `//server/share` Matches URLs

The pattern `//\w[\w.-]+/\w[\w./$-]+` for SMB share paths like `//fileserver/data` also matches every URL containing `://` because `://example.com/path` contains `//example.com/path`.

**Fix:** Add a negative lookbehind for the colon:
```python
re.compile(r"(?<!:)//\w[\w.-]+/\w[\w./$-]+")
```

This is a general rule: any pattern starting with `//` needs `(?<!:)` to exclude URL schemes.

## Overly Broad Credential Patterns

Patterns like `password=\S+` or `username=\S+` match everywhere -- Python source code, documentation, config templates, URL query strings. On real firmware (Raspberry Pi OS), this produced dozens of false positives.

**Fix:** Require the service context on the same line:
```python
re.compile(r"(?:cifs|smbfs|mount).*\bpassword=\S+", re.IGNORECASE)
```

General rule: credential-detection patterns must be scoped to the protocol or service they apply to. Never use bare `password=` as a standalone pattern.

## Docker Compose Restart vs Up

`docker compose restart backend` reuses the existing container image. If you rebuilt the image, you need `docker compose up -d backend` to recreate the container with the new image. This is a recurring gotcha -- always use `up -d` after code changes, not `restart`.
