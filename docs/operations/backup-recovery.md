# PostgreSQL Backup & Recovery

Wairz ships with a `pg-backup` service that runs `pg_dump` nightly against the
primary `postgres` service and writes custom-format dumps into
`${BACKUP_DIR:-./backups}` on the host. This document describes how the
backups work and how to recover from one.

## What's backed up

The entire Wairz database — every project, firmware row, finding, analysis
cache entry, scheduled kernel-vulns index, etc. The `firmware_data` volume
(the actual uploaded firmware blobs and extracted filesystems) is **not**
part of these dumps; it is large and already replayable from the stored
blobs. If you need bit-identical firmware state restoration, snapshot the
`firmware_data` Docker volume separately.

## How it runs

`docker-compose.yml` defines `pg-backup` using the same `postgres:16-alpine`
image as the primary. The service:

1. Waits 5 min after `docker compose up` before the first dump (lets
   operators cancel or tune before a write lands).
2. Runs `pg_dump --clean --if-exists -Fc` in a 24-hour loop, writing to
   `/backups/wairz_YYYYMMDD_HHMMSS.dump`.
3. After each dump, deletes files matching `wairz_*.dump` older than
   30 days from `/backups` (retention).
4. Logs each step to `docker compose logs pg-backup`.

Memory is capped at 512 MB (plenty for a Wairz-scale DB; much larger databases
may need tuning).

## Configuring the destination

By default the service bind-mounts `./backups` on the host (relative to the
docker-compose working directory — typically the repo root). Override via
`.env`:

```bash
BACKUP_DIR=/var/wairz/backups
```

The directory is auto-created when `pg-backup` starts. Ensure its filesystem
is separate from the primary postgres volume so a host-disk failure doesn't
lose both.

## Restore procedure

### Full restore (all projects, findings, cache, everything)

Stop the dependent services so they don't see a half-restored DB:

```bash
docker compose stop backend worker
```

Drop-and-restore into the running postgres service. `-Fc` custom-format dumps
use `pg_restore`, not `psql`:

```bash
# Pick your target dump
ls -lh backups/wairz_*.dump

# Restore (replace the timestamp with your backup of choice)
docker compose exec -T postgres pg_restore \
  -U wairz -d wairz \
  --clean --if-exists --no-owner \
  </backups/wairz_20260419_030000.dump
```

`--clean --if-exists` drops existing objects before recreating them. The
`--no-owner` flag replays all objects as the connecting user (`wairz`)
instead of trying to reproduce the original owner (useful when the
restore runs against a fresh volume).

Bring the backend back:

```bash
docker compose start backend worker
```

Check it came up cleanly:

```bash
curl -sf http://127.0.0.1:8000/ready
docker compose logs --tail 20 backend
```

### Partial / point-in-time recovery

`pg_dump -Fc` is a full logical snapshot — there's no WAL granularity, so
the best you can do is restore the most recent nightly and replay any
intervening work manually. If you need sub-day RPO, look at a continuous
WAL-archiving tool (`wal-g`, `pgbackrest`) — out of scope for the default
Wairz deployment but compatible alongside these nightlies.

### Restore into a fresh deployment

Stand up a new stack (different host, different `BACKUP_DIR`), copy the
`.dump` file into the new `backups/` directory, and run the commands above.
The only caveat: if you're migrating off a deployment where
`POSTGRES_PASSWORD` was the old `wairz` default, you'll need to set it
explicitly in the new `.env` (see README "Security" section — the
docker-compose file now requires `POSTGRES_PASSWORD`).

## Troubleshooting

- **`pg-backup` container restarts in a loop** — check
  `docker compose logs pg-backup`. The most common cause is a mismatched
  `POSTGRES_PASSWORD` between the primary and backup service (both read
  from the same env var, so this usually indicates a stale container;
  `docker compose up -d pg-backup` recreates it with fresh env).
- **`permission denied` writing to `/backups`** — the host bind-mount
  needs to be writable by UID 999 (the postgres image's user). On SELinux
  systems, add `:Z` to the volume spec or label the host directory with
  `chcon -Rt container_file_t /path/to/backups`.
- **Dumps are empty** — 0-byte `.dump` files usually mean `pg_dump` failed
  before emitting data. Check the logs; the service logs "dump FAILED" and
  removes the partial file when this happens.
- **Retention isn't deleting old files** — `find -mtime +30` uses ctime
  relative to the container's clock. If the container has been recreated
  recently, your "old" files may look younger than they are; give it 24 h
  for the next cycle.

## Related

- `pg-backup` service: `docker-compose.yml`
- Database volume: `pgdata` (named volume, not bind-mounted — back it up
  too if you care about `pg_xlog` / WAL beyond the nightly dumps)
- Backup directory env var: `BACKUP_DIR` (see `.env.example`)
