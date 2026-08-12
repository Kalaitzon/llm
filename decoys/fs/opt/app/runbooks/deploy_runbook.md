# Deployment Runbook - `app` service (app-srv-01)

> Owner: Platform team. Keep this in sync with `bin/deploy.sh`.

## 1. Pre-flight
- Confirm green build on **ci01.corp.local**.
- Announce in #ops. Check current version: `systemctl show -p ActiveEnterTimestamp app.service`.

## 2. Release
```bash
cd /opt/app
git fetch --all
git checkout release/<YYYY.MM>
./bin/migrate.sh          # runs against db01.corp.local (PostgreSQL 14)
sudo systemctl restart app.service
```

## 3. Post-deploy
- Warm cache on **cache01**: `./bin/cache_warm.sh`
- Smoke test: `curl -fsS http://127.0.0.1:8000/health`
- Tail logs for 5 min: `journalctl -u app.service -f`

## 4. Rollback
```bash
git checkout release/<previous>
./bin/migrate.sh --rollback
sudo systemctl restart app.service
```
Redis cache on cache01 is flushed automatically on rollback.

## Notes
- Migrations are **not** reversible for the `orders` table. Take a db01 snapshot first.
- If nginx (1.18.0) shows 502s, check the upstream `app_backend` on :8000.
