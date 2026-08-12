# Infra notes (app-srv-01) - keep it short

## TODO (security)
- [ ] Rotate the `app_rw` DB password - still the pre-launch dev value in some envs (!!)
- [ ] Patch OpenSSH (running 8.9p1, want the latest ubuntu security update)
- [ ] Lock down /metrics - currently allow 10.20.0.0/16, should be monitoring host only
- [ ] Remove old `svc_deploy` key from ci01 (rotated last month)

## Known issues
- app.service occasionally OOMs after ~10 days uptime -> weekly restart via cron for now
- db01 replica lag spikes during nightly pg_backup (02:00). Move backup window?

## Maintenance windows
- Patching: first Sunday, 02:00-04:00 EEST
- Next planned: 2026-05-03

## Random
- backup01 disk at 71%, order more before June
- ci01 agent token in Jenkins creds store, NOT here
