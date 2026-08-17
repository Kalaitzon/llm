# Session Log Schema

## What this file is and why it exists

A honeypot is only valuable if it records accurately what the attacker did.
This file describes the FORMAT (schema) in which the honeypot
(`02_ssh_honeypot.py`) stores each session, so that:

- it is clear to anyone reading the logs what each field means,
- each session can be fully reconstructed (i.e. we can replay step by step what
  commands the attacker issued, in what order, and what they read),
- the analysis program (`04_analyze_sessions.py`) can read the data in a
  programmatic, reliable way.

## Why the logging is done in two formats

The logging is done in two places at the same time, because they serve
different needs:

- **`logs/sessions/session_<id>.json`** : a standalone, human-readable
  (indented) JSON file per session. It is convenient for opening ONE specific
  session and studying it by eye.
- **`logs/sessions.jsonl`** : a single master file in JSON Lines format, where
  each line is a full session. It is ideal for BULK analysis, since the analysis
  program reads it line by line, without having to open hundreds of separate
  files.

The content is the same in both formats. Only the organisation differs.

## Full example of a session

```json
{
  "session_id": "a1b2c3d4e5f6",
  "src_ip": "127.0.0.1",
  "src_port": 51566,
  "start_time": "2026-04-20T09:15:03.120000+0000",
  "end_time":   "2026-04-20T09:15:10.640000+0000",
  "duration_seconds": 7.52,
  "client_version": "SSH-2.0-paramiko_3.4.0",
  "auth": {
    "username": "root",
    "success": true,
    "attempts": [
      {"time": "...", "username": "root", "method": "password",
       "credential_sample": "123456"},
      {"time": "...", "username": "root", "method": "password",
       "credential_sample": "Corp2026!"}
    ]
  },
  "command_count": 6,
  "commands": ["cd /opt/app", "cat .env", "grep -r password /opt/app", "..."],
  "artefacts_touched": ["/opt/app/.env", "/opt/app/config/database.yml"],
  "events": [
    {
      "seq": 1,
      "time": "2026-04-20T09:15:03.500000+0000",
      "type": "command",
      "input": "cat .env",
      "cwd": "/opt/app",
      "output_bytes": 412,
      "artefacts_touched": ["/opt/app/.env"]
    }
  ]
}
```

The example above shows a session where the attacker (a) first tried a wrong
password (123456) and then the correct one, (b) went to the application folder,
(c) read the .env file and (d) searched for passwords, touching two decoys in
total.

## Description of the session fields

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | Unique session identifier (12 hexadecimal characters). |
| `src_ip`, `src_port` | string / int | Client address and port. `src_port` is unique per connection and is used to match the session with the ground truth of the playbooks (which playbook produced it). |
| `start_time`, `end_time` | ISO-8601 | Start and end timestamps (in UTC). |
| `duration_seconds` | float | The session duration. Corresponds to the dwell time metric of the analysis. |
| `client_version` | string | The banner of the attacker's SSH client (e.g. the tool they use). Useful for fingerprinting the adversary themselves. |
| `auth.username` | string | The username with which the (successful) connection was made. |
| `auth.success` | bool | Whether the connection completed. Sessions with `false` and `command_count = 0` are failed-auth probes, i.e. failed login attempts. |
| `auth.attempts` | list | All authentication attempts of the session. Only a **sample** of the credential is recorded, never the whole thing, for safety reasons. |
| `command_count` | int | Number of commands executed. |
| `commands` | list[str] | The commands, in the order they were issued. |
| `artefacts_touched` | list[str] | The **unique** decoy artefacts that the attacker "touched" (read) over the whole session. This is the real engagement metric, i.e. an objective measure of how deeply the attacker engaged. |
| `events` | list[obj] | The detailed chronological sequence of events (see below). |

## Description of the fields of an event

Each event corresponds to a command and enables the full, step-by-step
reconstruction of the session.

| Field | Type | Description |
|-------|------|-------------|
| `seq` | int | Sequence number of the event within the session (1, 2, 3, ...). |
| `time` | ISO-8601 | The timestamp of the event. |
| `type` | string | The type of the event (here always `command`). |
| `input` | string | The exact command the attacker issued. |
| `cwd` | string | The current directory at the moment of the command. The honeypot keeps this state per session, so that successive `cd` and `ls` commands behave as on a real shell. |
| `output_bytes` | int | The size of the response in bytes (an indication of how "rich" the output was). |
| `artefacts_touched` | list[str] | Which decoys THIS SPECIFIC command touched. A command like `grep -r` can touch many decoys at once, and this is recorded accurately. |

## How a session is reconstructed

To see what an attacker did, it is enough to read the `events` list in `seq`
order: each event shows the command (`input`), where they were (`cwd`), and what
decoy they read (`artefacts_touched`). The sum of all `artefacts_touched` gives
the overall picture of what information the attacker obtained.

## Safety note

Full credentials are never recorded, nor are there any real secrets in the
virtual system. The honeypot listens only on loopback (127.0.0.1).
