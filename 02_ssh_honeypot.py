# -*- coding: utf-8 -*-
"""
02_ssh_honeypot.py  --  The SSH honeypot and the logging
========================================================
[TASK 1] Design and development of the honeypot.
[TASK 3] Structured session logging.

WHAT THIS FILE DOES
-------------------
Implements an SSH honeypot which, unlike a simple "banner imitation", speaks
REAL SSH protocol through the paramiko library (proper key exchange,
authentication, interactive channel). When the attacker connects, they receive
a simulated shell that executes commands on a virtual filesystem. The virtual
filesystem contains the decoy artefacts, so when the attacker runs `cat` on a
decoy they REALLY get its content, and the honeypot notes that this particular
decoy was "touched".

WHY IT MATTERS
--------------
Because the honeypot really serves the decoys and records what the attacker
read, the metric "which artefacts were touched" becomes a REAL, measurable
quantity. Thus the behaviour analysis (Task 5) is based on real events and not
on guesses.

WHAT IT CONSISTS OF (the main classes)
--------------------------------------
- VFS             : the virtual filesystem. Combines the decoy files (from disk)
                    with synthetic system files (/etc/passwd, /etc/os-release,
                    etc.) generated from the profile. Includes protection
                    against path traversal.
- ShellEmulator   : the shell emulator. Parses each command, executes it on the
                    VFS, keeps state (current directory) and returns (output,
                    which decoys were touched). Each supported command is a
                    cmd_<name> method.
- HoneypotServer  : the paramiko interface (authentication, channel requests).
- Session         : the session object. Collects the events and stores them in
                    structured form (Task 3).

LOGGING (Task 3)
----------------
Each session is stored (a) as a standalone JSON in logs/sessions/ and (b) as a
single line in the master logs/sessions.jsonl. The full schema is described in
SCHEMA.md.

HOW TO RUN
----------
    python3 02_ssh_honeypot.py --host 127.0.0.1 --port 2222
It stays open and listens. Test: ssh -p 2222 root@127.0.0.1 (pw: Corp2026!).

SAFETY: it listens ONLY on 127.0.0.1 (loopback), it is not exposed to the
internet. No real secret exists in the virtual system.
"""

import os
import sys
import json
import socket
import threading
import argparse
import importlib
import shlex
import uuid
import posixpath   # for the virtual paths (always with "/", even on Windows)
from datetime import datetime, timezone
from pathlib import Path

import paramiko

cfg = importlib.import_module("00_config")

BASE      = Path(__file__).resolve().parent
DECOY_DIR = BASE / "decoys"
FS_ROOT   = DECOY_DIR / "fs"
LOG_DIR   = BASE / "logs"
SESS_DIR  = LOG_DIR / "sessions"
HOSTKEY   = LOG_DIR / "honeypot_hostkey"
MASTER    = LOG_DIR / "sessions.jsonl"

S = cfg.SYSTEM
V = cfg.VERSIONS
N = cfg.NETWORK

# Fake password that the honeypot "accepts" (so that the playbooks can log in).
# ALL attempts are logged, regardless of success.
ACCEPTED_PASSWORD = "Corp2026!"
ACTIVE = cfg.ACTIVE_USER["name"]


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f%z")


# ==========================================================================
#  Virtual filesystem (VFS)
#  Combines the decoy files (from disk) with synthetic system files that are
#  generated from the profile, so that the environment looks complete.
# ==========================================================================
class VFS:
    """Virtual File System (VFS).

    Presents to the attacker a seemingly complete Linux filesystem, but in
    reality everything is controlled and fake. It combines two sources: (1) the
    decoy artefacts, which are real files on disk inside decoys/fs/, and (2)
    synthetic system files (e.g. /etc/passwd) generated dynamically from the
    shared profile. When a decoy is read, the VFS recognises it and returns it
    together with its catalogue entry, so that the honeypot knows a decoy was
    "touched"."""

    def __init__(self):
        # Load the decoy catalogue and build a map:
        # virtual_path -> inventory entry. Used so that, when a file is read, we
        # can immediately check whether it is a decoy (artefact tracking).
        self.inventory = {}
        inv = json.loads((DECOY_DIR / "artifact_inventory.json").read_text(encoding="utf-8"))
        for a in inv["artifacts"]:
            self.inventory[a["virtual_path"]] = a

        # Synthetic system files (not decoys, generated here).
        self.synthetic = self._build_synthetic()

    def _build_synthetic(self):
        """Dynamically generates the basic system files (/etc/passwd,
        /etc/os-release, /etc/hosts, etc.) based on the shared profile, so that
        they are consistent with the rest (same users, same hostname, same IPs).
        Thus, if the attacker runs `cat /etc/passwd`, they see exactly the users
        they expect based on the rest of the story."""
        users = cfg.USERS
        # /etc/passwd: one line per user (root + the profile users +
        # typical service accounts www-data/postgres/sshd).
        passwd = ["root:x:0:0:root:/root:/bin/bash"]
        for u in users:
            passwd.append(f"{u['name']}:x:{u['uid']}:{u['gid']}:{u['role']}:{u['home']}:{u['shell']}")
        passwd += [
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
            "postgres:x:114:120:PostgreSQL administrator:/var/lib/postgresql:/bin/bash",
            "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin",
        ]
        os_release = (
            'PRETTY_NAME="Ubuntu 22.04.4 LTS"\n'
            'NAME="Ubuntu"\nVERSION_ID="22.04"\nVERSION="22.04.4 LTS (Jammy Jellyfish)"\n'
            'ID=ubuntu\nID_LIKE=debian\n'
        )
        # /etc/hosts: localhost + all the internal network nodes.
        hosts = "127.0.0.1 localhost\n"
        for h in N["hosts"]:
            hosts += f"{h['ip']} {h['host']} {h['host'].split('.')[0]}\n"
        return {
            "/etc/passwd": "\n".join(passwd) + "\n",
            "/etc/hostname": S["hostname"] + "\n",
            "/etc/os-release": os_release,
            "/etc/hosts": hosts,
            "/etc/issue": "Ubuntu 22.04.4 LTS \\n \\l\n",
            "/proc/version": f"Linux version {S['kernel']} (buildd@lcy02) "
                             f"(gcc 11.4.0) #1 SMP {S['os']}\n",
            # Special marker: /etc/shadow exists but returns
            # "permission denied" (as on a real system without root).
            "/etc/shadow": "__DENIED__",
        }

    def _real(self, vpath):
        """Converts a "virtual" path (as the attacker sees it, e.g.
        /opt/app/.env) into the real path inside decoys/fs/.
        SAFETY: if the result escapes outside decoys/fs/ (a path traversal
        attempt, e.g. with ../../), it returns None and is blocked."""
        # Normalise the virtual path to POSIX form (with "/") so that it works
        # on Windows too, where backslashes would otherwise be inserted.
        rel = vpath.lstrip("/").replace("\\", "/")
        p = (FS_ROOT / rel).resolve()
        try:
            p.relative_to(FS_ROOT.resolve())   # forbids path traversal outside the VFS
        except ValueError:
            return None
        return p

    def is_dir(self, vpath):
        """Checks whether the path corresponds to a directory inside the VFS."""
        p = self._real(vpath)
        return p is not None and p.is_dir()

    def is_file(self, vpath):
        """Checks whether the path corresponds to a file (decoy or synthetic)."""
        if vpath in self.synthetic:
            return True
        p = self._real(vpath)
        return p is not None and p.is_file()

    def read(self, vpath):
        """Reads a file. Returns a triple (content, artefact, denied):
        - content : the content (or None if it does not exist),
        - artefact: the inventory entry IF the file is a decoy, otherwise None
                    (so the caller knows whether a decoy was "touched"),
        - denied  : True if access is forbidden (e.g. /etc/shadow)."""
        # First check the synthetic system files.
        if vpath in self.synthetic:
            val = self.synthetic[vpath]
            if val == "__DENIED__":
                return (None, None, True)
            return (val, None, False)
        # Otherwise, look in the real files (decoys) of the VFS.
        p = self._real(vpath)
        if p is None or not p.is_file():
            return (None, None, False)
        content = p.read_text(encoding="utf-8", errors="ignore")
        art = self.inventory.get(vpath)      # if it is in the catalogue, it is a decoy
        return (content, art, False)

    def listdir(self, vpath):
        """Returns the contents of a directory (for the ls command), or None if
        the directory does not exist."""
        p = self._real(vpath)
        if p is None or not p.is_dir():
            return None
        return sorted(os.listdir(p))

    def walk_files(self, vpath):
        """Returns all files under a path, recursively (for the find and grep -r
        commands). The paths are returned as virtual paths."""
        p = self._real(vpath)
        if p is None:
            return []
        out = []
        base = FS_ROOT.resolve()
        for root, _dirs, files in os.walk(p):
            for f in files:
                full = Path(root) / f
                # replace("\\","/"): on Windows relative_to gives backslashes,
                # so we convert them to "/" so the virtual paths stay consistent.
                out.append("/" + str(full.resolve().relative_to(base)).replace("\\", "/"))
        return sorted(out)


# ==========================================================================
#  Shell emulator
#  Executes commands on the VFS and returns (output, touched_artefacts).
# ==========================================================================
class ShellEmulator:
    """Shell emulator.

    This is the "heart" of the honeypot. It receives the commands the attacker
    types, parses them, executes them on the virtual filesystem (VFS), and
    returns the result. Each supported command is implemented as a separate
    method named cmd_<command> (e.g. cmd_ls, cmd_cat). The emulator keeps STATE
    per session: it remembers the current directory (cwd), so that successive
    cd/ls commands behave realistically."""

    def __init__(self, vfs, username):
        self.vfs = vfs                        # the virtual filesystem
        self.user = username                  # the "logged-in" user
        self.uid = cfg.ACTIVE_USER["uid"]
        self.cwd = cfg.ACTIVE_USER["home"]    # start in the home directory
        self.host = S["hostname"]

    def prompt(self):
        """Builds the shell prompt, e.g. "mgeorgiou@app-srv-01:~$ ".
        If the current directory is inside home, it is shown as ~."""
        home = cfg.ACTIVE_USER["home"]
        disp = "~" + self.cwd[len(home):] if self.cwd.startswith(home) else self.cwd
        return f"{self.user}@{self.host}:{disp}$ "

    def _abspath(self, arg):
        """Converts a command argument into an absolute path, handling all three
        cases: absolute (/opt/app), home (~) and relative (config) with respect
        to the current directory. Uses posixpath (always "/"), so that the
        virtual Linux paths work correctly on Windows too."""
        if arg.startswith("/"):
            path = arg
        elif arg == "~" or arg.startswith("~/"):
            path = cfg.ACTIVE_USER["home"] + arg[1:]
        else:
            path = posixpath.normpath(posixpath.join(self.cwd, arg))
        return posixpath.normpath(path)

    def run(self, line):
        """Executes one command line. Returns (output, decoy_list).
        The decoy list shows which decoys were "touched" by this command.

        Flow: (1) strips any sudo prefix, (2) splits the line into command +
        arguments, (3) finds the corresponding cmd_<command> method and calls it.
        If the command is not supported, it returns "command not found" (as a
        real shell would)."""
        line = line.strip()
        if not line:
            return ("", [])
        touched = []                          # here we collect the decoys that were touched

        # sudo handling: the honeypot "allows" everything (pretends the user has
        # privileges), so that the attacker proceeds and is observed. A bare
        # "sudo -l" returns the sudoers privileges.
        had_sudo = False
        if line.split() and line.split()[0] == "sudo":
            had_sudo = True
            rest = line[4:].strip()
            if rest in ("", "-l"):
                return (self._sudo_l(), [])
            line = rest

        # Parse the line into command + arguments, respecting quotes (shlex).
        # If that fails, fall back to a simple split.
        try:
            parts = shlex.split(line)
        except ValueError:
            parts = line.split()
        if not parts:
            return ("", [])
        cmd, args = parts[0], parts[1:]

        # Dynamically find the handler method: cmd_ls, cmd_cat, cmd_grep, etc.
        handler = getattr(self, f"cmd_{cmd}", None)
        if handler is None:
            # If the line has a pipe (|) or redirection (>), we try a simplified
            # handling. Otherwise, "command not found".
            if "|" in line or ">" in line:
                return self._piped(line)
            return (f"{cmd}: command not found", [])
        return handler(args, touched, had_sudo)

    # ----- Individual commands ------------------------------------------------
    # Each cmd_<x> method simulates the corresponding Linux command. It takes the
    # arguments (a), the decoy list (t) and whether sudo preceded it (s), and
    # returns (output, decoy_list).

    def cmd_whoami(self, a, t, s): return (self.user, t)          # user name
    def cmd_hostname(self, a, t, s): return (self.host, t)        # machine name
    def cmd_pwd(self, a, t, s): return (self.cwd, t)              # current directory
    def cmd_echo(self, a, t, s): return (" ".join(a), t)         # echo text

    def cmd_id(self, a, t, s):
        """Simulates `id`: shows the uid, gid and groups of the user."""
        u = cfg.ACTIVE_USER
        return (f"uid={u['uid']}({u['name']}) gid={u['gid']}({u['name']}) "
                f"groups={u['gid']}({u['name']}),27(sudo),1000(corp)", t)

    def cmd_uname(self, a, t, s):
        """Simulates `uname`: with -a it gives full kernel/OS details."""
        if "-a" in a:
            return (f"Linux {self.host} {S['kernel']} #1 SMP {S['os']} {S['arch']} "
                    f"{S['arch']} {S['arch']} GNU/Linux", t)
        return ("Linux", t)

    def cmd_cd(self, a, t, s):
        """Simulates `cd`: changes the current directory (and stores it in
        self.cwd, so that the honeypot "remembers" where we are)."""
        if not a or a[0] == "~":
            self.cwd = cfg.ACTIVE_USER["home"]; return ("", t)
        target = self._abspath(a[0])
        if self.vfs.is_dir(target):
            self.cwd = target; return ("", t)
        # Realistic error messages, as in real bash.
        if self.vfs.is_file(target):
            return (f"bash: cd: {a[0]}: Not a directory", t)
        return (f"bash: cd: {a[0]}: No such file or directory", t)

    def cmd_ls(self, a, t, s):
        """Simulates `ls`: lists directory contents. Supports -l (detailed form
        with permissions/size) and -a (including hidden files)."""
        paths = [x for x in a if not x.startswith("-")]
        longfmt = any(x.startswith("-") and "l" in x for x in a)   # -l
        showall = any(x.startswith("-") and "a" in x for x in a)   # -a
        target = self._abspath(paths[0]) if paths else self.cwd
        if self.vfs.is_file(target):
            return (posixpath.basename(target), t)
        entries = self.vfs.listdir(target)
        if entries is None:
            return (f"ls: cannot access '{paths[0] if paths else target}': No such file or directory", t)
        # Without -a, hide the files starting with a dot (hidden).
        if not showall:
            entries = [e for e in entries if not e.startswith(".")]
        if showall:
            entries = [".", ".."] + entries
        # With -l, build a realistic line per file (permissions, size).
        if longfmt:
            lines = []
            for e in entries:
                full = self._abspath(posixpath.join(target, e)) if e not in (".", "..") else target
                is_d = self.vfs.is_dir(full)
                perm = "drwxr-xr-x" if is_d else "-rw-r--r--"
                size = 4096 if is_d else self._size(full)
                lines.append(f"{perm} 1 {self.user} {self.user} {size:>6} Apr 19 09:14 {e}")
            return ("\n".join(lines), t)
        return ("  ".join(entries), t)

    def _size(self, vpath):
        """Helper: returns the size of a file in bytes (for ls -l)."""
        c, _art, _d = self.vfs.read(vpath)
        return len(c.encode()) if c else 0

    def cmd_cat(self, a, t, s):
        """Simulates `cat`: shows the content of files. THIS is where the core
        artefact tracking happens: if the file is a decoy, it is added to the
        list of touched decoys. It also handles permission denied (e.g.
        /etc/shadow without sudo) and non-existent files/directories."""
        if not a:
            return ("", t)
        outs = []
        for arg in a:
            target = self._abspath(arg)
            content, art, denied = self.vfs.read(target)
            if denied and not s:
                outs.append(f"cat: {arg}: Permission denied")
                continue
            if content is None:
                if self.vfs.is_dir(target):
                    outs.append(f"cat: {arg}: Is a directory")
                else:
                    outs.append(f"cat: {arg}: No such file or directory")
                continue
            outs.append(content.rstrip("\n"))
            if art:                       # THE FILE IS A DECOY -> we record it
                t.append(art["virtual_path"])
        return ("\n".join(outs), t)

    # less/more behave like cat in the honeypot.
    cmd_less = cmd_more = cmd_cat

    def cmd_head(self, a, t, s):
        """Simulates `head`: the first 10 lines (with artefact tracking)."""
        files = [x for x in a if not x.startswith("-")]
        out, tt = self.cmd_cat(files, t, s)
        return ("\n".join(out.splitlines()[:10]), tt)

    def cmd_tail(self, a, t, s):
        """Simulates `tail`: the last 10 lines (with tracking)."""
        files = [x for x in a if not x.startswith("-") and not x[0].isdigit()]
        out, tt = self.cmd_cat(files, t, s)
        return ("\n".join(out.splitlines()[-10:]), tt)

    def cmd_grep(self, a, t, s):
        """Simulates `grep`: text search in files. Supports -r (recursively over
        the whole folder). IMPORTANT: a single grep -r command can read (and thus
        "touch") MANY decoys at once, and all of them are recorded. This
        realistically captures a mass search for passwords."""
        recursive = any(x in ("-r", "-R", "-rn", "-rni") for x in a)
        pos = [x for x in a if not x.startswith("-")]
        if not pos:
            return ("", t)
        pattern = pos[0].strip("'\"")                 # the search pattern
        targets = pos[1:] if len(pos) > 1 else [self.cwd]
        results = []
        for tg in targets:
            tgt = self._abspath(tg)
            # If it is a directory or -r, search all files inside it.
            files = self.vfs.walk_files(tgt) if (recursive or self.vfs.is_dir(tgt)) else [tgt]
            for f in files:
                content, art, denied = self.vfs.read(f)
                if not content:
                    continue
                for ln in content.splitlines():
                    if pattern.lower() in ln.lower():
                        results.append(f"{f}:{ln}" if len(files) > 1 else ln)
                        if art and art["virtual_path"] not in t:
                            t.append(art["virtual_path"])
        return ("\n".join(results[:40]), t)

    def cmd_find(self, a, t, s):
        """Simulates `find`: searches for files in a directory tree.
        Supports -name <pattern> for filtering by name (e.g. '*.env')."""
        start = a[0] if a and not a[0].startswith("-") else self.cwd
        name = None
        if "-name" in a:
            name = a[a.index("-name") + 1].strip("'\"")
        files = self.vfs.walk_files(self._abspath(start))
        if name:
            import fnmatch
            files = [f for f in files if fnmatch.fnmatch(posixpath.basename(f), name)]
        return ("\n".join(files[:60]), t)

    def cmd_history(self, a, t, s):
        """Simulates `history`: shows the command history of the user.
        Reads the decoy .bash_history, so the touch is recorded."""
        content, art, _ = self.vfs.read(cfg.ACTIVE_USER["home"] + "/.bash_history")
        if art:
            t.append(art["virtual_path"])
        if not content:
            return ("", t)
        return ("\n".join(f"{i+1:>5}  {ln}" for i, ln in enumerate(content.splitlines())), t)

    def cmd_env(self, a, t, s):
        """Simulates `env`/`printenv`: shows realistic environment variables
        (USER, HOME, PATH, etc.) consistent with the user."""
        u = cfg.ACTIVE_USER
        return ("\n".join([
            f"USER={u['name']}", f"HOME={u['home']}", f"LOGNAME={u['name']}",
            "SHELL=/bin/bash", f"HOSTNAME={self.host}",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG=en_US.UTF-8", "TERM=xterm-256color", f"PWD={self.cwd}",
        ]), t)
    cmd_printenv = cmd_env

    def cmd_ps(self, a, t, s):
        """Simulates `ps aux`: shows a realistic process list (init, sshd,
        postgres, nginx, the app), consistent with the story of the system (it
        looks like the app and the database are running)."""
        rows = [
            "USER         PID %CPU %MEM    VSZ   RSS TTY   STAT START   TIME COMMAND",
            "root           1  0.0  0.1 168404 11460 ?     Ss   Apr10   0:12 /sbin/init",
            "root         412  0.0  0.0  95232  7620 ?     Ss   Apr10   0:03 /usr/sbin/sshd -D",
            "postgres     980  0.1  1.2 402100 98220 ?     S    Apr10   3:44 postgres: 14/main",
            "www-data    1201  0.0  0.3 145220 25600 ?     S    Apr10   0:55 nginx: worker process",
            f"{self.user:<10} 2044  0.0  0.2  22140  9012 pts/0 Ss   09:12   0:00 -bash",
            "svc_deploy  2101  0.2  2.1 991233 172440 ?    Sl   Apr18   6:20 /opt/app/.venv/bin/python app.py",
        ]
        return ("\n".join(rows), t)

    def cmd_ss(self, a, t, s):
        """Simulates `ss`/`netstat`: shows the open ports (22 SSH, 8000 the app,
        443 nginx, 5432 PostgreSQL), consistent with the configs."""
        rows = [
            "State    Recv-Q Send-Q Local Address:Port  Peer Address:Port Process",
            "LISTEN   0      128        0.0.0.0:22         0.0.0.0:*     users:((\"sshd\"))",
            "LISTEN   0      511      127.0.0.1:8000       0.0.0.0:*     users:((\"python\"))",
            "LISTEN   0      511        0.0.0.0:443        0.0.0.0:*     users:((\"nginx\"))",
            "LISTEN   0      244      127.0.0.1:5432       0.0.0.0:*     users:((\"postgres\"))",
        ]
        return ("\n".join(rows), t)
    cmd_netstat = cmd_ss

    def cmd_ip(self, a, t, s):
        """Simulates `ip addr`/`ifconfig`: shows the network interfaces with the
        internal IP of the machine (10.20.1.5), consistent with the profile."""
        return ("1: lo: <LOOPBACK,UP> mtu 65536\n    inet 127.0.0.1/8 scope host lo\n"
                f"2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500\n    inet 10.20.1.5/16 brd 10.20.255.255 scope global eth0", t)
    cmd_ifconfig = cmd_ip

    def cmd_ssh(self, a, t, s):
        """Simulates `ssh` to another node: returns "Connection timed out". This
        way the honeypot records the INTENT of lateral movement (the attacker
        tries to jump to another machine) without allowing a real connection
        outside the isolated environment."""
        host = a[-1] if a else "host"
        return (f"ssh: connect to host {host} port 22: Connection timed out", t)

    def cmd_wget(self, a, t, s): return ("", t)   # "download" (empty response)
    def cmd_curl(self, a, t, s):
        """Simulates `curl`: the health check returns OK (it looks like the app
        is running), anything else an empty response."""
        if any("health" in x for x in a):
            return ("OK", t)
        return ("", t)

    def cmd_exit(self, a, t, s): return ("__EXIT__", t)   # special exit marker
    cmd_logout = cmd_exit

    def _sudo_l(self):
        """Simulates `sudo -l`: shows that the user can run everything as root
        (tempting for the attacker)."""
        return (f"Matching Defaults entries for {self.user} on {self.host}:\n"
                f"    env_reset, secure_path=/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\n\n"
                f"User {self.user} may run the following commands on {self.host}:\n"
                f"    (ALL : ALL) ALL")

    def _piped(self, line):
        """Simplified pipe (|) handling. Executes the first segment of the
        command and then applies the grep/head/tail/wc filters in sequence.
        Covers the most common cases (e.g. cat file | grep x)."""
        segs = [s.strip() for s in line.split("|")]
        out, touched = self.run(segs[0])          # first segment (may touch a decoy)
        for seg in segs[1:]:
            p = seg.split()
            if p and p[0] == "grep" and len(p) > 1:
                pat = p[-1].strip("'\"").lower()
                out = "\n".join(l for l in out.splitlines() if pat in l.lower())
            elif p and p[0] == "head":
                n = 10
                out = "\n".join(out.splitlines()[:n])
            elif p and p[0] == "tail":
                n = 10
                out = "\n".join(out.splitlines()[-n:])
            elif p and p[0] == "wc":
                out = str(len(out.splitlines()))
        return (out, touched)


# ==========================================================================
#  paramiko interface (HoneypotServer)
#  This class tells the paramiko library how the SSH "server" should behave:
#  which authentication methods it accepts, which attempts it approves, and
#  which channel requests (shell/exec) it allows.
# ==========================================================================
class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, session):
        self.session = session                # the logging object
        self.event = threading.Event()        # signals that shell/exec was requested

    def check_channel_request(self, kind, chanid):
        """Allows only channels of type "session" (a normal shell)."""
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        """Tells the client that we accept password and publickey."""
        return "password,publickey"

    def check_auth_password(self, username, password):
        """Password authentication check. EVERY attempt is logged (even the
        failed ones, as a credential-probing signal). It accepts only the
        predefined password, so that the playbooks can log in."""
        self.session.log_auth(username, "password", password)
        if password == ACCEPTED_PASSWORD:
            self.session.auth_success = True
            self.session.username = username
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        """Public-key authentication check. The honeypot accepts any key (typical
        honeypot behaviour), but records the fingerprint."""
        self.session.log_auth(username, "publickey", key.get_fingerprint().hex())
        self.session.auth_success = True
        self.session.username = username
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        """The client requested an interactive shell -> we signal it to start."""
        self.event.set(); return True

    def check_channel_pty_request(self, *a):
        """We accept the pseudo-terminal (PTY) request."""
        return True

    def check_channel_exec_request(self, channel, command):
        """Non-interactive execution, i.e. `ssh host "command"`. We store the
        command so that it runs once and the connection closes."""
        self.session.exec_command = command.decode("utf-8", "ignore")
        self.event.set(); return True


# ==========================================================================
#  Session object + logging (Task 3)
# ==========================================================================
class Session:
    """Session object: collects all the data of a connection (identity, times,
    authentication, commands, decoys) and stores them in structured form. It is
    the implementation of Task 3 (logging)."""

    def __init__(self, addr):
        self.id = uuid.uuid4().hex[:12]       # unique identifier
        self.src_ip, self.src_port = addr     # client address/port
        self.start = now_iso()                # start time
        self.username = None
        self.auth_success = False
        self.auth_attempts = []               # all authentication attempts
        self.client_version = None            # banner SSH client (fingerprint)
        self.exec_command = None              # for non-interactive execution
        self.events = []                      # chronological sequence of commands
        self.seq = 0                          # event counter

    def log_auth(self, username, method, secret):
        """Logs an authentication attempt. For safety, only a sample of the
        password (the first 24 chars) or the key fingerprint is stored, NEVER the
        whole secret."""
        self.auth_attempts.append({
            "time": now_iso(), "username": username, "method": method,
            "credential_sample": (secret[:24] if method == "password" else f"fp:{secret[:16]}"),
        })

    def log_event(self, etype, **kw):
        """Logs an event (e.g. a command) with a sequence number and a time."""
        self.seq += 1
        ev = {"seq": self.seq, "time": now_iso(), "type": etype}
        ev.update(kw)
        self.events.append(ev)

    def to_dict(self):
        """Assembles all the session data into a dictionary ready to be stored
        as JSON. It computes the duration, gathers the command list and the set
        of unique decoys that were touched."""
        cmds = [e["input"] for e in self.events if e["type"] == "command"]
        # Collect the unique decoys from all the events.
        touched = []
        for e in self.events:
            for a in e.get("artefacts_touched", []):
                if a not in touched:
                    touched.append(a)
        end = now_iso()
        dur = (datetime.strptime(end[:26], "%Y-%m-%dT%H:%M:%S.%f") -
               datetime.strptime(self.start[:26], "%Y-%m-%dT%H:%M:%S.%f")).total_seconds()
        return {
            "session_id": self.id,
            "src_ip": self.src_ip, "src_port": self.src_port,
            "start_time": self.start, "end_time": end,
            "duration_seconds": round(dur, 3),
            "client_version": self.client_version,     # SSH client banner (fingerprint)
            "auth": {
                "username": self.username,
                "success": self.auth_success,
                "attempts": self.auth_attempts,
            },
            "command_count": len(cmds),
            "commands": cmds,
            "artefacts_touched": touched,
            "events": self.events,
        }

    def save(self):
        """Saves the session in two places: (1) as a standalone JSON file in
        logs/sessions/ and (2) as a single line in the master
        logs/sessions.jsonl."""
        SESS_DIR.mkdir(parents=True, exist_ok=True)
        d = self.to_dict()
        (SESS_DIR / f"session_{self.id}.json").write_text(
            json.dumps(d, indent=2, ensure_ascii=False), encoding="utf-8")
        with open(MASTER, "a", encoding="utf-8") as f:
            f.write(json.dumps(d, ensure_ascii=False) + "\n")
        return d


# ==========================================================================
#  Handling a single connection
# ==========================================================================
_master_lock = threading.Lock()


def handle_connection(client, addr, host_key, vfs):
    """Handles one whole connection, from start to finish. Runs in a separate
    thread per client, so that the honeypot accepts many connections at the same
    time. Flow: (1) sets up the SSH transport, (2) waits for authentication and a
    channel request, (3) runs the simulated shell, logging every command, (4) at
    the end saves the session."""
    session = Session(addr)
    transport = None
    try:
        # (1) Set up the SSH transport with the OpenSSH banner and the host key.
        transport = paramiko.Transport(client)
        transport.local_version = "SSH-2.0-" + V["ssh_banner"].split("SSH-2.0-")[-1]
        transport.add_server_key(host_key)
        server = HoneypotServer(session)
        transport.start_server(server=server)

        # (2) Wait for the client to open a channel (after authentication).
        chan = transport.accept(20)
        session.client_version = transport.remote_version   # record client banner
        if chan is None:
            return
        server.event.wait(10)          # wait for a shell or exec request

        shell = ShellEmulator(vfs, session.username or ACTIVE)

        # (3a) Non-interactive case: ssh host "command". Runs one command and
        # closes.
        if session.exec_command:
            out, touched = shell.run(session.exec_command)
            session.log_event("command", input=session.exec_command,
                              cwd=shell.cwd, output_bytes=len(out.encode()),
                              artefacts_touched=touched)
            if out and out != "__EXIT__":
                chan.send((out + "\n").encode())
            chan.close()
            return

        # (3b) Interactive shell: send a realistic welcome banner (like Ubuntu)
        # and the first prompt.
        banner = (f"Welcome to {S['os']} ({S['kernel']} {S['arch']})\r\n\r\n"
                  f" * Documentation:  https://help.ubuntu.com\r\n"
                  f"Last login: Sun Apr 19 09:03:11 2026 from {N['admin_workstation']}\r\n")
        chan.send(banner.encode())
        chan.send(shell.prompt().encode())

        # Read loop: read whatever the attacker types, split it into lines,
        # execute each command and log the event.
        buf = b""
        while True:
            data = chan.recv(1024)
            if not data:
                break
            buf += data
            # Echo the characters back to the client, so it looks like a real tty.
            try:
                chan.send(data)
            except Exception:
                break
            # Once a full line (newline) is complete, execute it.
            while b"\n" in buf or b"\r" in buf:
                if b"\r\n" in buf:
                    line, buf = buf.split(b"\r\n", 1)
                elif b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                else:
                    line, buf = buf.split(b"\r", 1)
                cmd = line.decode("utf-8", "ignore").strip()
                if cmd == "":
                    chan.send(("\r\n" + shell.prompt()).encode()); continue
                # Execute the command and LOG the event (Task 3).
                out, touched = shell.run(cmd)
                session.log_event("command", input=cmd, cwd=shell.cwd,
                                  output_bytes=len(out.encode()),
                                  artefacts_touched=touched)
                # If the user typed exit/logout, close the session.
                if out == "__EXIT__":
                    chan.send(b"\r\nlogout\r\n")
                    chan.close()
                    return
                # Send the command output and the next prompt.
                payload = "\r\n" + (out + "\r\n" if out else "") + shell.prompt()
                chan.send(payload.encode())
    except Exception:
        pass
    finally:
        try:
            if transport:
                transport.close()
        except Exception:
            pass
        # Save the session (with a lock, because many threads write to the same
        # master file at the same time).
        with _master_lock:
            d = session.save()
        print(f"[log] session {session.id} from {session.src_ip} "
              f"| user={session.username} cmds={d['command_count']} "
              f"touched={len(d['artefacts_touched'])}")


# ==========================================================================
#  Server startup
# ==========================================================================
def load_or_create_hostkey():
    """Loads the server host key if it exists, otherwise creates a new RSA 2048
    and stores it. The host key is needed for the cryptographic identity of the
    SSH server."""
    if HOSTKEY.exists():
        return paramiko.RSAKey(filename=str(HOSTKEY))
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(HOSTKEY))
    return key


def serve(host="127.0.0.1", port=2222):
    """Starts the honeypot: opens a socket, listens for connections, and for
    each incoming connection starts a new thread that handles it. This way the
    honeypot serves many connections in parallel. It listens ONLY on loopback."""
    vfs = VFS()                                     # loaded once, shared
    host_key = load_or_create_hostkey()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(100)
    print(f"[*] Honeypot SSH ακουει στο {host}:{port}  ({V['ssh_banner']})")
    print(f"[*] Logs: {SESS_DIR}/  και  {MASTER}")
    try:
        while True:
            client, addr = sock.accept()            # blocks until a connection arrives
            th = threading.Thread(target=handle_connection,
                                  args=(client, addr, host_key, vfs), daemon=True)
            th.start()
    except KeyboardInterrupt:
        print("\n[*] Τερματισμος honeypot.")         # Ctrl+C για σταματημα
    finally:
        sock.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="SSH honeypot")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2222)
    args = ap.parse_args()
    serve(args.host, args.port)
