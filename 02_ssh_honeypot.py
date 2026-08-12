# ── Kalaitzidis Ioannis - MTE25012 ─────────────────────────────────────────────────────

"""
02_ssh_honeypot.py  --  Το honeypot SSH και η καταγραφη
========================================================
[TASK 1] Σχεδιαση και αναπτυξη του honeypot.
[TASK 3] Δομημενη καταγραφη συνεδριων (structured logging).

ΤΙ ΚΑΝΕΙ ΑΥΤΟ ΤΟ ΑΡΧΕΙΟ
-----------------------
Υλοποιει ενα honeypot SSH το οποιο, σε αντιθεση με μια απλη "μιμηση banner",
μιλαει ΠΡΑΓΜΑΤΙΚΟ πρωτοκολλο SSH μεσω της βιβλιοθηκης paramiko (κανονικη
ανταλλαγη κλειδιων, authentication, διαδραστικο καναλι). Οταν ο επιτιθεμενος
συνδεθει, λαμβανει ενα προσομοιωμενο κελυφος (shell) που εκτελει εντολες πανω
σε ενα εικονικο συστημα αρχειων. Το εικονικο συστημα περιεχει τα decoy
artefacts, οποτε οταν ο επιτιθεμενος κανει `cat` σε ενα δολωμα ΠΑΙΡΝΕΙ
ΠΡΑΓΜΑΤΙΚΑ το περιεχομενο του, και το honeypot σημειωνει οτι το συγκεκριμενο
δολωμα "αγγιχτηκε".

ΓΙΑΤΙ ΕΙΝΑΙ ΣΗΜΑΝΤΙΚΟ
--------------------
Επειδη το honeypot σερβιρει πραγματικα τα δολωματα και καταγραφει τι διαβασε
ο επιτιθεμενος, η μετρικη "ποια artefacts αγγιχτηκαν" γινεται ΠΡΑΓΜΑΤΙΚΟ,
μετρησιμο μεγεθος. Ετσι η αναλυση συμπεριφορας (Task 5) βασιζεται σε
πραγματικα γεγονοτα και οχι σε εικασιες.

ΑΠΟ ΤΙ ΑΠΟΤΕΛΕΙΤΑΙ (οι βασικες κλασεις)
--------------------------------------
- VFS             : το εικονικο συστημα αρχειων. Συνδυαζει τα decoy αρχεια
                    (απο τον δισκο) με συνθετικα αρχεια συστηματος (/etc/passwd,
                    /etc/os-release κ.λπ.) που παραγονται απο το profile.
                    Περιλαμβανει προστασια εναντι path traversal.
- ShellEmulator   : ο προσομοιωτης κελυφους. Αναλυει καθε εντολη, την εκτελει
                    πανω στο VFS, κραταει κατασταση (τρεχων καταλογος) και
                    επιστρεφει (εξοδος, ποια δολωματα αγγιχτηκαν). Καθε
                    υποστηριζομενη εντολη ειναι μια μεθοδος cmd_<ονομα>.
- HoneypotServer  : η διεπαφη paramiko (authentication, αιτηματα καναλιου).
- Session         : αντικειμενο συνεδριας. Συγκεντρωνει τα events και τα
                    αποθηκευει σε δομημενη μορφη (Task 3).

ΚΑΤΑΓΡΑΦΗ (Task 3)
------------------
Καθε session αποθηκευεται (α) ως αυτονομο JSON στο logs/sessions/ και (β) ως
μια γραμμη στο master logs/sessions.jsonl. Το πληρες schema περιγραφεται στο
SCHEMA.md.

ΠΩΣ ΤΡΕΧΕΙ
----------
    python3 02_ssh_honeypot.py --host 127.0.0.1 --port 2222
Μενει ανοιχτο και ακουει. Δοκιμη: ssh -p 2222 root@127.0.0.1 (pw: Corp2026!).

ΑΣΦΑΛΕΙΑ: ακουει ΜΟΝΟ στο 127.0.0.1 (loopback), δεν εκτιθεται στο διαδικτυο.
Κανενα πραγματικο μυστικο δεν υπαρχει στο εικονικο συστημα.
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
import posixpath   # για τα εικονικα paths (παντα με "/", ακομη και σε Windows)
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

# Ψευτικο password που "δεχεται" το honeypot (ωστε τα playbooks να μπαινουν).
# Καταγραφονται ΟΛΕΣ οι προσπαθειες, ανεξαρτητως επιτυχιας.
ACCEPTED_PASSWORD = "Corp2026!"
ACTIVE = cfg.ACTIVE_USER["name"]


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f%z")


# ==========================================================================
#  Εικονικο συστημα αρχειων (VFS)
#  Συνδυαζει τα decoy files (απο disk) με συνθετικα system files που
#  παραγονται απο το profile, ωστε το περιβαλλον να μοιαζει πληρες.
# ==========================================================================
class VFS:
    """Εικονικο συστημα αρχειων (Virtual File System).

    Παρουσιαζει στον επιτιθεμενο ενα φαινομενικα πληρες συστημα αρχειων Linux,
    αλλα στην πραγματικοτητα ολα ειναι ελεγχομενα και ψευτικα. Συνδυαζει δυο
    πηγες: (1) τα decoy artefacts, που ειναι πραγματικα αρχεια στον δισκο μεσα
    στο decoys/fs/, και (2) συνθετικα αρχεια συστηματος (π.χ. /etc/passwd) που
    παραγονται δυναμικα απο το κοινο profile. Οταν διαβαστει ενα decoy, το VFS
    το αναγνωριζει και το επιστρεφει μαζι με την εγγραφη του καταλογου, ωστε
    το honeypot να ξερει οτι "αγγιχτηκε" δολωμα."""

    def __init__(self):
        # Φορτωνει τον καταλογο των decoys και φτιαχνει εναν χαρτη:
        # virtual_path -> εγγραφη inventory. Χρησιμευει ωστε, οταν διαβαστει
        # ενα αρχειο, να ελεγχουμε αμεσα αν ειναι decoy (artefact tracking).
        self.inventory = {}
        inv = json.loads((DECOY_DIR / "artifact_inventory.json").read_text(encoding="utf-8"))
        for a in inv["artifacts"]:
            self.inventory[a["virtual_path"]] = a

        # Συνθετικα αρχεια συστηματος (δεν ειναι decoys, παραγονται εδω).
        self.synthetic = self._build_synthetic()

    def _build_synthetic(self):
        """Παραγει δυναμικα τα βασικα αρχεια συστηματος (/etc/passwd,
        /etc/os-release, /etc/hosts κ.λπ.) με βαση το κοινο profile, ωστε να
        ειναι συνεπη με τα υπολοιπα (ιδιοι χρηστες, ιδιο hostname, ιδιες IPs).
        Ετσι, αν ο επιτιθεμενος κανει `cat /etc/passwd`, βλεπει ακριβως τους
        χρηστες που περιμενει με βαση την υπολοιπη ιστορια."""
        users = cfg.USERS
        # /etc/passwd: μια γραμμη ανα χρηστη (root + οι χρηστες του profile +
        # τυπικοι λογαριασμοι υπηρεσιων www-data/postgres/sshd).
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
        # /etc/hosts: το localhost + ολοι οι εσωτερικοι κομβοι του δικτυου.
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
            # Ειδικος δεικτης: το /etc/shadow υπαρχει αλλα επιστρεφει
            # "permission denied" (οπως σε πραγματικο συστημα χωρις root).
            "/etc/shadow": "__DENIED__",
        }

    def _real(self, vpath):
        """Μετατρεπει ενα "εικονικο" μονοπατι (οπως το βλεπει ο επιτιθεμενος,
        π.χ. /opt/app/.env) στο πραγματικο μονοπατι μεσα στο decoys/fs/.
        ΑΣΦΑΛΕΙΑ: αν το αποτελεσμα ξεφευγει εξω απο το decoys/fs/ (προσπαθεια
        path traversal, π.χ. με ../../), επιστρεφει None και μπλοκαρεται."""
        # Καθαριζουμε το εικονικο path σε μορφη POSIX (με "/") ωστε να δουλευει
        # και σε Windows, οπου αλλιως θα εμπαιναν backslashes.
        rel = vpath.lstrip("/").replace("\\", "/")
        p = (FS_ROOT / rel).resolve()
        try:
            p.relative_to(FS_ROOT.resolve())   # απαγορευει path traversal εξω απο το VFS
        except ValueError:
            return None
        return p

    def is_dir(self, vpath):
        """Ελεγχει αν το μονοπατι αντιστοιχει σε φακελο μεσα στο VFS."""
        p = self._real(vpath)
        return p is not None and p.is_dir()

    def is_file(self, vpath):
        """Ελεγχει αν το μονοπατι αντιστοιχει σε αρχειο (decoy ή συνθετικο)."""
        if vpath in self.synthetic:
            return True
        p = self._real(vpath)
        return p is not None and p.is_file()

    def read(self, vpath):
        """Διαβαζει ενα αρχειο. Επιστρεφει τριαδα (content, artefact, denied):
        - content : το περιεχομενο (ή None αν δεν υπαρχει),
        - artefact: η εγγραφη inventory ΑΝ το αρχειο ειναι decoy, αλλιως None
                    (ετσι ο caller ξερει αν "αγγιχτηκε" δολωμα),
        - denied  : True αν η προσβαση απαγορευεται (π.χ. /etc/shadow)."""
        # Πρωτα ελεγχει τα συνθετικα αρχεια συστηματος.
        if vpath in self.synthetic:
            val = self.synthetic[vpath]
            if val == "__DENIED__":
                return (None, None, True)
            return (val, None, False)
        # Αλλιως, ψαχνει στα πραγματικα αρχεια (decoys) του VFS.
        p = self._real(vpath)
        if p is None or not p.is_file():
            return (None, None, False)
        content = p.read_text(encoding="utf-8", errors="ignore")
        art = self.inventory.get(vpath)      # αν υπαρχει στον καταλογο, ειναι decoy
        return (content, art, False)

    def listdir(self, vpath):
        """Επιστρεφει τα περιεχομενα ενος φακελου (για την εντολη ls), ή None
        αν ο φακελος δεν υπαρχει."""
        p = self._real(vpath)
        if p is None or not p.is_dir():
            return None
        return sorted(os.listdir(p))

    def walk_files(self, vpath):
        """Επιστρεφει ολα τα αρχεια κατω απο ενα μονοπατι, αναδρομικα (για τις
        εντολες find και grep -r). Τα μονοπατια επιστρεφονται ως εικονικα."""
        p = self._real(vpath)
        if p is None:
            return []
        out = []
        base = FS_ROOT.resolve()
        for root, _dirs, files in os.walk(p):
            for f in files:
                full = Path(root) / f
                # replace("\\","/"): στα Windows το relative_to δινει backslashes,
                # οποτε τα μετατρεπουμε σε "/" ωστε τα εικονικα paths να ειναι συνεπη.
                out.append("/" + str(full.resolve().relative_to(base)).replace("\\", "/"))
        return sorted(out)


# ==========================================================================
#  Προσομοιωτης κελυφους (shell emulator)
#  Εκτελει εντολες πανω στο VFS και επιστρεφει (output, touched_artefacts).
# ==========================================================================
class ShellEmulator:
    """Προσομοιωτης κελυφους (shell).

    Ειναι η "καρδια" του honeypot. Δεχεται τις εντολες που πληκτρολογει ο
    επιτιθεμενος, τις αναλυει, τις εκτελει πανω στο εικονικο συστημα αρχειων
    (VFS), και επιστρεφει το αποτελεσμα. Καθε υποστηριζομενη εντολη υλοποιειται
    ως ξεχωριστη μεθοδος με ονομα cmd_<εντολη> (π.χ. cmd_ls, cmd_cat). Ο
    προσομοιωτης κραταει ΚΑΤΑΣΤΑΣΗ ανα συνεδρια: θυμαται τον τρεχοντα καταλογο
    (cwd), ωστε οι διαδοχικες εντολες cd/ls να συμπεριφερονται ρεαλιστικα."""

    def __init__(self, vfs, username):
        self.vfs = vfs                        # το εικονικο συστημα αρχειων
        self.user = username                  # ο "συνδεδεμενος" χρηστης
        self.uid = cfg.ACTIVE_USER["uid"]
        self.cwd = cfg.ACTIVE_USER["home"]    # ξεκιναμε στον προσωπικο φακελο
        self.host = S["hostname"]

    def prompt(self):
        """Φτιαχνει το prompt του κελυφους, π.χ. "mgeorgiou@app-srv-01:~$ ".
        Αν ο τρεχων καταλογος ειναι μεσα στο home, εμφανιζεται ως ~."""
        home = cfg.ACTIVE_USER["home"]
        disp = "~" + self.cwd[len(home):] if self.cwd.startswith(home) else self.cwd
        return f"{self.user}@{self.host}:{disp}$ "

    def _abspath(self, arg):
        """Μετατρεπει ενα ορισμα εντολης σε απολυτο μονοπατι, χειριζομενος και
        τις τρεις περιπτωσεις: απολυτο (/opt/app), home (~) και σχετικο (config)
        ως προς τον τρεχοντα καταλογο. Χρησιμοποιει posixpath (παντα "/"), ωστε
        τα εικονικα Linux paths να δουλευουν σωστα ΚΑΙ σε Windows."""
        if arg.startswith("/"):
            path = arg
        elif arg == "~" or arg.startswith("~/"):
            path = cfg.ACTIVE_USER["home"] + arg[1:]
        else:
            path = posixpath.normpath(posixpath.join(self.cwd, arg))
        return posixpath.normpath(path)

    def run(self, line):
        """Εκτελει μια γραμμη εντολης. Επιστρεφει (εξοδος, λιστα_δολωματων).
        Η λιστα δολωματων δειχνει ποια decoys "αγγιχτηκαν" απο αυτη την εντολη.

        Ροη: (1) αφαιρει τυχον προθεμα sudo, (2) σπαει τη γραμμη σε εντολη +
        ορισματα, (3) βρισκει την αντιστοιχη μεθοδο cmd_<εντολη> και την καλει.
        Αν η εντολη δεν υποστηριζεται, επιστρεφει "command not found" (οπως θα
        εκανε και ενα πραγματικο κελυφος)."""
        line = line.strip()
        if not line:
            return ("", [])
        touched = []                          # εδω μαζευονται τα δολωματα που αγγιχτηκαν

        # Χειρισμος sudo: το honeypot "επιτρεπει" τα παντα (προσποιειται οτι ο
        # χρηστης εχει δικαιωματα), ωστε ο επιτιθεμενος να προχωρησει και να
        # παρατηρηθει. Το σκετο "sudo -l" επιστρεφει τα δικαιωματα sudoers.
        had_sudo = False
        if line.split() and line.split()[0] == "sudo":
            had_sudo = True
            rest = line[4:].strip()
            if rest in ("", "-l"):
                return (self._sudo_l(), [])
            line = rest

        # Αναλυση (parsing) της γραμμης σε εντολη + ορισματα, σεβομενοι τα
        # εισαγωγικα (shlex). Αν αποτυχει, πεφτουμε σε απλο split.
        try:
            parts = shlex.split(line)
        except ValueError:
            parts = line.split()
        if not parts:
            return ("", [])
        cmd, args = parts[0], parts[1:]

        # Δυναμικη ευρεση της μεθοδου-χειριστη: cmd_ls, cmd_cat, cmd_grep, κ.λπ.
        handler = getattr(self, f"cmd_{cmd}", None)
        if handler is None:
            # Αν η γραμμη εχει pipe (|) ή ανακατευθυνση (>), δοκιμαζουμε
            # απλοποιημενο χειρισμο. Αλλιως, "command not found".
            if "|" in line or ">" in line:
                return self._piped(line)
            return (f"{cmd}: command not found", [])
        return handler(args, touched, had_sudo)

    # ----- Επιμερους εντολες --------------------------------------------------
    # Καθε μεθοδος cmd_<x> προσομοιωνει την αντιστοιχη εντολη Linux. Δεχεται τα
    # ορισματα (a), τη λιστα δολωματων (t) και το αν προηγηθηκε sudo (s), και
    # επιστρεφει (εξοδος, λιστα_δολωματων).

    def cmd_whoami(self, a, t, s): return (self.user, t)          # ονομα χρηστη
    def cmd_hostname(self, a, t, s): return (self.host, t)        # ονομα μηχανηματος
    def cmd_pwd(self, a, t, s): return (self.cwd, t)              # τρεχων καταλογος
    def cmd_echo(self, a, t, s): return (" ".join(a), t)         # επαναληψη κειμενου

    def cmd_id(self, a, t, s):
        """Προσομοιωνει την `id`: εμφανιζει uid, gid και ομαδες του χρηστη."""
        u = cfg.ACTIVE_USER
        return (f"uid={u['uid']}({u['name']}) gid={u['gid']}({u['name']}) "
                f"groups={u['gid']}({u['name']}),27(sudo),1000(corp)", t)

    def cmd_uname(self, a, t, s):
        """Προσομοιωνει την `uname`: με -a δινει πληρη στοιχεια πυρηνα/OS."""
        if "-a" in a:
            return (f"Linux {self.host} {S['kernel']} #1 SMP {S['os']} {S['arch']} "
                    f"{S['arch']} {S['arch']} GNU/Linux", t)
        return ("Linux", t)

    def cmd_cd(self, a, t, s):
        """Προσομοιωνει την `cd`: αλλαζει τον τρεχοντα καταλογο (και τον
        αποθηκευει στο self.cwd, ωστε να "θυμαται" το honeypot που βρισκομαστε)."""
        if not a or a[0] == "~":
            self.cwd = cfg.ACTIVE_USER["home"]; return ("", t)
        target = self._abspath(a[0])
        if self.vfs.is_dir(target):
            self.cwd = target; return ("", t)
        # Ρεαλιστικα μηνυματα σφαλματος, οπως σε πραγματικο bash.
        if self.vfs.is_file(target):
            return (f"bash: cd: {a[0]}: Not a directory", t)
        return (f"bash: cd: {a[0]}: No such file or directory", t)

    def cmd_ls(self, a, t, s):
        """Προσομοιωνει την `ls`: λιστα περιεχομενων φακελου. Υποστηριζει -l
        (αναλυτικη μορφη με δικαιωματα/μεγεθος) και -a (και κρυφα αρχεια)."""
        paths = [x for x in a if not x.startswith("-")]
        longfmt = any(x.startswith("-") and "l" in x for x in a)   # -l
        showall = any(x.startswith("-") and "a" in x for x in a)   # -a
        target = self._abspath(paths[0]) if paths else self.cwd
        if self.vfs.is_file(target):
            return (posixpath.basename(target), t)
        entries = self.vfs.listdir(target)
        if entries is None:
            return (f"ls: cannot access '{paths[0] if paths else target}': No such file or directory", t)
        # Χωρις -a, κρυβουμε τα αρχεια που ξεκινουν με τελεια (κρυφα).
        if not showall:
            entries = [e for e in entries if not e.startswith(".")]
        if showall:
            entries = [".", ".."] + entries
        # Με -l, φτιαχνουμε ρεαλιστικη γραμμη ανα αρχειο (δικαιωματα, μεγεθος).
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
        """Βοηθητικη: επιστρεφει το μεγεθος ενος αρχειου σε bytes (για το ls -l)."""
        c, _art, _d = self.vfs.read(vpath)
        return len(c.encode()) if c else 0

    def cmd_cat(self, a, t, s):
        """Προσομοιωνει την `cat`: εμφανιζει το περιεχομενο αρχειων. ΕΔΩ γινεται
        το βασικο artefact tracking: αν το αρχειο ειναι decoy, προστιθεται στη
        λιστα των δολωματων που αγγιχτηκαν. Χειριζεται επισης permission denied
        (π.χ. /etc/shadow χωρις sudo) και μη υπαρκτα αρχεια/φακελους."""
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
            if art:                       # ΤΟ ΑΡΧΕΙΟ ΕΙΝΑΙ DECOY -> το καταγραφουμε
                t.append(art["virtual_path"])
        return ("\n".join(outs), t)

    # Οι less/more συμπεριφερονται σαν cat στο honeypot.
    cmd_less = cmd_more = cmd_cat

    def cmd_head(self, a, t, s):
        """Προσομοιωνει την `head`: τις πρωτες 10 γραμμες (με artefact tracking)."""
        files = [x for x in a if not x.startswith("-")]
        out, tt = self.cmd_cat(files, t, s)
        return ("\n".join(out.splitlines()[:10]), tt)

    def cmd_tail(self, a, t, s):
        """Προσομοιωνει την `tail`: τις τελευταιες 10 γραμμες (με tracking)."""
        files = [x for x in a if not x.startswith("-") and not x[0].isdigit()]
        out, tt = self.cmd_cat(files, t, s)
        return ("\n".join(out.splitlines()[-10:]), tt)

    def cmd_grep(self, a, t, s):
        """Προσομοιωνει την `grep`: αναζητηση κειμενου σε αρχεια. Υποστηριζει -r
        (αναδρομικα σε ολον τον φακελο). ΣΗΜΑΝΤΙΚΟ: μια εντολη grep -r μπορει να
        διαβασει (και αρα να "αγγιξει") ΠΟΛΛΑ δολωματα ταυτοχρονα, και ολα
        καταγραφονται. Ετσι αποτυπωνεται ρεαλιστικα η μαζικη αναζητηση κωδικων."""
        recursive = any(x in ("-r", "-R", "-rn", "-rni") for x in a)
        pos = [x for x in a if not x.startswith("-")]
        if not pos:
            return ("", t)
        pattern = pos[0].strip("'\"")                 # το μοτιβο αναζητησης
        targets = pos[1:] if len(pos) > 1 else [self.cwd]
        results = []
        for tg in targets:
            tgt = self._abspath(tg)
            # Αν ειναι φακελος ή -r, ψαχνουμε ολα τα αρχεια μεσα του.
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
        """Προσομοιωνει την `find`: αναζητηση αρχειων σε δεντρο φακελων.
        Υποστηριζει -name <pattern> για φιλτραρισμα κατα ονομα (π.χ. '*.env')."""
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
        """Προσομοιωνει την `history`: εμφανιζει το ιστορικο εντολων του χρηστη.
        Διαβαζει το decoy .bash_history, οποτε το αγγιγμα καταγραφεται."""
        content, art, _ = self.vfs.read(cfg.ACTIVE_USER["home"] + "/.bash_history")
        if art:
            t.append(art["virtual_path"])
        if not content:
            return ("", t)
        return ("\n".join(f"{i+1:>5}  {ln}" for i, ln in enumerate(content.splitlines())), t)

    def cmd_env(self, a, t, s):
        """Προσομοιωνει την `env`/`printenv`: εμφανιζει ρεαλιστικες μεταβλητες
        περιβαλλοντος (USER, HOME, PATH κ.λπ.) συνεπεις με τον χρηστη."""
        u = cfg.ACTIVE_USER
        return ("\n".join([
            f"USER={u['name']}", f"HOME={u['home']}", f"LOGNAME={u['name']}",
            "SHELL=/bin/bash", f"HOSTNAME={self.host}",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG=en_US.UTF-8", "TERM=xterm-256color", f"PWD={self.cwd}",
        ]), t)
    cmd_printenv = cmd_env

    def cmd_ps(self, a, t, s):
        """Προσομοιωνει την `ps aux`: εμφανιζει μια ρεαλιστικη λιστα διεργασιων
        (init, sshd, postgres, nginx, η εφαρμογη), συνεπη με την ιστορια του
        συστηματος (φαινεται οτι τρεχει η εφαρμογη και η βαση)."""
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
        """Προσομοιωνει την `ss`/`netstat`: εμφανιζει τις ανοιχτες θυρες (22 SSH,
        8000 η εφαρμογη, 443 nginx, 5432 PostgreSQL), συνεπεις με τα configs."""
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
        """Προσομοιωνει την `ip addr`/`ifconfig`: δειχνει τις καρτες δικτυου με
        την εσωτερικη IP του μηχανηματος (10.20.1.5), συνεπη με το profile."""
        return ("1: lo: <LOOPBACK,UP> mtu 65536\n    inet 127.0.0.1/8 scope host lo\n"
                f"2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500\n    inet 10.20.1.5/16 brd 10.20.255.255 scope global eth0", t)
    cmd_ifconfig = cmd_ip

    def cmd_ssh(self, a, t, s):
        """Προσομοιωνει την `ssh` προς αλλον κομβο: επιστρεφει "Connection timed
        out". Ετσι το honeypot καταγραφει την ΠΡΟΘΕΣΗ οριζοντιας μετακινησης
        (ο επιτιθεμενος προσπαθει να πηδηξει σε αλλο μηχανημα) χωρις να επιτρεπει
        πραγματικη συνδεση εκτος του απομονωμενου περιβαλλοντος."""
        host = a[-1] if a else "host"
        return (f"ssh: connect to host {host} port 22: Connection timed out", t)

    def cmd_wget(self, a, t, s): return ("", t)   # "κατεβασμα" (κενη αποκριση)
    def cmd_curl(self, a, t, s):
        """Προσομοιωνει την `curl`: το health check επιστρεφει OK (φαινεται οτι
        η εφαρμογη τρεχει), οτιδηποτε αλλο κενη αποκριση."""
        if any("health" in x for x in a):
            return ("OK", t)
        return ("", t)

    def cmd_exit(self, a, t, s): return ("__EXIT__", t)   # ειδικος δεικτης εξοδου
    cmd_logout = cmd_exit

    def _sudo_l(self):
        """Προσομοιωνει την `sudo -l`: δειχνει οτι ο χρηστης μπορει να τρεξει
        τα παντα ως root (δελεαστικο για τον επιτιθεμενο)."""
        return (f"Matching Defaults entries for {self.user} on {self.host}:\n"
                f"    env_reset, secure_path=/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\n\n"
                f"User {self.user} may run the following commands on {self.host}:\n"
                f"    (ALL : ALL) ALL")

    def _piped(self, line):
        """Απλοποιημενος χειρισμος σωληνωσεων (pipes, |). Εκτελει το πρωτο
        σκελος της εντολης και μετα εφαρμοζει διαδοχικα τα φιλτρα grep/head/
        tail/wc. Καλυπτει τις πιο συνηθισμενες περιπτωσεις (π.χ. cat file | grep x)."""
        segs = [s.strip() for s in line.split("|")]
        out, touched = self.run(segs[0])          # πρωτο σκελος (μπορει να αγγιξει decoy)
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
#  Διεπαφη paramiko (HoneypotServer)
#  Η κλαση αυτη λεει στη βιβλιοθηκη paramiko πως να συμπεριφερεται ο
#  "εξυπηρετητης" SSH: ποιες μεθοδους authentication δεχεται, ποιες
#  προσπαθειες εγκρινει, και ποια αιτηματα καναλιου (shell/exec) επιτρεπει.
# ==========================================================================
class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, session):
        self.session = session                # το αντικειμενο καταγραφης
        self.event = threading.Event()        # σηματοδοτει οτι ζητηθηκε shell/exec

    def check_channel_request(self, kind, chanid):
        """Επιτρεπει μονο καναλια τυπου "session" (κανονικο shell)."""
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        """Δηλωνει στον πελατη οτι δεχομαστε password και publickey."""
        return "password,publickey"

    def check_auth_password(self, username, password):
        """Ελεγχος συνδεσης με κωδικο. ΚΑΘΕ προσπαθεια καταγραφεται (ακομη και
        οι αποτυχημενες, ως σημα credential probing). Δεχεται μονο τον
        προκαθορισμενο κωδικο, ωστε τα playbooks να μπορουν να συνδεθουν."""
        self.session.log_auth(username, "password", password)
        if password == ACCEPTED_PASSWORD:
            self.session.auth_success = True
            self.session.username = username
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        """Ελεγχος συνδεσης με δημοσιο κλειδι. Το honeypot δεχεται οποιοδηποτε
        κλειδι (τυπικη honeypot συμπεριφορα), αλλα καταγραφει το fingerprint."""
        self.session.log_auth(username, "publickey", key.get_fingerprint().hex())
        self.session.auth_success = True
        self.session.username = username
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        """Ο πελατης ζητησε διαδραστικο shell -> σηματοδοτουμε να ξεκινησει."""
        self.event.set(); return True

    def check_channel_pty_request(self, *a):
        """Δεχομαστε το αιτημα για ψευδο-τερματικο (PTY)."""
        return True

    def check_channel_exec_request(self, channel, command):
        """Μη-διαδραστικη εκτελεση, δηλαδη `ssh host "εντολη"`. Αποθηκευουμε την
        εντολη ωστε να εκτελεστει μια φορα και να κλεισει η συνδεση."""
        self.session.exec_command = command.decode("utf-8", "ignore")
        self.event.set(); return True


# ==========================================================================
#  Αντικειμενο συνεδριας + καταγραφη (Task 3)
# ==========================================================================
class Session:
    """Αντικειμενο συνεδριας: συγκεντρωνει ολα τα δεδομενα μιας συνδεσης
    (ταυτοτητα, χρονοι, authentication, εντολες, δολωματα) και τα αποθηκευει
    σε δομημενη μορφη. Ειναι η υλοποιηση του Task 3 (καταγραφη)."""

    def __init__(self, addr):
        self.id = uuid.uuid4().hex[:12]       # μοναδικο αναγνωριστικο
        self.src_ip, self.src_port = addr     # διευθυνση/θυρα πελατη
        self.start = now_iso()                # χρονος εναρξης
        self.username = None
        self.auth_success = False
        self.auth_attempts = []               # ολες οι προσπαθειες authentication
        self.client_version = None            # banner SSH client (fingerprint)
        self.exec_command = None              # για μη-διαδραστικη εκτελεση
        self.events = []                      # χρονικη ακολουθια εντολων
        self.seq = 0                          # μετρητης συμβαντων

    def log_auth(self, username, method, secret):
        """Καταγραφει μια προσπαθεια authentication. Για ασφαλεια, αποθηκευεται
        μονο ενα δειγμα του κωδικου (τα πρωτα 24 chars) ή το fingerprint του
        κλειδιου, ΠΟΤΕ ολοκληρο το μυστικο."""
        self.auth_attempts.append({
            "time": now_iso(), "username": username, "method": method,
            "credential_sample": (secret[:24] if method == "password" else f"fp:{secret[:16]}"),
        })

    def log_event(self, etype, **kw):
        """Καταγραφει ενα συμβαν (π.χ. μια εντολη) με αυξοντα αριθμο και χρονο."""
        self.seq += 1
        ev = {"seq": self.seq, "time": now_iso(), "type": etype}
        ev.update(kw)
        self.events.append(ev)

    def to_dict(self):
        """Συνθετει ολα τα δεδομενα της συνεδριας σε ενα λεξικο (dictionary)
        ετοιμο για αποθηκευση ως JSON. Υπολογιζει τη διαρκεια, μαζευει τη λιστα
        των εντολων και το συνολο των μοναδικων δολωματων που αγγιχτηκαν."""
        cmds = [e["input"] for e in self.events if e["type"] == "command"]
        # Συγκεντρωνουμε τα μοναδικα δολωματα απο ολα τα events.
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
        """Αποθηκευει τη συνεδρια σε δυο σημεια: (1) ως αυτονομο αρχειο JSON στο
        logs/sessions/ και (2) ως μια γραμμη στο master logs/sessions.jsonl."""
        SESS_DIR.mkdir(parents=True, exist_ok=True)
        d = self.to_dict()
        (SESS_DIR / f"session_{self.id}.json").write_text(
            json.dumps(d, indent=2, ensure_ascii=False), encoding="utf-8")
        with open(MASTER, "a", encoding="utf-8") as f:
            f.write(json.dumps(d, ensure_ascii=False) + "\n")
        return d


# ==========================================================================
#  Χειρισμος μιας συνδεσης
# ==========================================================================
_master_lock = threading.Lock()


def handle_connection(client, addr, host_key, vfs):
    """Χειριζεται μια ολοκληρη συνδεση, απο την αρχη ως το τελος. Τρεχει σε
    ξεχωριστο νημα (thread) ανα πελατη, ωστε το honeypot να δεχεται πολλες
    συνδεσεις ταυτοχρονα. Ροη: (1) στηνει το SSH transport, (2) περιμενει
    authentication και αιτημα καναλιου, (3) τρεχει το προσομοιωμενο shell,
    καταγραφοντας καθε εντολη, (4) στο τελος αποθηκευει τη συνεδρια."""
    session = Session(addr)
    transport = None
    try:
        # (1) Στησιμο του SSH transport με το banner OpenSSH και το host key.
        transport = paramiko.Transport(client)
        transport.local_version = "SSH-2.0-" + V["ssh_banner"].split("SSH-2.0-")[-1]
        transport.add_server_key(host_key)
        server = HoneypotServer(session)
        transport.start_server(server=server)

        # (2) Περιμενουμε ο πελατης να ανοιξει καναλι (μετα το authentication).
        chan = transport.accept(20)
        session.client_version = transport.remote_version   # καταγραφη banner πελατη
        if chan is None:
            return
        server.event.wait(10)          # περιμενουμε αιτημα shell ή exec

        shell = ShellEmulator(vfs, session.username or ACTIVE)

        # (3α) Μη-διαδραστικη περιπτωση: ssh host "εντολη". Εκτελει μια εντολη
        # και κλεινει.
        if session.exec_command:
            out, touched = shell.run(session.exec_command)
            session.log_event("command", input=session.exec_command,
                              cwd=shell.cwd, output_bytes=len(out.encode()),
                              artefacts_touched=touched)
            if out and out != "__EXIT__":
                chan.send((out + "\n").encode())
            chan.close()
            return

        # (3β) Διαδραστικο shell: στελνουμε ενα ρεαλιστικο banner καλωσορισματος
        # (οπως το Ubuntu) και το πρωτο prompt.
        banner = (f"Welcome to {S['os']} ({S['kernel']} {S['arch']})\r\n\r\n"
                  f" * Documentation:  https://help.ubuntu.com\r\n"
                  f"Last login: Sun Apr 19 09:03:11 2026 from {N['admin_workstation']}\r\n")
        chan.send(banner.encode())
        chan.send(shell.prompt().encode())

        # Βρογχος αναγνωσης: διαβαζουμε ο,τι πληκτρολογει ο επιτιθεμενος, το
        # κοβουμε σε γραμμες, εκτελουμε καθε εντολη και καταγραφουμε το συμβαν.
        buf = b""
        while True:
            data = chan.recv(1024)
            if not data:
                break
            buf += data
            # Echo των χαρακτηρων πισω στον πελατη, ωστε να μοιαζει με πραγματικο tty.
            try:
                chan.send(data)
            except Exception:
                break
            # Οταν εχει συμπληρωθει γραμμη (newline), την εκτελουμε.
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
                # Εκτελεση της εντολης και ΚΑΤΑΓΡΑΦΗ του συμβαντος (Task 3).
                out, touched = shell.run(cmd)
                session.log_event("command", input=cmd, cwd=shell.cwd,
                                  output_bytes=len(out.encode()),
                                  artefacts_touched=touched)
                # Αν ο χρηστης εγραψε exit/logout, κλεινουμε τη συνεδρια.
                if out == "__EXIT__":
                    chan.send(b"\r\nlogout\r\n")
                    chan.close()
                    return
                # Στελνουμε την εξοδο της εντολης και το επομενο prompt.
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
        # Αποθηκευση της συνεδριας (με κλειδωμα, γιατι πολλα νηματα γραφουν στο
        # ιδιο master αρχειο ταυτοχρονα).
        with _master_lock:
            d = session.save()
        print(f"[log] session {session.id} from {session.src_ip} "
              f"| user={session.username} cmds={d['command_count']} "
              f"touched={len(d['artefacts_touched'])}")


# ==========================================================================
#  Εκκινηση του server
# ==========================================================================
def load_or_create_hostkey():
    """Φορτωνει το κλειδι του εξυπηρετητη (host key) αν υπαρχει, αλλιως
    δημιουργει ενα νεο RSA 2048 και το αποθηκευει. Το host key χρειαζεται για
    την κρυπτογραφικη ταυτοτητα του SSH εξυπηρετητη."""
    if HOSTKEY.exists():
        return paramiko.RSAKey(filename=str(HOSTKEY))
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(HOSTKEY))
    return key


def serve(host="127.0.0.1", port=2222):
    """Ξεκιναει το honeypot: ανοιγει socket, ακουει για συνδεσεις, και για καθε
    εισερχομενη συνδεση ξεκιναει ενα νεο νημα (thread) που την χειριζεται. Ετσι
    το honeypot εξυπηρετει πολλες συνδεσεις παραλληλα. Ακουει ΜΟΝΟ στο loopback."""
    vfs = VFS()                                     # φορτωνεται μια φορα, μοιραζεται
    host_key = load_or_create_hostkey()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(100)
    print(f"[*] Honeypot SSH ακουει στο {host}:{port}  ({V['ssh_banner']})")
    print(f"[*] Logs: {SESS_DIR}/  και  {MASTER}")
    try:
        while True:
            client, addr = sock.accept()            # μπλοκαρει μεχρι να ερθει συνδεση
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
