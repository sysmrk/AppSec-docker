"""Per-job live telemetry. Only allowlisted event messages and numeric fields.

Raw tool lines, commands, paths, URLs, environment, credentials and findings
are never persisted here. A watch failure must not change job outcome.
"""
from __future__ import annotations

from contextvars import ContextVar
import os
import re
import selectors
import subprocess
import time

from . import db

CURRENT=ContextVar("watch_job",default=None)
MESSAGES={
    "claimed":"Worker claimed job", "success":"Worker finished job",
    "failed":"Worker attempt failed; check job status",
    "pull":"Pulling approved image source", "pull_ok":"Image source selected",
    "pull_failed":"Image source attempt failed",
    "scan":"Vulnerability scan started", "sbom":"SBOM generation started",
    "db":"Vulnerability database preparation started",
    "patch":"Copa / BuildKit patch started", "publish":"Registry publication started",
    "git":"Repository clone started", "gitleaks":"Redacted secret scanner started",
    "verified":"Verified scan findings", "done":"Tool command completed",
    "tool_failed":"Tool command failed", "elapsed":"Tool still running (seconds)",
    "trivy_os":"Trivy detected operating system",
    "trivy_vuln":"Trivy vulnerability scanner enabled",
    "trivy_packages":"Trivy OS package count",
    "trivy_languages":"Trivy language-specific file count",
    "buildkit_step":"BuildKit completed step", "optimization":"Optimization task started",
    "plan":"Package removal plan prepared", "build":"Approved candidate build started",
    "rescan":"Candidate rescan started", "review":"Candidate review complete",
}
NUMERIC={"elapsed","verified","trivy_packages","trivy_languages","buildkit_step"}


def emit(event, number=None):
    scope=CURRENT.get()
    if scope is None or event not in MESSAGES:
        return
    if number is not None and (event not in NUMERIC or type(number) is not int or not 0<=number<=10**9):
        return
    detail=MESSAGES[event]+(": "+str(number) if number is not None else "")
    column={"image":"image_job_id","security":"security_job_id","optimization":"optimization_id"}.get(scope[0])
    if not column:
        return
    try:
        with db.connect() as conn:
            conn.execute("INSERT INTO job_watch_events ("+column+",event,detail) VALUES (%s,%s,%s)",
                         (scope[1],event,detail))
            conn.execute("DELETE FROM job_watch_events WHERE "+column+"=%s AND id < ("
                         "SELECT id FROM job_watch_events WHERE "+column+"=%s ORDER BY id DESC OFFSET 999 LIMIT 1)",
                         (scope[1],scope[1]))
    except Exception:
        # No exception payload or secrets on stdout. Existing job processing
        # remains authoritative even during telemetry outages.
        return


def read(conn, kind, ids, after=0, limit=200):
    if kind not in ("image","security","optimization") or not 0<=after<=2**63-1 or not 1<=limit<=200:
        raise ValueError("Invalid watch cursor")
    if not ids:
        return []
    column={"image":"image_job_id","security":"security_job_id","optimization":"optimization_id"}[kind]
    return [dict(row) for row in conn.execute(
        "SELECT id,created_at,event,detail FROM job_watch_events WHERE "+column+
        " = ANY(%s::uuid[]) AND id>%s ORDER BY id LIMIT %s",
        (list(ids),after,limit)).fetchall()]


def parse_line(raw):
    # Only emit fixed strings or bounded numbers from known tool formats.
    # Never return a substring of untrusted logs as text.
    if re.search(r"\bINFO\s+Detected OS\b",raw):
        return ("trivy_os",None)
    if re.search(r"\bINFO\s+\[vuln\] Vulnerability scanning is enabled",raw):
        return ("trivy_vuln",None)
    m=re.search(r"\bINFO\s+\[debian\] Detecting vulnerabilities.*\bpkg_num=(\d{1,9})\b",raw)
    if m:
        return ("trivy_packages",int(m[1]))
    m=re.search(r"\bINFO\s+Number of language-specific files\s+num=(\d{1,9})\b",raw)
    if m:
        return ("trivy_languages",int(m[1]))
    m=re.fullmatch(r"#(\d{1,7}) DONE(?: \d+(?:\.\d+)?s)?",raw.strip())
    if m:
        return ("buildkit_step",int(m[1]))
    return None


def capture_stderr(command, environment=None, timeout=None):
    """Preserve existing CLI stderr semantics while reporting real tool events.

    Bounded tail is retained only for existing error classification, not watch.
    Deadline kills the CLI process; existing callers clean up managed containers.
    """
    started=time.monotonic()
    last=started
    tail=b""
    pending=b""
    with subprocess.Popen(command,stderr=subprocess.PIPE,env=environment) as proc:
        try:
            with selectors.DefaultSelector() as sel:
                sel.register(proc.stderr,selectors.EVENT_READ)
                while sel.get_map():
                    now=time.monotonic()
                    if timeout is not None and now-started>=timeout:
                        raise subprocess.TimeoutExpired(command,timeout,stderr=tail.decode(errors="replace"))
                    wait=min(1,max(0,timeout-(now-started))) if timeout is not None else 1
                    for key,_ in sel.select(wait):
                        block=os.read(key.fd,8192)
                        if not block:
                            sel.unregister(key.fileobj)
                            continue
                        tail=(tail+block)[-65536:]
                        pending+=block
                        lines=pending.split(b"\n")
                        pending=lines.pop()[-8192:]
                        for line in lines:
                            parsed=parse_line(line[:8192].decode(errors="replace"))
                            if parsed:
                                emit(*parsed)
                    now=time.monotonic()
                    if now-last>=5:
                        emit("elapsed",int(now-started))
                        last=now
            remaining=None if timeout is None else max(0,timeout-(time.monotonic()-started))
            code=proc.wait(timeout=remaining)
            if code:
                raise subprocess.CalledProcessError(code,command,stderr=tail.decode(errors="replace"))
        except BaseException:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            raise
