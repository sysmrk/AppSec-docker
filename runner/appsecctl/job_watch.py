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
    "layer_download":"Registry layer downloaded", "layer_extract":"Registry layer extracted",
    "layer_cached":"Registry layer already present",
    "scan":"Vulnerability scan started", "sbom":"SBOM generation started",
    "db":"Vulnerability database preparation started",
    "copa_eligible":"OS findings with a known fix eligible for targeted Copa",
    "copa_skipped":"Copa targeted patch skipped: no OS findings with a reported fix",
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
    "approval_wait":"Plan ready; waiting for administrator approval",
    "auto_approved":"Validated removal plan authorized at start; build queued automatically",
    "stopped":"Stop acknowledged; no further workflow stages will run",
    "apt_index":"APT repository index received", "apt_fetch":"APT metadata/package download received",
    "apt_remove":"APT package removal observed", "apt_install":"APT package installation observed",
    "apt_upgrades":"APT reported upgrade candidates", "apt_removals":"APT reported removal candidates",
    "apt_probe":"Checking approved APT repository",
    "apt_inventory":"Reading installed package inventory",
    "apt_simulate":"Simulating package changes",
    "apt_download":"Downloading approved version-pinned archives",
}
NUMERIC={"copa_eligible","elapsed","verified","trivy_packages","trivy_languages","buildkit_step","apt_upgrades","apt_removals"}


def checkpoint():
    scope=CURRENT.get()
    if scope is None or scope[0] not in ("image","optimization"):
        return
    from . import workflow_control
    with db.connect() as conn:
        if workflow_control.requested(conn,*scope):
            raise workflow_control.StopRequested("Workflow stopped at a safe execution boundary")


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
    layer=re.fullmatch(r"[0-9a-f]{12,64}: (Download complete|Pull complete|Already exists)",raw.strip())
    if layer:
        return ({"Download complete":"layer_download","Pull complete":"layer_extract","Already exists":"layer_cached"}[layer[1]],None)
    m=re.fullmatch(r"#(\d{1,7}) DONE(?: \d+(?:\.\d+)?s)?",raw.strip())
    if m:
        return ("buildkit_step",int(m[1]))
    # BuildKit prefixes RUN output with step number and elapsed time.
    line=re.sub(r"^#\d{1,7} \d+(?:\.\d+)?\s+", "", raw.strip())
    if re.match(r"^Get:\d+\s",line):
        return ("apt_index" if re.search(r"\b(?:InRelease|Packages|Release)\b",line) else "apt_fetch",None)
    if re.match(r"^Removing [a-z0-9][a-z0-9+.:\-]*\s",line):
        return ("apt_remove",None)
    if re.match(r"^(?:Setting up|Unpacking) [a-z0-9][a-z0-9+.:\-]*\s",line):
        return ("apt_install",None)
    m=re.fullmatch(r"(\d{1,7}) upgraded, \d{1,7} newly installed, (\d{1,7}) to remove and \d{1,7} not upgraded\.",line)
    if m:
        return ("apt_removals",int(m[2])) if int(m[2]) else ("apt_upgrades",int(m[1]))
    return None


def capture_stderr(command, environment=None, timeout=None):
    """Preserve existing CLI stderr semantics while reporting real tool events.

    Bounded tail is retained only for existing error classification, not watch.
    Deadline kills the CLI process; existing callers clean up managed containers.
    """
    started=time.monotonic()
    last=started
    last_stop_check=started
    managed_trivy=command[:2]==["docker","run"] and "appsec.managed=trivy" in command
    tail=b""
    pending=b""
    with subprocess.Popen(command,stderr=subprocess.PIPE,env=environment) as proc:
        try:
            with selectors.DefaultSelector() as sel:
                sel.register(proc.stderr,selectors.EVENT_READ)
                while sel.get_map():
                    now=time.monotonic()
                    if managed_trivy and now-last_stop_check>=2:
                        checkpoint()
                        last_stop_check=now
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


def observed_run(command, *, timeout=None, environment=None, quiet=False):
    """Observe real process output or elapsed time; raw data never enters watch.

    Preserve CompletedProcess semantics for existing Docker pull/push callers.
    A repository clone or secret scan uses quiet=True: no output is collected.
    """
    started=time.monotonic()
    last=started
    tails={"stdout":b"","stderr":b""}
    pending={"stdout":b"","stderr":b""}
    mode=subprocess.DEVNULL if quiet else subprocess.PIPE
    with subprocess.Popen(command,stdout=mode,stderr=mode,env=environment) as proc:
        try:
            with selectors.DefaultSelector() as sel:
                if not quiet:
                    sel.register(proc.stdout,selectors.EVENT_READ,"stdout")
                    sel.register(proc.stderr,selectors.EVENT_READ,"stderr")
                while proc.poll() is None or sel.get_map():
                    now=time.monotonic()
                    if timeout is not None and now-started>=timeout:
                        raise subprocess.TimeoutExpired(command,timeout)
                    if sel.get_map():
                        for key,_ in sel.select(1):
                            block=os.read(key.fd,8192)
                            if not block:
                                sel.unregister(key.fileobj)
                                continue
                            kind=key.data
                            tails[kind]=(tails[kind]+block)[-65536:]
                            lines=(pending[kind]+block).replace(b"\r",b"\n").split(b"\n")
                            pending[kind]=lines.pop()[-8192:]
                            for line in lines:
                                parsed=parse_line(line[:8192].decode(errors="replace"))
                                if parsed:
                                    emit(*parsed)
                    elif proc.poll() is None:
                        time.sleep(0.25)
                    now=time.monotonic()
                    if now-last>=5:
                        emit("elapsed",int(now-started))
                        last=now
            return subprocess.CompletedProcess(command,proc.wait(),
                    tails["stdout"].decode(errors="replace"),tails["stderr"].decode(errors="replace"))
        except BaseException:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            raise


def capture_output(command, timeout=180, max_bytes=8*1024*1024):
    """Capture both pipes without blocking and emit only fixed allowlisted events.

    Preserve stdout/stderr for callers, including repository error classification.
    Refuse oversized output instead of silently truncating a trust failure.
    """
    started=last=time.monotonic()
    buffers={"stdout":bytearray(),"stderr":bytearray()}
    pending={"stdout":b"","stderr":b""}
    with subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE) as proc:
        try:
            with selectors.DefaultSelector() as sel:
                sel.register(proc.stdout,selectors.EVENT_READ,"stdout")
                sel.register(proc.stderr,selectors.EVENT_READ,"stderr")
                while sel.get_map():
                    now=time.monotonic()
                    if now-started>=timeout:
                        raise subprocess.TimeoutExpired(command,timeout)
                    for key,_ in sel.select(min(1,max(0,timeout-(now-started)))):
                        part=os.read(key.fd,8192)
                        name=key.data
                        if not part:
                            sel.unregister(key.fileobj)
                            if pending[name]:
                                event=parse_line(pending[name].decode(errors="replace"))
                                if event:
                                    emit(*event)
                            continue
                        buffers[name].extend(part)
                        if len(buffers[name])>max_bytes:
                            raise RuntimeError("Tool output exceeds capture limit")
                        lines=(pending[name]+part).split(b"\n")
                        pending[name]=lines.pop()[-8192:]
                        for line in lines:
                            event=parse_line(line[:8192].decode(errors="replace"))
                            if event:
                                emit(*event)
                    now=time.monotonic()
                    if now-last>=5:
                        emit("elapsed",int(now-started))
                        last=now
            code=proc.wait(timeout=max(0,timeout-(time.monotonic()-started)))
            stdout=buffers["stdout"].decode(errors="replace")
            stderr=buffers["stderr"].decode(errors="replace")
            if code:
                raise subprocess.CalledProcessError(code,command,output=stdout,stderr=stderr)
            return stdout
        except BaseException:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            raise
