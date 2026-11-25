"""Scheduler-owned tool upgrades; API only queues admin-approved releases."""
from __future__ import annotations
import hashlib
import io
import json
import os
import re
import subprocess
import socket
import ssl
import time
import urllib.error
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit
from . import db, image_sources
TOOLS = {"copa": "project-copacetic/copacetic", "trivy": "aquasecurity/trivy", "gitleaks": "gitleaks/gitleaks"}
DEFAULTS = {"trivy": "aquasec/trivy:latest", "gitleaks": "zricethezav/gitleaks:latest"}
VERSION = re.compile(r"^v?([0-9]+\.[0-9]+\.[0-9]+)$")
ROOT = Path("/tool-updates")
def version(value):
    m = VERSION.fullmatch(value) if isinstance(value, str) else None
    return m.group(1) if m else None
def newer(candidate, installed):
    return bool(version(candidate) and (not version(installed) or
        tuple(map(int, version(candidate).split("."))) > tuple(map(int, version(installed).split(".")))))
def image_ref(tool, tag=None):
    raw = os.getenv(tool.upper() + "_IMAGE", DEFAULTS[tool])
    if not tag:
        return raw
    if not version(tag):
        raise ValueError("Invalid tool version")
    repo = raw.split("@", 1)[0]
    if ":" in repo.rsplit("/", 1)[-1]:
        repo = repo.rsplit(":", 1)[0]
    return repo + (":v" if tool == "gitleaks" else ":") + version(tag)
def active(conn, tool):
    row = conn.execute("SELECT active_version FROM tool_updates WHERE tool=%s", (tool,)).fetchone()
    return version(row["active_version"]) if row else None
def scanner_reference(conn, tool):
    return image_ref(tool, active(conn, tool))
def copa_binary(conn):
    v = active(conn, "copa")
    if not v:
        return "copa"
    path = ROOT / v / "copa"
    if not path.is_file():
        raise RuntimeError("Active Copa binary missing; restore tool-updates volume")
    return str(path)
def command_version(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=30)
        output = (result.stdout + "\n" + result.stderr).strip()
        match = re.search(r"(?<![\w.])v?(\d+\.\d+\.\d+)(?![\w.])", output)
        return (match.group(1) if match else None), output[:1400]
    except (OSError, subprocess.SubprocessError):
        return None, "Unavailable"
def scanner_version(reference, cache=False):
    args = ["docker", "run", "--rm", "--pull=never", "--network", "none"]
    if cache:
        args += ["-v", os.getenv("TRIVY_CACHE_VOLUME", "appsec_trivy_cache") + ":/root/.cache/trivy:ro"]
    return command_version(args + [reference, "--version"])
HOSTS = ("api.github.com", "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com")
def allowed_url(url):
    try:
        parsed = urlsplit(url)
        return (parsed.scheme == "https" and parsed.hostname in HOSTS and
                parsed.port in (None, 443) and not parsed.username and not parsed.password)
    except ValueError:
        return False
class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not allowed_url(newurl):
            raise RuntimeError("Unexpected release redirect")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        self.last_host = urlsplit(newurl).hostname
        return redirected
class ReleaseNetworkError(RuntimeError):
    """Sanitized release transport failure (no URL queries or proxy credentials)."""


def network_reason(exc):
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code == 403 and exc.headers and exc.headers.get("X-RateLimit-Remaining") == "0":
            return "HTTP 403 (GitHub API rate limit; try a later check)", False
        return "HTTP " + str(exc.code), exc.code in (408, 429, 500, 502, 503, 504)
    reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    if isinstance(reason, ssl.SSLCertVerificationError):
        return "TLS certificate verification failed", False
    if isinstance(reason, ssl.SSLError):
        return "TLS handshake failed", True
    if isinstance(reason, socket.gaierror):
        return "DNS resolution failed", True
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return "Connection timed out", True
    if isinstance(reason, OSError):
        import errno
        label = errno.errorcode.get(reason.errno, "")
        return "Connection failed" + (" (" + label + ")" if label else ""), True
    return "HTTPS transport failed (" + type(reason).__name__ + ")", True


def release_opener():
    proxy = os.getenv("APPSEC_TOOL_HTTPS_PROXY", "").strip()
    ca = os.getenv("APPSEC_TOOL_CA_FILE", "").strip()
    context = ssl.create_default_context()
    if ca:
        try:
            context.load_verify_locations(cafile=ca)
        except (OSError, ssl.SSLError):
            raise RuntimeError("Configured enterprise CA file cannot be loaded; check scheduler mount and PEM format") from None
    redirect = SafeRedirect()
    handlers = [redirect, urllib.request.HTTPSHandler(context=context)]
    if proxy:
        parsed = urlsplit(proxy)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise RuntimeError("Invalid APPSEC_TOOL_HTTPS_PROXY; use an HTTP(S) proxy URL")
        handlers.append(urllib.request.ProxyHandler({"https": proxy}))
    opener = urllib.request.build_opener(*handlers)
    opener.appsec_redirect = redirect
    return opener


def read_url(url, maximum, stage="Release metadata"):
    if not allowed_url(url):
        raise RuntimeError("Unexpected release endpoint")
    request = urllib.request.Request(url, headers={"User-Agent": "AppSec-Control-Center"})
    opener = release_opener()
    for attempt in range(3):
        try:
            redirect = getattr(opener, "appsec_redirect", None)
            if redirect is not None:
                redirect.last_host = None
            with opener.open(request, timeout=20) as response:
                data = response.read(maximum + 1)
                if len(data) > maximum:
                    raise RuntimeError("Release response exceeded size limit")
                return data
        except (urllib.error.URLError, OSError) as exc:
            reason, transient = network_reason(exc)
            # Redirect failures identify the failing official host without leaking signed query parameters.
            failed_url = getattr(exc, "url", None) or url
            host = urlsplit(failed_url).hostname
            redirected_host = getattr(redirect, "last_host", None)
            if not getattr(exc, "url", None) and redirected_host in HOSTS:
                host = redirected_host
            if host not in HOSTS:
                host = urlsplit(url).hostname
            if transient and attempt < 2:
                time.sleep(attempt + 1)
                continue
            raise ReleaseNetworkError(stage + " (" + host + "): " + reason) from None


def validate_release(item, tag=None):
    v = version(item.get("tag_name"))
    if not v or item.get("draft") or item.get("prerelease") or (tag and v != version(tag)):
        raise RuntimeError("No supported stable release")
    return v


def release_cache(tool, v):
    return ROOT / "release-metadata" / tool / (v + ".json")


def cache_release(tool, v, item):
    path = release_cache(tool, v)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, mode="w", encoding="utf-8", delete=False) as stream:
        tmp = Path(stream.name)
        json.dump(item, stream)
    try:
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def release(tool, tag=None):
    suffix = "/latest" if tag is None else "/tags/v" + version(tag)
    item = json.loads(read_url("https://api.github.com/repos/" + TOOLS[tool] + "/releases" + suffix, 4 * 1024 * 1024))
    v = validate_release(item, tag)
    cache_release(tool, v, item)
    return v, item


def approved_release(tool, tag):
    # This exact tag was already discovered by a release check and approved by an admin.
    # Prefer the cached official metadata, eliminating the second API dependency.
    v = version(tag)
    if not v:
        raise RuntimeError("Invalid approved release version")
    path = release_cache(tool, v)
    if path.is_file():
        item = json.loads(path.read_text(encoding="utf-8"))
        validate_release(item, v)
        return v, item
    return release(tool, v)


def install_copa(v, item):
    import platform
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if not architecture:
        raise RuntimeError("Unsupported Copa architecture")
    filename = f"copa_{v}_linux_{architecture}.tar.gz"
    asset = next((x for x in item.get("assets", []) if x.get("name") == filename), None)
    digest = (asset or {}).get("digest") or ""
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise RuntimeError("Official release asset has no SHA256 digest; update refused")
    expected = "https://github.com/" + TOOLS["copa"] + "/releases/download/v" + v + "/" + filename
    if asset.get("browser_download_url") != expected:
        raise RuntimeError("Unexpected Copa asset URL")
    staged = ROOT / "inbox" / filename
    if staged.is_file():
        if staged.stat().st_size > 100 * 1024 * 1024:
            raise RuntimeError("Staged Copa archive exceeds size limit")
        data = staged.read_bytes()
    else:
        data = read_url(expected, 100 * 1024 * 1024, "Copa asset download")
    if hashlib.sha256(data).hexdigest() != digest.split(":", 1)[1]:
        raise RuntimeError("Copa release SHA256 mismatch; remove any invalid staged archive and retry")
    folder = ROOT / v
    folder.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = [m for m in archive.getmembers() if m.isfile() and m.name in ("copa", "./copa")]
        if len(members) != 1 or members[0].size > 100 * 1024 * 1024:
            raise RuntimeError("Unexpected Copa archive layout")
        binary = archive.extractfile(members[0]).read()
    with tempfile.NamedTemporaryFile(dir=folder, delete=False) as tmp:
        path = Path(tmp.name)
        tmp.write(binary)
    try:
        path.chmod(0o755)
        actual, _ = command_version([str(path), "--version"])
        help_result = subprocess.run([str(path), "patch", "--help"], capture_output=True, text=True, timeout=30, check=True)
        if actual != v or not all(flag in help_result.stdout for flag in ("--addr", "--timeout")):
            raise RuntimeError("Copa version or command compatibility check failed")
        os.replace(path, folder / "copa")
    finally:
        path.unlink(missing_ok=True)
def resolve_scanner(tool, requested, sources, expected=None):
    """Use configured priority, also fall back if a mirror has the wrong version."""
    if sources is None and expected is None:
        return requested
    if sources is None:
        raise RuntimeError("Configure an approved image pull source before using managed scanner versions")
    failures = []
    for candidate in image_sources.ordered_candidates(sources, [requested]):
        try:
            ref = image_sources.pull_ordered([candidate])
            if expected and scanner_version(ref)[0] != expected:
                raise RuntimeError("Scanner version mismatch")
            return ref
        except RuntimeError as exc:
            failures.append(candidate["name"] + ": " + str(exc)[:200])
    raise RuntimeError("SOURCE_PULL_FAILED: No approved scanner source succeeded: " + "; ".join(failures)[:1000])

def install_scanner(tool, v):
    with db.connect() as conn:
        sources = image_sources.configured_sources(conn)
    if not sources:
        raise RuntimeError("Configure an approved image pull source before installing scanner updates")
    resolve_scanner(tool, image_ref(tool, v), sources, v)
def installed_version(tool):
    with db.connect() as conn:
        if tool == "copa":
            return command_version([copa_binary(conn), "--version"])[0]
        candidates = image_sources.candidates(conn, scanner_reference(conn, tool))
    for candidate in candidates:
        actual, _ = scanner_version(candidate["ref"])
        if actual:
            return actual
    return None
def status_rows(conn):
    rows = conn.execute("SELECT * FROM tool_updates ORDER BY tool").fetchall()
    return [dict(row, update_available=row["status"] in ("available", "failed", "check_failed") and newer(row["latest_version"], row["current_version"])) for row in rows]
def enqueue(conn, tool):
    if tool not in TOOLS:
        raise ValueError("Unsupported tool")
    row = conn.execute("SELECT * FROM tool_updates WHERE tool=%s FOR UPDATE", (tool,)).fetchone()
    if not row or row["status"] not in ("available", "failed", "check_failed") or not newer(row["latest_version"], row["current_version"]):
        raise ValueError("No verified newer release available or update already queued")
    conn.execute("UPDATE tool_updates SET requested_version=latest_version, requested_at=now(), status='queued', last_error=NULL WHERE tool=%s", (tool,))
    return row["latest_version"]
def check_due():
    with db.connect() as conn:
        rows = conn.execute("""SELECT tool FROM tool_updates WHERE status NOT IN ('queued','applying')
            AND (checked_at IS NULL OR checked_at < now() - interval '6 hours')""").fetchall()
    for row in rows:
        tool = row["tool"]
        current = None
        try:
            current = installed_version(tool)
            latest, _ = release(tool)
            state = "available" if newer(latest, current) else "current"
            with db.connect() as conn:
                conn.execute("""UPDATE tool_updates SET current_version=%s, latest_version=%s, checked_at=now(),
                    status=%s, last_error=NULL WHERE tool=%s AND status NOT IN ('queued','applying')""", (current, latest, state, tool))
        except Exception as exc:
            message = update_error(exc)
            with db.connect() as conn:
                conn.execute("""UPDATE tool_updates SET checked_at=now(),status='check_failed',
                    current_version=COALESCE(%s,current_version),last_error=%s
                    WHERE tool=%s AND status NOT IN ('queued','applying')""",
                    (current, message, tool))
def update_error(exc):
    if isinstance(exc, ReleaseNetworkError):
        return str(exc)[:500]
    if isinstance(exc, (urllib.error.URLError, OSError)):
        return network_reason(exc)[0]
    if isinstance(exc, RuntimeError):
        from .errors import safe_detail
        return safe_detail(str(exc))[:500]
    if isinstance(exc, (ValueError, TypeError)):
        return "Release metadata or update configuration invalid (" + type(exc).__name__ + ")"
    return "Update operation failed (" + type(exc).__name__ + ")"


def apply_one():
    with db.connect() as lock:
        if not lock.execute("SELECT pg_try_advisory_lock(78291342) AS locked").fetchone()["locked"]:
            return
        try:
            with db.connect() as conn:
                conn.execute("""UPDATE tool_updates SET status='failed',last_error='Interrupted update; request again' WHERE status='applying'""")
                row = conn.execute("""SELECT * FROM tool_updates WHERE status='queued'
                    ORDER BY requested_at LIMIT 1 FOR UPDATE SKIP LOCKED""").fetchone()
                if not row:
                    return
                tool, v = row["tool"], row["requested_version"]
                conn.execute("UPDATE tool_updates SET status='applying' WHERE tool=%s", (tool,))
            try:
                current = installed_version(tool)
                if not newer(v, current):
                    raise RuntimeError("Requested release is not newer than installed version")
                if tool == "copa":
                    actual, item = approved_release(tool, v)
                    install_copa(actual, item)
                else:
                    # Version was discovered and explicitly approved; OCI retrieval is through approved mirrors.
                    actual = version(v)
                    if not actual:
                        raise RuntimeError("Invalid approved scanner release")
                    install_scanner(tool, actual)
                with db.connect() as conn:
                    conn.execute("""UPDATE tool_updates SET active_version=%s,current_version=%s,status='current',
                        applied_at=now(),checked_at=now(),last_error=NULL WHERE tool=%s""", (actual, actual, tool))
                    db.insert_audit(conn, None, "tool.update.applied", "tool", None, {"tool":tool,"version":actual})
            except Exception as exc:
                message = update_error(exc)
                with db.connect() as conn:
                    conn.execute("UPDATE tool_updates SET status='failed',last_error=%s WHERE tool=%s", (message, tool))
        finally:
            lock.execute("SELECT pg_advisory_unlock(78291342)")
