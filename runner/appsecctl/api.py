from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4
import secrets

import os

from fastapi import Request
from fastapi import Cookie, Depends, FastAPI, Header, HTTPException
from pydantic import field_validator
from fastapi.responses import FileResponse, RedirectResponse, Response, JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pydantic import BaseModel, Field

from . import db
from .errors import classify
from .artifacts import presigned_download_url
from .logging_utils import log_event
from .reports import notify, write_html_report, write_security_sarif
from .security import enqueue_security_job
from .sanitization import validate_repo_target


app = FastAPI(title="AppSec Pipeline API", version="0.1.0")

HTTP_REQUESTS = Counter("appsec_http_requests_total", "HTTP requests", ["method", "path", "status"])
HTTP_LATENCY = Histogram("appsec_http_request_duration_seconds", "HTTP request latency", ["method", "path"])


@app.middleware("http")
async def request_logging(request: Request, call_next):
    request_id = str(uuid4())
    request.state.request_id = request_id
    path = request.url.path
    method = request.method
    with HTTP_LATENCY.labels(method=method, path=path).time():
        response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    HTTP_REQUESTS.labels(method=method, path=path, status=str(response.status_code)).inc()
    log_event("api.request", request_id=request_id, method=method, path=path, status=response.status_code)
    return response


@app.exception_handler(HTTPException)
async def appsec_http_error(request: Request, exc: HTTPException) -> JSONResponse:
    info = classify(exc.detail)
    detail = str(exc.detail) if isinstance(exc.detail, str) else info["title"]
    return JSONResponse(status_code=exc.status_code, content={
        "detail": detail, "error": {**info, "request_id": getattr(request.state, "request_id", "")},
    })


@app.exception_handler(RequestValidationError)
async def appsec_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    fields = [".".join(str(x) for x in item.get("loc", []) if x != "body")[:80] for item in exc.errors()[:8]]
    return JSONResponse(status_code=422, content={
        "detail": "Please correct the input fields.",
        "error": {"code": "INPUT_INVALID", "title": "Invalid input",
                  "hint": "Check required fields, formats, and allowed values.",
                  "fields": fields, "retryable": False,
                  "request_id": getattr(request.state, "request_id", "")},
    })


@app.exception_handler(Exception)
async def appsec_internal_error(request: Request, exc: Exception) -> JSONResponse:
    request_id = getattr(request.state, "request_id", str(uuid4()))
    log_event("api.unhandled_error", level="error", request_id=request_id, error_type=type(exc).__name__)
    return JSONResponse(status_code=500, content={
        "detail": "Internal service error; the operation may not have completed.",
        "error": {"code": "INTERNAL_ERROR", "title": "Internal service error",
                  "hint": "Ask an administrator to find this request ID in API logs. Never retry a registry publish blindly.",
                  "request_id": request_id, "retryable": False},
    })


class PipelineRequest(BaseModel):
    image: str = Field(min_length=1, max_length=1024)
    priority: int = Field(default=100, ge=0, le=10000)
    project_id: str | None = None
    mode: str = Field(default="scan", pattern="^(scan|patch)$")
    confirm_patch: bool = False


class ManualWorkflowRequest(BaseModel):
    image: str = Field(min_length=1, max_length=1024)
    project_id: str | None = None


class ManualDecisionRequest(BaseModel):
    action: str = Field(pattern="^(finish|approve_patch|cancel)$")
    confirm_push: bool = False


class ScheduleRequest(BaseModel):
    image: str = Field(min_length=1)
    interval_minutes: int = Field(default=1440, ge=1)


class SecurityJobRequest(BaseModel):
    kind: str = Field(pattern="^(secrets)$")
    target: str = Field(min_length=1)
    priority: int = 100
    profile: str = Field(default="standard", pattern="^(quick|standard|strict|release)$")
    project_id: str | None = None


class TeamRequest(BaseModel):
    name: str = Field(min_length=2)
    description: str | None = None


class TeamMemberRequest(BaseModel):
    user_id: str
    role: str = Field(pattern="^(owner|maintainer|member|viewer)$")


class ProjectRequest(BaseModel):
    name: str = Field(min_length=2)
    slug: str = Field(min_length=2)
    team_id: str | None = None
    description: str | None = None
    repo_url: str | None = None
    registry_namespace: str | None = None


class PolicyRequest(BaseModel):
    name: str = Field(min_length=2)
    project_id: str | None = None
    rules: dict[str, Any]


class AcceptRiskRequest(BaseModel):
    reason: str = Field(min_length=3)
    owner: str = Field(min_length=1)
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def require_future_expiry(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value <= datetime.now(timezone.utc):
            raise ValueError("expires_at must be a future timezone-aware datetime")
        return value


class UserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern="^[A-Za-z0-9._-]+$")
    display_name: str = Field(min_length=1, max_length=120)
    role: str = Field(pattern="^(admin|operator|viewer)$")
    api_key: str | None = Field(default=None, min_length=24)
    password: str = Field(min_length=12, max_length=256)


class UserUpdateRequest(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=120)
    role: str | None = Field(default=None, pattern="^(admin|operator|viewer)$")
    disabled: bool | None = None


class UserResetPasswordRequest(BaseModel):
    password: str = Field(min_length=12, max_length=256)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class PasswordRequest(BaseModel):
    current_password: str = Field(min_length=1)
    new_password: str = Field(min_length=12, max_length=256)


def current_user(
    x_api_key: str | None = Header(default=None),
    appsec_session: str | None = Cookie(default=None),
) -> dict[str, Any]:
    if not x_api_key and not appsec_session:
        raise HTTPException(status_code=401, detail="authentication required")
    with db.connect() as conn:
        user = db.user_by_api_key(conn, x_api_key) if x_api_key else None
        if not user and appsec_session:
            user = db.user_by_session(conn, appsec_session)
    if not user:
        raise HTTPException(status_code=401, detail="authentication required")
    return user


def require_role(*roles: str):
    def dependency(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="insufficient role")
        return user

    return dependency


def require_project(conn, user: dict[str, Any], project_id: Any, write: bool = False) -> None:
    # NULL means legacy/global content: visible to authenticated users.
    if project_id and not db.user_can_access_project(conn, user, str(project_id), write=write):
        raise HTTPException(status_code=403, detail="project access denied")


def require_resource(conn, user: dict[str, Any], kind: str, identifier: str, write: bool = False) -> None:
    queries = {
        "pipeline": "SELECT project_id FROM pipeline_runs WHERE id::text = %s",
        "pipeline_job": "SELECT project_id FROM pipeline_jobs WHERE id::text = %s",
        "security_job": "SELECT project_id FROM security_jobs WHERE id::text = %s",
        "finding": """SELECT j.project_id FROM security_findings f
                     JOIN security_jobs j ON j.id = f.job_id WHERE f.id::text = %s""",
        "scan": """SELECT p.project_id FROM scan_runs s
                   LEFT JOIN pipeline_runs p ON p.id = s.pipeline_id WHERE s.id::text = %s""",
        "artifact": """SELECT COALESCE(p.project_id, p2.project_id) AS project_id
                       FROM artifacts a LEFT JOIN pipeline_runs p ON p.id = a.pipeline_id
                       LEFT JOIN scan_runs s ON s.id = a.scan_id
                       LEFT JOIN pipeline_runs p2 ON p2.id = s.pipeline_id
                       WHERE a.id::text = %s""",
    }
    if kind not in queries:
        raise HTTPException(status_code=404, detail="unsupported resource")
    row = conn.execute(queries[kind], (identifier,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="resource not found")
    require_project(conn, user, row["project_id"], write=write)


@app.get("/")
def index() -> dict[str, str]:
    return {"service": "appsec-api", "status": "ok"}


@app.get("/health")
def health() -> dict[str, str]:
    with db.connect() as conn:
        conn.execute("SELECT 1").fetchone()
    return {"status": "ok"}


@app.get("/metrics")
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/api/auth/login")
def login(request: LoginRequest, response: Response) -> dict[str, Any]:
    with db.connect() as conn:
        user = db.authenticate_user(conn, request.username, request.password)
        if not user:
            raise HTTPException(status_code=401, detail="invalid username or password")
        token, expires_at = db.create_session(conn, str(user["id"]))
        db.insert_audit(conn, str(user["id"]), "auth.login", "user", str(user["id"]), {})
    response.set_cookie(
        "appsec_session",
        token,
        httponly=True,
        samesite="lax",
        secure=os.environ.get("APPSEC_SESSION_COOKIE_SECURE", "true").lower() in ("1", "true", "yes"),
        expires=expires_at,
        path="/",
    )
    return {"user": user, "expires_at": expires_at}


@app.post("/api/auth/logout")
def logout(
    response: Response,
    appsec_session: str | None = Cookie(default=None),
    user: dict[str, Any] = Depends(current_user),
) -> dict[str, str]:
    if appsec_session:
        with db.connect() as conn:
            db.revoke_session(conn, appsec_session)
            db.insert_audit(conn, str(user["id"]), "auth.logout", "user", str(user["id"]), {})
    response.delete_cookie("appsec_session", path="/")
    return {"status": "logged_out"}


@app.post("/pipelines")
def create_pipeline(
    request: PipelineRequest,
    user: dict[str, Any] = Depends(require_role("admin", "operator")),
) -> dict[str, Any]:
    if request.mode == "patch" and not request.confirm_patch:
        raise HTTPException(status_code=422, detail="patch and registry push require confirm_patch=true")
    if request.mode == "patch" and os.environ.get("APPSEC_PATCH_ENABLED", "false").lower() not in ("1", "true", "yes"):
        raise HTTPException(status_code=409, detail="patching is disabled; start with ./appsec start --patching and configure the registry")
    with db.connect() as conn:
        require_project(conn, user, request.project_id, write=True)
        job_id = db.enqueue_pipeline(conn, request.image, request.priority, request.project_id, mode=request.mode)
        db.insert_audit(conn, str(user["id"]), "pipeline.enqueue", "pipeline_job", job_id, request.model_dump())
    return {"job_id": job_id, "image": request.image, "mode": request.mode, "status": "queued"}


@app.get("/jobs")
def list_jobs(limit: int = 20, user: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
    with db.connect() as conn:
        return db.list_jobs(conn, limit, user)


@app.post("/jobs/{job_id}/stop")
def stop_pipeline_job(job_id: str, user: dict[str, Any] = Depends(require_role("admin", "operator"))) -> dict[str, str]:
    with db.connect() as conn:
        require_resource(conn, user, "pipeline_job", job_id, write=True)
        if not db.cancel_pipeline_job(conn, job_id):
            raise HTTPException(status_code=409, detail="only queued pipeline jobs can be stopped")
        db.insert_audit(conn, str(user["id"]), "pipeline_job.stop", "pipeline_job", job_id, {})
    return {"id": job_id, "status": "canceled"}


@app.delete("/jobs/{job_id}")
def delete_pipeline_job(job_id: str, user: dict[str, Any] = Depends(require_role("admin", "operator"))) -> dict[str, str]:
    with db.connect() as conn:
        require_resource(conn, user, "pipeline_job", job_id, write=True)
        if not db.delete_queued_pipeline_job(conn, job_id):
            raise HTTPException(status_code=409, detail="only queued pipeline jobs can be deleted")
        db.insert_audit(conn, str(user["id"]), "pipeline_job.delete", "pipeline_job", job_id, {})
    return {"id": job_id, "status": "deleted"}


@app.get("/pipelines/{pipeline_id}")
def get_pipeline(pipeline_id: str, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    with db.connect() as conn:
        pipeline = db.get_pipeline(conn, pipeline_id)
        if not pipeline:
            raise HTTPException(status_code=404, detail="pipeline not found")
        require_project(conn, user, pipeline.get("project_id"))
        payload = db.pipeline_summary(conn, pipeline_id)
    payload["reports"] = reports_with_downloads(payload.get("reports", []))
    return payload


@app.post("/schedules")
def create_schedule(
    request: ScheduleRequest,
    user: dict[str, Any] = Depends(require_role("admin", "operator")),
) -> dict[str, Any]:
    with db.connect() as conn:
        schedule_id = db.upsert_scheduled_image(conn, request.image, request.interval_minutes)
        db.insert_audit(conn, str(user["id"]), "schedule.upsert", "scheduled_image", schedule_id, request.model_dump())
    return {"schedule_id": schedule_id, "image": request.image, "interval_minutes": request.interval_minutes}


@app.get("/api/profile")
def profile(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return user


@app.post("/api/profile/password")
def change_password(request: PasswordRequest, user: dict[str, Any] = Depends(current_user)) -> dict[str, str]:
    with db.connect() as conn:
        authenticated = db.authenticate_user(conn, user["username"], request.current_password)
        if not authenticated:
            raise HTTPException(status_code=401, detail="current password is invalid")
        if request.current_password == request.new_password:
            raise HTTPException(status_code=422, detail="new password must differ from current password")
        conn.execute("""
            UPDATE users SET password_hash = %s, must_change_password=false,
              password_changed_at=now(), failed_login_count=0, locked_until=NULL
            WHERE id = %s
        """, (db.password_hash(request.new_password), user["id"]))
        db.revoke_all_sessions(conn, str(user["id"]))
        db.insert_audit(conn, str(user["id"]), "profile.password.change", "user", str(user["id"]), {})
    return {"status": "updated"}


@app.get("/api/dashboard")
def dashboard(user: dict[str, Any] = Depends(require_role("admin"))) -> dict[str, Any]:
    with db.connect() as conn:
        return db.dashboard_stats(conn)


@app.get("/api/history")
def history(q: str | None = None, limit: int = 50, user: dict[str, Any] = Depends(require_role("admin"))) -> dict[str, Any]:
    with db.connect() as conn:
        return db.search_history(conn, q, limit)


@app.get("/api/audit-logs")
def audit_logs(limit: int = 100, user: dict[str, Any] = Depends(require_role("admin"))) -> list[dict[str, Any]]:
    with db.connect() as conn:
        return db.list_audit_logs(conn, limit)


@app.get("/api/users")
def users(user: dict[str, Any] = Depends(require_role("admin"))) -> list[dict[str, Any]]:
    with db.connect() as conn:
        return db.list_users(conn)


@app.post("/api/users")
def create_user(request: UserRequest, user: dict[str, Any] = Depends(require_role("admin"))) -> dict[str, Any]:
    api_key = request.api_key or secrets.token_urlsafe(48)
    with db.connect() as conn:
        try:
            user_id = db.create_user(conn, request.username, request.display_name, request.role, api_key, request.password)
        except Exception as exc:
            if "unique" in str(exc).lower() or "duplicate" in str(exc).lower():
                raise HTTPException(status_code=409, detail="username already exists") from None
            raise
        conn.execute("UPDATE users SET must_change_password=true WHERE id=%s", (user_id,))
        db.insert_audit(conn, str(user["id"]), "user.create", "user", user_id, {"username": request.username})
    return {"id": user_id, "username": request.username, "role": request.role, "api_key": api_key}



@app.get("/api/users/{user_id}")
def user_detail(user_id: str, actor: dict[str, Any] = Depends(require_role("admin"))) -> dict[str, Any]:
    with db.connect() as conn:
        record = conn.execute("""
            SELECT id, username, display_name, role, disabled, must_change_password,
                   failed_login_count, locked_until, password_changed_at, api_key_rotated_at,
                   created_at, last_seen_at
            FROM users WHERE id=%s
        """, (user_id,)).fetchone()
        if not record:
            raise HTTPException(status_code=404, detail="user not found")
        return {
            "user": dict(record),
            "teams": db.list_user_memberships(conn, user_id),
            "sessions": db.list_user_sessions(conn, user_id),
        }


@app.patch("/api/users/{user_id}")
def update_user(
    user_id: str, request: UserUpdateRequest,
    actor: dict[str, Any] = Depends(require_role("admin")),
) -> dict[str, Any]:
    if not request.model_fields_set:
        raise HTTPException(status_code=422, detail="specify at least one user field to update")
    with db.connect() as conn:
        try:
            record = db.update_user_admin(
                conn, user_id, str(actor["id"]), display_name=request.display_name,
                role=request.role, disabled=request.disabled,
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        if not record:
            raise HTTPException(status_code=404, detail="user not found")
        db.insert_audit(conn, str(actor["id"]), "user.update", "user", user_id, {
            "role": record["role"], "disabled": record["disabled"],
        })
    return record


@app.post("/api/users/{user_id}/reset-password")
def reset_user_password(
    user_id: str, request: UserResetPasswordRequest,
    actor: dict[str, Any] = Depends(require_role("admin")),
) -> dict[str, str]:
    if str(user_id) == str(actor["id"]):
        raise HTTPException(status_code=409, detail="change your own password in My Profile with the current password")
    with db.connect() as conn:
        if not db.reset_user_password(conn, user_id, request.password):
            raise HTTPException(status_code=404, detail="user not found")
        db.insert_audit(conn, str(actor["id"]), "user.password.reset", "user", user_id, {})
    return {"status": "password_reset", "requires_change": "true"}


@app.post("/api/users/{user_id}/rotate-api-key")
def rotate_user_api_key(
    user_id: str, actor: dict[str, Any] = Depends(require_role("admin")),
) -> dict[str, str]:
    with db.connect() as conn:
        key = db.rotate_user_api_key(conn, user_id)
        if not key:
            raise HTTPException(status_code=404, detail="user not found")
        db.insert_audit(conn, str(actor["id"]), "user.api_key.rotate", "user", user_id, {})
    return {"status": "rotated", "api_key": key}


@app.post("/api/users/{user_id}/revoke-sessions")
def revoke_user_sessions(
    user_id: str, actor: dict[str, Any] = Depends(require_role("admin")),
) -> dict[str, int]:
    with db.connect() as conn:
        row = conn.execute("SELECT id FROM users WHERE id=%s", (user_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="user not found")
        count = db.revoke_all_sessions(conn, user_id)
        db.insert_audit(conn, str(actor["id"]), "user.sessions.revoke", "user", user_id, {"count": count})
    return {"revoked": count}


@app.delete("/api/teams/{team_id}/members/{user_id}")
def remove_member(
    team_id: str, user_id: str, actor: dict[str, Any] = Depends(require_role("admin")),
) -> dict[str, str]:
    with db.connect() as conn:
        result = conn.execute(
            "DELETE FROM team_members WHERE team_id=%s AND user_id=%s RETURNING user_id",
            (team_id, user_id),
        ).fetchone()
        if not result:
            raise HTTPException(status_code=404, detail="membership not found")
        db.insert_audit(conn, str(actor["id"]), "team.member.remove", "team", team_id, {"user_id": user_id})
    return {"status": "removed"}


@app.post("/api/security-jobs")
def create_security_job(
    request: SecurityJobRequest,
    user: dict[str, Any] = Depends(require_role("admin", "operator")),
) -> dict[str, Any]:
    with db.connect() as conn:
        if request.project_id and not db.user_can_access_project(conn, user, request.project_id, write=True):
            raise HTTPException(status_code=403, detail="project access denied")
    try:
        validate_repo_target(request.target)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    job_id = enqueue_security_job(request.kind, request.target, str(user["id"]), request.priority, request.profile, request.project_id)
    with db.connect() as conn:
        db.insert_audit(conn, str(user["id"]), "security.enqueue", "security_job", job_id, request.model_dump())
    return {"job_id": job_id, "kind": request.kind, "target": request.target, "status": "queued"}


@app.get("/api/teams")
def teams(user: dict[str, Any] = Depends(require_role("admin"))) -> list[dict[str, Any]]:
    with db.connect() as conn:
        return db.list_teams(conn)


@app.post("/api/teams")
def create_team(request: TeamRequest, user: dict[str, Any] = Depends(require_role("admin"))) -> dict[str, Any]:
    with db.connect() as conn:
        team_id = db.create_team(conn, request.name, request.description)
        db.insert_audit(conn, str(user["id"]), "team.create", "team", team_id, request.model_dump())
    return {"id": team_id, "name": request.name}


@app.post("/api/teams/{team_id}/members")
def add_team_member(team_id: str, request: TeamMemberRequest, user: dict[str, Any] = Depends(require_role("admin"))) -> dict[str, str]:
    with db.connect() as conn:
        db.add_team_member(conn, team_id, request.user_id, request.role)
        db.insert_audit(conn, str(user["id"]), "team.member.upsert", "team", team_id, request.model_dump())
    return {"team_id": team_id, "user_id": request.user_id, "role": request.role}


@app.get("/api/projects")
def projects(user: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
    with db.connect() as conn:
        return db.list_projects(conn, user)


@app.post("/api/projects")
def create_project(request: ProjectRequest, user: dict[str, Any] = Depends(require_role("admin"))) -> dict[str, Any]:
    with db.connect() as conn:
        project_id = db.create_project(
            conn,
            request.name,
            request.slug,
            request.team_id,
            request.description,
            request.repo_url,
            request.registry_namespace,
        )
        db.insert_audit(conn, str(user["id"]), "project.create", "project", project_id, request.model_dump())
    return {"id": project_id, "name": request.name, "slug": request.slug}


@app.get("/api/policies")
def policies(project_id: str | None = None, user: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
    with db.connect() as conn:
        if not project_id and user["role"] != "admin":
            raise HTTPException(status_code=403, detail="global policies require admin")
        if project_id:
            require_project(conn, user, project_id)
        return db.list_policies(conn, project_id)


@app.post("/api/policies")
def create_policy(request: PolicyRequest, user: dict[str, Any] = Depends(require_role("admin", "operator"))) -> dict[str, Any]:
    with db.connect() as conn:
        if request.project_id and not db.user_can_access_project(conn, user, request.project_id, write=True):
            raise HTTPException(status_code=403, detail="project access denied")
        policy_id = db.create_policy(conn, request.name, request.rules, request.project_id, str(user["id"]))
        db.insert_audit(conn, str(user["id"]), "policy.create", "policy", policy_id, request.model_dump())
    return {"id": policy_id, "name": request.name}


@app.get("/api/security-jobs")
def security_jobs(limit: int = 50, user: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
    with db.connect() as conn:
        return db.list_security_jobs(conn, limit, user)


@app.post("/api/security-jobs/{job_id}/stop")
def stop_security_job(job_id: str, user: dict[str, Any] = Depends(require_role("admin", "operator"))) -> dict[str, str]:
    with db.connect() as conn:
        require_resource(conn, user, "security_job", job_id, write=True)
        if not db.cancel_security_job(conn, job_id):
            raise HTTPException(status_code=409, detail="only queued security jobs can be stopped")
        db.insert_audit(conn, str(user["id"]), "security_job.stop", "security_job", job_id, {})
    return {"id": job_id, "status": "canceled"}


@app.delete("/api/security-jobs/{job_id}")
def delete_security_job(job_id: str, user: dict[str, Any] = Depends(require_role("admin", "operator"))) -> dict[str, str]:
    with db.connect() as conn:
        require_resource(conn, user, "security_job", job_id, write=True)
        if not db.delete_queued_security_job(conn, job_id):
            raise HTTPException(status_code=409, detail="only queued security jobs can be deleted")
        db.insert_audit(conn, str(user["id"]), "security_job.delete", "security_job", job_id, {})
    return {"id": job_id, "status": "deleted"}


@app.get("/api/security-jobs/{job_id}")
def security_job(job_id: str, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    with db.connect() as conn:
        detail = db.security_job_detail(conn, job_id)
        if detail:
            require_project(conn, user, detail["job"].get("project_id"))
    if not detail:
        raise HTTPException(status_code=404, detail="security job not found")
    detail["reports"] = reports_with_downloads(detail.get("reports", []))
    return detail


@app.post("/api/security-findings/{finding_id}/accept")
def accept_finding(
    finding_id: str,
    request: AcceptRiskRequest,
    user: dict[str, Any] = Depends(require_role("admin", "operator")),
) -> dict[str, Any]:
    with db.connect() as conn:
        require_resource(conn, user, "finding", finding_id, write=True)
        risk_id = db.accept_security_finding(
            conn,
            finding_id,
            request.reason,
            request.owner,
            request.expires_at.isoformat(),
            str(user["id"]),
        )
        db.insert_audit(conn, str(user["id"]), "risk.accept", "security_finding", finding_id, request.model_dump(mode="json"))
    return {"risk_id": risk_id, "finding_id": finding_id}


@app.post("/api/security-jobs/{job_id}/reports/html")
def security_html_report(job_id: str, user: dict[str, Any] = Depends(current_user)) -> dict[str, str]:
    with db.connect() as conn:
        require_resource(conn, user, "security_job", job_id)
        detail = db.security_job_detail(conn, job_id)
    if not detail:
        raise HTTPException(status_code=404, detail="security job not found")
    try:
        path = write_html_report("security_job", job_id, detail)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    with db.connect() as conn:
        report = db.latest_generated_report(conn, "security_job", job_id, "html")
    return report_response(report, path)


@app.post("/api/security-jobs/{job_id}/reports/sarif")
def security_sarif_report(job_id: str, user: dict[str, Any] = Depends(current_user)) -> dict[str, str]:
    with db.connect() as conn:
        require_resource(conn, user, "security_job", job_id)
    path = write_security_sarif(job_id)
    with db.connect() as conn:
        report = db.latest_generated_report(conn, "security_job", job_id, "sarif")
    return report_response(report, path)


@app.post("/api/pipelines/{pipeline_id}/reports/html")
def pipeline_html_report(pipeline_id: str, user: dict[str, Any] = Depends(current_user)) -> dict[str, str]:
    with db.connect() as conn:
        require_resource(conn, user, "pipeline", pipeline_id)
        payload = db.pipeline_summary(conn, pipeline_id)
    if not payload.get("pipeline"):
        raise HTTPException(status_code=404, detail="pipeline not found")
    try:
        path = write_html_report("pipeline", pipeline_id, payload)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    with db.connect() as conn:
        report = db.latest_generated_report(conn, "pipeline", pipeline_id, "html")
    return report_response(report, path)


@app.get("/api/pipelines/{pipeline_id}/reports")
def pipeline_reports(pipeline_id: str, user: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
    with db.connect() as conn:
        require_resource(conn, user, "pipeline", pipeline_id)
        return reports_with_downloads(db.list_generated_reports(conn, "pipeline", pipeline_id))


@app.get("/api/security-jobs/{job_id}/reports")
def security_reports(job_id: str, user: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
    with db.connect() as conn:
        require_resource(conn, user, "security_job", job_id)
        return reports_with_downloads(db.list_generated_reports(conn, "security_job", job_id))


@app.get("/api/reports/{report_id}/download")
def download_report(report_id: str, request: Request):
    user = require_download_auth(request)
    with db.connect() as conn:
        report = db.generated_report(conn, report_id)
        if report:
            require_resource(conn, user, report["resource_type"], report["resource_id"])
    if not report:
        raise HTTPException(status_code=404, detail="report not found")
    return download_path(str(report["path"]))


@app.get("/api/artifacts/{artifact_id}/download")
def download_artifact(artifact_id: str, request: Request):
    user = require_download_auth(request)
    with db.connect() as conn:
        require_resource(conn, user, "artifact", artifact_id)
        artifact = db.artifact(conn, artifact_id)
    if not artifact:
        raise HTTPException(status_code=404, detail="artifact not found")
    return download_path(str(artifact["path"]))


@app.get("/api/scans/{scan_id}/report/download")
def download_scan_report(scan_id: str, request: Request):
    user = require_download_auth(request)
    with db.connect() as conn:
        require_resource(conn, user, "scan", scan_id)
        try:
            scan = db.get_scan(conn, scan_id)
        except RuntimeError:
            raise HTTPException(status_code=404, detail="scan not found") from None
    report_path = scan.get("report_path")
    if not report_path:
        raise HTTPException(status_code=404, detail="scan report not found")
    return download_path(str(report_path))


def reports_with_downloads(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{**report, "download_url": external_api_path(f"/api/reports/{report['id']}/download")} for report in reports]


def report_response(report: dict[str, Any] | None, path: str) -> dict[str, str]:
    if not report:
        return {"path": path}
    return {
        "id": str(report["id"]),
        "path": str(report["path"]),
        "download_url": external_api_path(f"/api/reports/{report['id']}/download"),
    }


def download_path(path: str):
    if path.startswith("s3://"):
        return RedirectResponse(presigned_download_url(path))
    report_file = Path(path)
    reports_root = Path("/reports").resolve()
    try:
        resolved = report_file.resolve()
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="file not found") from None
    if not resolved.is_file() or not resolved.is_relative_to(reports_root):
        raise HTTPException(status_code=404, detail="file not found")
    return FileResponse(str(resolved), filename=resolved.name, media_type="application/octet-stream")


def external_api_path(path: str) -> str:
    prefix = os.environ.get("APPSEC_API_EXTERNAL_PREFIX", "/appsec-api").rstrip("/")
    return f"{prefix}{path}"


def require_download_auth(request: Request) -> dict[str, Any]:
    # A UUID or artifact URL is not an authentication mechanism.
    return current_user(
        x_api_key=request.headers.get("X-API-Key"),
        appsec_session=request.cookies.get("appsec_session"),
    )


@app.post("/api/maintenance/cleanup")
def cleanup(days: int = 30, user: dict[str, Any] = Depends(require_role("admin"))) -> dict[str, Any]:
    with db.connect() as conn:
        result = db.cleanup_old_records(conn, days)
        db.insert_audit(conn, str(user["id"]), "maintenance.cleanup", None, None, {"days": days, "result": result})
    return {"days": days, "deleted": result}


@app.post("/api/integrations/test-webhook")
def test_webhook(user: dict[str, Any] = Depends(require_role("admin"))) -> dict[str, str]:
    notify("appsec.test", {"user": user["username"]})
    return {"status": "sent_if_configured"}


# First-party UI. No separate frontend runtime, external CDN, or demo dataset.
WEB_ROOT = Path(__file__).with_name("webui")
app.mount("/ui/assets", StaticFiles(directory=str(WEB_ROOT / "assets")), name="ui-assets")


@app.get("/ui/", include_in_schema=False)
def appsec_control_center() -> FileResponse:
    return FileResponse(WEB_ROOT / "index.html", media_type="text/html")


@app.get("/ui", include_in_schema=False)
def appsec_control_center_redirect() -> RedirectResponse:
    return RedirectResponse("/ui/")


@app.get("/api/ui/overview")
def ui_overview(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    """Lightweight, tenant-aware overview for the first-party UI."""
    from .ui_queries import overview_data

    with db.connect() as conn:
        return overview_data(conn, user)


@app.get("/api/ui/pipelines/{pipeline_id}")
def ui_pipeline(
    pipeline_id: str, user: dict[str, Any] = Depends(current_user)
) -> dict[str, Any]:
    """Compact result without raw Trivy JSON; access-scoped by pipeline."""
    from .ui_queries import pipeline_details

    with db.connect() as conn:
        require_resource(conn, user, "pipeline", pipeline_id)
        return pipeline_details(conn, pipeline_id)


@app.get("/api/ui/scans/{scan_id}/vulnerabilities")
def ui_scan_vulnerabilities(
    scan_id: str,
    severity: str | None = None,
    limit: int = 100,
    user: dict[str, Any] = Depends(current_user),
) -> dict[str, Any]:
    from .ui_queries import scan_vulnerabilities

    with db.connect() as conn:
        require_resource(conn, user, "scan", scan_id)
        if severity and severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
            raise HTTPException(status_code=422, detail="unknown severity")
        return scan_vulnerabilities(conn, scan_id, severity, limit)


@app.get("/api/ui/security-jobs/{job_id}")
def ui_security_job(
    job_id: str, user: dict[str, Any] = Depends(current_user)
) -> dict[str, Any]:
    with db.connect() as conn:
        require_resource(conn, user, "security_job", job_id)
        detail = db.security_job_detail(conn, job_id)
        if not detail:
            raise HTTPException(status_code=404, detail="job not found")
    job = detail["job"]
    safe_job = {
        key: job.get(key) for key in (
            "id", "kind", "target", "status", "finding_count", "high_count",
            "medium_count", "low_count", "started_at", "finished_at",
            "error_message", "project_id",
        )
    }
    safe_findings = [
        {key: finding.get(key) for key in (
            "id", "rule_id", "severity", "title", "location", "created_at"
        )}
        for finding in detail.get("findings", [])
    ]
    return {
        "job": safe_job,
        "findings": safe_findings,
        "reports": reports_with_downloads(detail.get("reports", [])),
    }


@app.get("/api/ui/capabilities")
def ui_capabilities(user: dict[str, Any] = Depends(current_user)) -> dict[str, bool]:
    """Reflect active deployment state rather than assuming patch is available."""
    return {"patch_enabled": os.environ.get("APPSEC_PATCH_ENABLED", "false").lower() in ("1", "true", "yes")}


@app.get("/api/ui/system/health")
def ui_system_health(user: dict[str, Any] = Depends(require_role("admin"))) -> dict[str, Any]:
    """Real service and queue health; no Docker Socket access from API."""
    with db.connect() as conn:
        return db.service_health_summary(conn)


@app.post("/api/manual-workflows", status_code=201)
def create_manual_workflow(
    request: ManualWorkflowRequest,
    user: dict[str, Any] = Depends(require_role("admin", "operator")),
) -> dict[str, Any]:
    from . import manual_workflows as mw
    with db.connect() as conn:
        require_project(conn, user, request.project_id, write=True)
        try:
            result = mw.create(conn, request.image, request.project_id, str(user["id"]))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        db.insert_audit(conn, str(user["id"]), "manual.create", "manual_workflow", result["id"], {
            "image": request.image, "project_id": request.project_id,
        })
    return result


@app.get("/api/manual-workflows")
def list_manual_workflows(
    limit: int = 40, user: dict[str, Any] = Depends(current_user),
) -> list[dict[str, Any]]:
    from . import manual_workflows as mw
    with db.connect() as conn:
        return mw.list_workflows(conn, user, limit)


@app.get("/api/manual-workflows/{workflow_id}")
def get_manual_workflow(
    workflow_id: str, user: dict[str, Any] = Depends(current_user),
) -> dict[str, Any]:
    from . import manual_workflows as mw
    from .ui_queries import pipeline_details
    with db.connect() as conn:
        try:
            record = mw.get_workflow(conn, workflow_id, user)
        except ValueError:
            raise HTTPException(status_code=404, detail="workflow not found") from None
        if not record:
            raise HTTPException(status_code=404, detail="workflow not found")
        pipeline = pipeline_details(conn, str(record["pipeline_id"])) if record.get("pipeline_id") else None
    return {
        "workflow": record,
        "pipeline": pipeline,
        "patch_enabled": os.environ.get("APPSEC_PATCH_ENABLED", "false").lower() in ("1", "true", "yes"),
        "registry_destination": os.environ.get("REGISTRY_HOST", "") + "/" +
            os.environ.get("PATCHED_REPOSITORY", ""),
    }


@app.post("/api/manual-workflows/{workflow_id}/decision")
def decide_manual_workflow(
    workflow_id: str, request: ManualDecisionRequest,
    user: dict[str, Any] = Depends(require_role("admin", "operator")),
) -> dict[str, Any]:
    from . import manual_workflows as mw
    if request.action == "approve_patch":
        if not request.confirm_push:
            raise HTTPException(status_code=422, detail="registry push requires explicit confirmation")
        if os.environ.get("APPSEC_PATCH_ENABLED", "false").lower() not in ("1", "true", "yes"):
            raise HTTPException(status_code=409, detail="patching disabled; start AppSec with --patching")
    with db.connect() as conn:
        try:
            result = mw.decide(conn, workflow_id, user, request.action, request.confirm_push)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from None
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        db.insert_audit(
            conn, str(user["id"]), "manual." + request.action,
            "manual_workflow", workflow_id,
            {"confirmed_push": request.confirm_push},
        )
    return result
