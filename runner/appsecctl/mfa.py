"""Optional TOTP MFA with encrypted secrets, replay protection and one-use recovery codes.

Fernet key must be provisioned in APPSEC_MFA_ENCRYPTION_KEY and retained
through backup/restore. OIDC/enterprise identity is a separate future integration.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from urllib.parse import quote

import pyotp
from cryptography.fernet import Fernet, InvalidToken

from . import db


def _cipher() -> Fernet:
    key = os.environ.get("APPSEC_MFA_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("MFA encryption key is not configured; ask administrator to set APPSEC_MFA_ENCRYPTION_KEY")
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise RuntimeError("MFA encryption key is invalid") from exc


def generate_secret() -> str:
    return pyotp.random_base32()


def encrypt_secret(secret: str) -> str:
    return _cipher().encrypt(secret.encode("ascii")).decode("ascii")


def decrypt_secret(encrypted: str) -> str:
    try:
        return _cipher().decrypt(encrypted.encode("ascii")).decode("ascii")
    except (InvalidToken, ValueError) as exc:
        raise RuntimeError("MFA secret could not be decrypted; verify the configured encryption key") from exc


def totp_step(secret: str, code: str, last_step: int = -1, now: int | None = None) -> int | None:
    otp = code.strip()
    if len(otp) != 6 or not otp.isdecimal():
        return None
    clock = int(time.time()) if now is None else int(now)
    current = clock // 30
    totp = pyotp.TOTP(secret)
    for step in (current - 1, current, current + 1):
        if step <= last_step:
            continue
        if hmac.compare_digest(totp.at(step * 30), otp):
            return step
    return None


def register_failure(conn, user_id: str) -> None:
    conn.execute("""
        UPDATE users SET failed_login_count=failed_login_count + 1,
            locked_until=CASE WHEN failed_login_count + 1 >= 5
                THEN now() + interval '15 minutes' ELSE NULL END
        WHERE id=%s
    """, (user_id,))


def verify_login(conn, user_id: str, code: str) -> bool:
    row = conn.execute("""
        SELECT mfa_secret_enc, mfa_last_step FROM users
        WHERE id=%s AND mfa_enabled=true AND disabled=false
        FOR UPDATE
    """, (user_id,)).fetchone()
    if not row or not row["mfa_secret_enc"]:
        return False
    code = code.strip().upper()
    # One-use backup codes are 12 hex digits; no plaintext is stored.
    if len(code) == 12 and all(ch in "0123456789ABCDEF" for ch in code):
        result = conn.execute("""
            UPDATE mfa_recovery_codes SET used_at=now()
            WHERE user_id=%s AND code_hash=%s AND used_at IS NULL
            RETURNING id
        """, (user_id, hashlib.sha256(code.encode("ascii")).hexdigest())).fetchone()
        if result:
            conn.execute(
                "UPDATE users SET failed_login_count=0, locked_until=NULL WHERE id=%s", (user_id,)
            )
            return True
    step = totp_step(decrypt_secret(row["mfa_secret_enc"]), code, int(row["mfa_last_step"]))
    if step is None:
        register_failure(conn, user_id)
        return False
    updated = conn.execute("""
        UPDATE users SET mfa_last_step=%s, failed_login_count=0, locked_until=NULL
        WHERE id=%s AND mfa_last_step<%s RETURNING id
    """, (step, user_id, step)).fetchone()
    return bool(updated)


def begin_enrollment(conn, user_id: str, password: str) -> dict[str, str]:
    user = conn.execute("""
        SELECT username, password_hash, mfa_enabled FROM users
        WHERE id=%s AND disabled=false FOR UPDATE
    """, (user_id,)).fetchone()
    if not user or not db.verify_password(password, user["password_hash"]):
        raise ValueError("Current password is incorrect")
    if user["mfa_enabled"]:
        raise ValueError("MFA already enabled. Disable it with a valid code first")
    secret = generate_secret()
    conn.execute("""
        UPDATE users SET mfa_pending_enc=%s, mfa_pending_at=now() WHERE id=%s
    """, (encrypt_secret(secret), user_id))
    return {
        "secret": secret,
        "provisioning_uri": pyotp.totp.TOTP(secret).provisioning_uri(
            name=user["username"], issuer_name="AppSec Control Center"
        ),
    }


def confirm_enrollment(conn, user_id: str, code: str) -> list[str]:
    row = conn.execute("""
        SELECT mfa_pending_enc FROM users
        WHERE id=%s AND mfa_enabled=false AND mfa_pending_at > now() - interval '10 minutes'
        FOR UPDATE
    """, (user_id,)).fetchone()
    if not row or not row["mfa_pending_enc"]:
        raise ValueError("MFA setup expired; start enrollment again")
    secret = decrypt_secret(row["mfa_pending_enc"])
    step = totp_step(secret, code)
    if step is None:
        raise ValueError("Incorrect authentication code; check the time on your device")
    conn.execute("""
        UPDATE users SET mfa_secret_enc=mfa_pending_enc, mfa_pending_enc=NULL,
            mfa_pending_at=NULL, mfa_enabled=true, mfa_last_step=%s,
            failed_login_count=0, locked_until=NULL WHERE id=%s
    """, (step, user_id))
    recovery = [secrets.token_hex(6).upper() for _ in range(8)]
    conn.execute("DELETE FROM mfa_recovery_codes WHERE user_id=%s", (user_id,))
    for item in recovery:
        conn.execute("""
            INSERT INTO mfa_recovery_codes(id,user_id,code_hash)
            VALUES (%s,%s,%s)
        """, (str(__import__("uuid").uuid4()), user_id, hashlib.sha256(item.encode("ascii")).hexdigest()))
    db.revoke_all_sessions(conn, user_id)
    return recovery


def disable_mfa(conn, user_id: str, password: str, code: str) -> bool:
    user = conn.execute("""
        SELECT password_hash, mfa_enabled FROM users
        WHERE id=%s AND disabled=false
    """, (user_id,)).fetchone()
    if not user or not user["mfa_enabled"] or not db.verify_password(password, user["password_hash"]):
        return False
    if not verify_login(conn, user_id, code):
        return False
    conn.execute("""
        UPDATE users SET mfa_enabled=false, mfa_secret_enc=NULL, mfa_pending_enc=NULL,
            mfa_pending_at=NULL, mfa_last_step=-1 WHERE id=%s
    """, (user_id,))
    conn.execute("DELETE FROM mfa_recovery_codes WHERE user_id=%s", (user_id,))
    db.revoke_all_sessions(conn, user_id)
    return True
