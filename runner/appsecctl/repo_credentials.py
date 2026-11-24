"""Short-lived one-job credentials; never include secrets in job/API/log data."""
import base64
import hashlib
import json
import os
from cryptography.fernet import Fernet, InvalidToken

def cipher():
    key = os.environ.get("APPSEC_MFA_ENCRYPTION_KEY", "")
    try:
        raw = base64.urlsafe_b64decode(key)
        if len(raw) != 32:
            raise ValueError()
        return Fernet(base64.urlsafe_b64encode(hashlib.sha256(b"appsec-repo-credential-v1:" + raw).digest()))
    except (ValueError, TypeError):
        raise RuntimeError("Repository credential encryption key is unavailable") from None

def store(conn, job_id, username, password):
    if not username or not password or any(c in username + password for c in ("\n", "\r", "\x00")):
        raise ValueError("Enter a username and password/token without control characters")
    token = cipher().encrypt(json.dumps([username, password]).encode()).decode()
    conn.execute("INSERT INTO repository_job_credentials(job_id,ciphertext) VALUES (%s,%s)", (job_id, token))
    conn.execute("UPDATE security_jobs SET max_attempts=1 WHERE id=%s", (job_id,))

def consume(conn, job_id):
    row = conn.execute("DELETE FROM repository_job_credentials WHERE job_id=%s RETURNING ciphertext, expires_at > now() AS valid", (job_id,)).fetchone()
    if not row:
        return None
    if not row["valid"]:
        raise RuntimeError("GIT_CLONE_FAILED: Repository credentials expired; submit a new scan")
    try:
        return tuple(json.loads(cipher().decrypt(row["ciphertext"].encode()).decode()))
    except (InvalidToken, ValueError):
        raise RuntimeError("GIT_CLONE_FAILED: Repository credentials cannot be decrypted") from None
