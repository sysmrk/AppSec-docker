from __future__ import annotations

import os
from pathlib import Path

import boto3
from botocore.client import Config


def s3_enabled() -> bool:
    return os.environ.get("ARTIFACT_STORAGE", "local").lower() == "s3"


def upload_artifact(path: str, key_prefix: str = "reports") -> str:
    if not s3_enabled():
        return path

    bucket = os.environ.get("S3_BUCKET", "appsec-artifacts")
    endpoint = os.environ.get("S3_ENDPOINT_URL")
    region = os.environ.get("S3_REGION", "us-east-1")
    access_key = secret_or_env("S3_ACCESS_KEY_ID")
    secret_key = secret_or_env("S3_SECRET_ACCESS_KEY")
    file_path = Path(path)
    key = f"{key_prefix.strip('/')}/{file_path.name}"

    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        region_name=region,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        config=Config(signature_version="s3v4"),
    )
    try:
        client.upload_file(str(file_path), bucket, key)
        return f"s3://{bucket}/{key}"
    except Exception:
        if os.environ.get("ARTIFACT_UPLOAD_STRICT", "false").lower() in ("1", "true", "yes"):
            raise
        return path


def presigned_download_url(s3_uri: str, expires_in: int = 900, filename: str | None = None) -> str:
    if not s3_uri.startswith("s3://"):
        raise ValueError("not an s3 uri")
    bucket_key = s3_uri.removeprefix("s3://")
    bucket, _, key = bucket_key.partition("/")
    if not bucket or not key:
        raise ValueError("invalid s3 uri")
    endpoint = os.environ.get("S3_PUBLIC_ENDPOINT_URL") or os.environ.get("S3_ENDPOINT_URL")
    region = os.environ.get("S3_REGION", "us-east-1")
    access_key = secret_or_env("S3_ACCESS_KEY_ID")
    secret_key = secret_or_env("S3_SECRET_ACCESS_KEY")
    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        region_name=region,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        config=Config(signature_version="s3v4"),
    )
    return client.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": key, **({"ResponseContentDisposition": f'attachment; filename="{filename}"'} if filename else {})},
        ExpiresIn=expires_in,
    )


def secret_or_env(name: str, default: str | None = None) -> str | None:
    file_path = os.environ.get(f"{name}_FILE")
    if file_path and Path(file_path).exists():
        return Path(file_path).read_text(encoding="utf-8").strip()
    return os.environ.get(name, default)
