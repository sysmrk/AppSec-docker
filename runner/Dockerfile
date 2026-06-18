FROM python:3.12-slim

ARG COPA_VERSION=0.14.1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        tar \
    && rm -rf /var/lib/apt/lists/*

RUN curl --retry 5 --retry-all-errors -fsSL \
        -o /tmp/copa.tar.gz \
        "https://github.com/project-copacetic/copacetic/releases/download/v${COPA_VERSION}/copa_${COPA_VERSION}_linux_amd64.tar.gz" \
    && tar -xzf /tmp/copa.tar.gz -C /usr/local/bin copa \
    && rm -f /tmp/copa.tar.gz \
    && copa --version

WORKDIR /app

COPY runner/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY runner/appsecctl ./appsecctl
COPY alembic.ini ./alembic.ini
COPY migrations ./migrations
COPY db ./db

ENTRYPOINT ["python", "-m", "appsecctl.cli"]
