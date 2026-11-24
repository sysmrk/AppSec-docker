ARG RUNNER_BASE_IMAGE=python:3.12-slim
FROM ${RUNNER_BASE_IMAGE}

ARG COPA_VERSION=0.14.1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Optional trusted Debian archive mirror (base URL without /debian).
ARG DEBIAN_MIRROR=
RUN if [ -n "${DEBIAN_MIRROR}" ]; then \
        sed -i -e "s|http://deb.debian.org/debian-security|${DEBIAN_MIRROR%/}/debian-security|g" \
               -e "s|http://deb.debian.org/debian|${DEBIAN_MIRROR%/}/debian|g" \
               /etc/apt/sources.list.d/debian.sources; \
    fi

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
ARG PIP_INDEX_URL=https://pypi.org/simple
RUN pip install --no-cache-dir --index-url "${PIP_INDEX_URL}" -r requirements.txt

COPY runner/appsecctl ./appsecctl
COPY alembic.ini ./alembic.ini
COPY migrations ./migrations
COPY db ./db

# Stamp late so revision changes do not invalidate dependency installation.
ARG APPSEC_BUILD_REVISION=unknown
RUN printf '%s\n' "$APPSEC_BUILD_REVISION" > /app/.appsec-build-revision
LABEL org.opencontainers.image.revision=$APPSEC_BUILD_REVISION

ENTRYPOINT ["python", "-m", "appsecctl.cli"]
