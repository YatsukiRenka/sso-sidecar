FROM python:3.12.13-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore

RUN groupadd --gid 10001 sidecar \
    && useradd --uid 10001 --gid sidecar --no-create-home \
        --shell /usr/sbin/nologin sidecar

WORKDIR /app
COPY requirements.txt .
RUN pip install --requirement requirements.txt

COPY --chown=sidecar:sidecar app.py .
RUN mkdir -p /var/lib/sso-sidecar \
    && chown sidecar:sidecar /var/lib/sso-sidecar

USER 10001:10001
EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; port = os.environ.get('LISTEN_PORT', '8001'); urllib.request.urlopen(f'http://127.0.0.1:{port}/_sso_health', timeout=3).read()"]

CMD ["python", "app.py"]
