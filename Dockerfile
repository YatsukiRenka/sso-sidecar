FROM python:3.14.6-slim@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6

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
RUN python -m pip install --requirement requirements.txt \
    && python -m pip uninstall --yes pip

COPY --chown=root:root app.py .
RUN chmod 0444 /app/app.py \
    && mkdir -p /var/lib/sso-sidecar \
    && chown sidecar:sidecar /var/lib/sso-sidecar

USER 10001:10001
EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; port = os.environ.get('LISTEN_PORT', '8001'); urllib.request.urlopen(f'http://127.0.0.1:{port}/_sso_health', timeout=3).read()"]

CMD ["python", "app.py"]
