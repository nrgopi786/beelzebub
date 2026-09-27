# Honeypot management console. Build context: console/
FROM docker:29-cli AS dockercli

FROM python:3.13-slim

# iproute2: deploy.sh checks host port availability with `ss` (console runs in the host netns).
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=dockercli /usr/local/libexec/docker/cli-plugins /usr/local/libexec/docker/cli-plugins

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    UVICORN_HOST=127.0.0.1 UVICORN_PORT=8088

# Overridden at runtime with the host user's uid:gid (see compose.yml).
USER 65532:65532

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["python", "-c", "import os,urllib.request; urllib.request.urlopen(f\"http://{os.environ['UVICORN_HOST'].replace('0.0.0.0','127.0.0.1')}:{os.environ['UVICORN_PORT']}/static/style.css\", timeout=4)"]

CMD ["uvicorn", "app.main:app", "--no-server-header", "--log-level", "info"]
