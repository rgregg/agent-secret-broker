# syntax=docker/dockerfile:1
# Stage 1: fetch the official native Bitwarden CLI, pinned by version + SHA-256
# (bump both together; sha256 of bw-linux-<version>.zip from the cli-v<version> release).
FROM python:3.12-slim AS bw
ARG BW_VERSION=2026.9.1
ARG BW_SHA256=84289eaf59d691f04242605112f21b00e8dba65acdedbc60dde001a2860f2097
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates \
 && curl -fsSL -o /tmp/bw.zip "https://github.com/bitwarden/clients/releases/download/cli-v${BW_VERSION}/bw-linux-${BW_VERSION}.zip" \
 && echo "${BW_SHA256}  /tmp/bw.zip" | sha256sum -c - \
 && unzip -q /tmp/bw.zip -d /out && chmod 0755 /out/bw

# Stage 2: runtime (stdlib-only Python + the bw binary)
FROM python:3.12-slim
COPY --from=bw /out/bw /usr/local/bin/bw
WORKDIR /app
COPY secret_broker ./secret_broker
USER nobody
CMD ["python", "-m", "secret_broker", "--config", "/data/config.json"]
