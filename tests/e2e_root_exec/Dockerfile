# Throwaway environment for tests/e2e_root_exec/driver.py: real root, real sudo, an unprivileged `agent` user.
# Build context is the repository root:  docker build -f tests/e2e_root_exec/Dockerfile .   (see run.sh)

FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
RUN cargo build --release --locked -p asb-root-exec

FROM python:3.12-slim-bookworm
# The driver edits /etc and creates users, and refuses to run anywhere that has not said it is disposable.
ENV ASB_E2E_DISPOSABLE=1 ASB_E2E_HELPER=/opt/asb-root-exec.build PYTHONUNBUFFERED=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends sudo \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY --from=build /src/target/release/asb-root-exec /opt/asb-root-exec.build
WORKDIR /repo
COPY secret_broker /repo/secret_broker
COPY client /repo/client
COPY tests/e2e_root_exec /repo/tests/e2e_root_exec
CMD ["python", "tests/e2e_root_exec/driver.py"]
