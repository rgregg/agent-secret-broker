# Throwaway environment for tests/e2e_remote_exec/driver.py: the OpenSSH client programs and a real sshd, an
# unprivileged user, and the broker's own Python code. Build context is the repository root:
#   docker build -f tests/e2e_remote_exec/Dockerfile .      (see run.sh)

FROM python:3.12-slim
# ASB_E2E_REQUIRE: a missing OpenSSH program is a failure here, not a skip.
ENV ASB_E2E_REQUIRE=1 PYTHONUNBUFFERED=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server openssh-client procps \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && useradd -m -s /bin/sh tester
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
WORKDIR /repo
COPY secret_broker /repo/secret_broker
COPY tests/e2e_remote_exec /repo/tests/e2e_remote_exec
# The driver starts its own sshd on a loopback port as this user; nothing needs root.
USER tester
CMD ["python", "tests/e2e_remote_exec/driver.py"]
