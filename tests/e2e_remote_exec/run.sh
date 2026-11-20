#!/bin/sh
# Run the remote-exec end-to-end test in a throwaway container with real OpenSSH. Nothing on this machine is
# changed: no host mounts, no --privileged, no Docker socket, and --rm deletes the container afterwards.
#   tests/e2e_remote_exec/run.sh
# (Without Docker, `python tests/e2e_remote_exec/driver.py` runs the same checks here if OpenSSH is installed.)
set -eu
cd "$(dirname "$0")/../.."
docker build -f tests/e2e_remote_exec/Dockerfile -t asb-remote-exec-e2e .
# --network none: the broker, the sshd and the agent all talk over the container's own loopback.
exec docker run --rm --network none --pids-limit 256 --memory 1g asb-remote-exec-e2e
