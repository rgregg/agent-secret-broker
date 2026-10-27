#!/bin/sh
# Run the root-helper end-to-end test in a throwaway container. Nothing on this machine is changed:
# no host mounts, no --privileged, no Docker socket, and --rm deletes the container afterwards.
#   tests/e2e_root_exec/run.sh
set -eu
cd "$(dirname "$0")/../.."
docker build -f tests/e2e_root_exec/Dockerfile -t asb-root-exec-e2e .
# --network none: the broker and the helper talk over the container's own loopback.
# Not set: no-new-privileges (sudo is setuid; that flag would stop it working, which is the thing under test).
exec docker run --rm --network none --pids-limit 256 --memory 1g asb-root-exec-e2e
