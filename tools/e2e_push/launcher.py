"""Starts the throwaway broker for the rig: loopback allowed (test switch), optional service-worker
override, and push send failures logged with their HTTP status. argv: CONFIG [SW_FILE]"""
import sys

from secret_broker import broker as b
from secret_broker import destguard
from secret_broker import webpush as wp

destguard.allow_loopback_for_tests()
if len(sys.argv) > 2 and sys.argv[2]:
    b._SERVICE_WORKER = open(sys.argv[2]).read().replace("__SW_VERSION__", b.SW_VERSION)
_orig = wp._send_with_pywebpush


def _logged(sub, data, key_path, subject, ttl):
    try:
        return _orig(sub, data, key_path, subject, ttl)
    except Exception as e:  # noqa: BLE001
        print("PUSH SEND FAILED status=%s %r" % (getattr(e, "status", None), e), flush=True)
        raise


wp._send_with_pywebpush = _logged
from secret_broker.__main__ import main  # noqa: E402

sys.argv = [sys.argv[0], "--config", sys.argv[1]]
main()
