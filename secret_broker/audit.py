"""Append-only, hash-chained JSONL audit log.

Every record carries `seq` and `prev`, the sha256 of the previous raw line, so
an edited or deleted record in the middle of the file is detectable with
`python -m secret_broker.audit verify FILE`. Truncating the tail is not
detectable from the file alone; the real protection is that the log lives on
the broker host, where the agent being audited has no access.

Records never contain secret values, request bodies, or header values.
"""
import hashlib
import json
import os
import sys
import threading
import time

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path):
        self._path = path
        self._lock = threading.Lock()
        self._seq, self._prev = 0, GENESIS
        if path and os.path.exists(path):
            last = None
            with open(path) as f:
                for line in f:
                    if line.strip():
                        last = line.rstrip("\n")
            if last:
                self._seq = json.loads(last)["seq"] + 1
                self._prev = hashlib.sha256(last.encode()).hexdigest()

    def log(self, event, **fields):
        if not self._path:
            return
        with self._lock:
            rec = {"seq": self._seq, "ts": round(time.time(), 3),
                   "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "event": event, "prev": self._prev, **fields}
            line = json.dumps(rec, sort_keys=True)
            fd = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, (line + "\n").encode())
                os.fsync(fd)
            finally:
                os.close(fd)
            self._seq += 1
            self._prev = hashlib.sha256(line.encode()).hexdigest()


def verify(path):
    """Return (ok, message). Checks sequence continuity and the hash chain."""
    prev, seq = GENESIS, 0
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line:
                continue
            rec = json.loads(line)
            if rec["seq"] != seq:
                return False, f"line {n}: expected seq {seq}, found {rec['seq']} (record removed or reordered)"
            if rec["prev"] != prev:
                return False, f"line {n}: hash chain broken (previous record altered or removed)"
            prev = hashlib.sha256(line.encode()).hexdigest()
            seq += 1
    return True, f"ok: {seq} records, chain intact"


def main(argv):
    if len(argv) == 2 and argv[0] == "verify":
        ok, msg = verify(argv[1])
        print(msg)
        return 0 if ok else 1
    if len(argv) >= 2 and argv[0] == "show":
        # show FILE [event|name=VALUE ...]: filter by event name or a field value
        want = argv[2:]
        with open(argv[1]) as f:
            for line in f:
                rec = json.loads(line)
                ok = True
                for w in want:
                    if "=" in w:
                        k, v = w.split("=", 1)
                        val = rec.get(k)
                        ok &= (v in val) if isinstance(val, list) else (str(val) == v)
                    else:
                        ok &= rec["event"] == w
                if ok:
                    print(f"{rec['time']} #{rec['seq']} {rec['event']} "
                          + " ".join(f"{k}={json.dumps(v)}" for k, v in rec.items()
                                     if k not in ("seq", "ts", "time", "event", "prev")))
        return 0
    print("usage: python -m secret_broker.audit verify FILE | show FILE [event|field=value ...]",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
