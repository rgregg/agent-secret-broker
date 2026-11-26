"""Hang detection. The broker's request paths go through a few plain locks; one that stays taken (a deadlock,
or a vault call that never returns while holding it) leaves the process up and the port open but every request
waiting, which no restart policy notices. A daemon thread probes those locks: one that cannot be taken for
UNHEALTHY_S makes /healthz answer 503, and one stuck for `stuck_s` makes the process exit so the container's
`restart:` policy brings it back. The probe holds a lock for no time at all, and /healthz reads only the
watchdog's own state, so neither can be caught by the hang it reports.
"""
import os
import sys
import threading

from . import clock

DEFAULTS = {"enabled": True, "stuck_s": 120}
STUCK_MIN, STUCK_MAX = 60, 3600
UNHEALTHY_S = 30
INTERVAL_S = 10
EXIT_CODE = 70


def parse_config(raw, field="watchdog"):
    """Validate `watchdog` -> {"enabled", "stuck_s"}. None means the defaults (on, 120 s)."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError(f"{field} must be an object")
    for k in raw:
        if k not in DEFAULTS:
            raise ValueError(f"{field}.{k} is not a known option")
    out = {**DEFAULTS, **raw}
    if not isinstance(out["enabled"], bool):
        raise ValueError(f"{field}.enabled must be true or false")
    s = out["stuck_s"]
    if isinstance(s, bool) or not isinstance(s, int) or not STUCK_MIN <= s <= STUCK_MAX:
        raise ValueError(f"{field}.stuck_s must be a whole number of seconds from {STUCK_MIN} to {STUCK_MAX}")
    return out


class Watchdog:
    def __init__(self, locks, on_stuck, stuck_s=DEFAULTS["stuck_s"], probe_s=1.0, mono=None):
        self.locks = dict(locks)
        self.on_stuck = on_stuck
        self.stuck_s = stuck_s
        self.probe_s = probe_s
        self.mono = mono or clock.mono
        self._since = {}            # lock name -> monotonic time of the first failed probe in a row
        self._fired = False

    def check(self):
        """Probe every lock once; fire on_stuck (once) for the first one stuck past stuck_s."""
        now = self.mono()
        for name, lock in self.locks.items():
            if lock.acquire(timeout=self.probe_s):
                lock.release()
                self._since.pop(name, None)
                continue
            since = self._since.setdefault(name, now)
            if now - since >= self.stuck_s and not self._fired:
                self._fired = True
                self.on_stuck(name, now - since)

    def stuck(self):
        """{lock name: seconds it has been unavailable} for every lock that failed its last probe."""
        now = self.mono()
        return {n: now - t for n, t in self._since.items()}

    def healthy(self):
        return all(s < UNHEALTHY_S for s in self.stuck().values())

    def run(self, interval_s=INTERVAL_S, stop=None):
        stop = stop or threading.Event()
        while not stop.wait(interval_s):
            try:
                self.check()
            except Exception as e:  # noqa: BLE001 -- the watchdog must outlive its own bugs
                print(f"watchdog: check failed: {type(e).__name__}", file=sys.stderr, flush=True)

    def start(self, interval_s=INTERVAL_S):
        threading.Thread(target=self.run, args=(interval_s,), name="watchdog", daemon=True).start()
        return self


def exit_on_stuck(log, exit_fn=os._exit, log_timeout_s=5.0):
    """The production on_stuck: audit it (bounded, since the audit write may be behind the same hang), say so
    on stderr, and exit with EXIT_CODE so the restart policy brings the broker back."""
    def fire(name, secs):
        print(f"watchdog: lock {name!r} stuck for {int(secs)}s; exiting for a restart", file=sys.stderr,
              flush=True)
        th = threading.Thread(target=lambda: log("watchdog_restart", lock=name, stuck_s=int(secs)),
                              daemon=True)
        th.start()
        th.join(log_timeout_s)
        exit_fn(EXIT_CODE)
    return fire
