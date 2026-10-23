"""One wall clock and one monotonic clock for time-bounded approvals.

Plans (plans.py), standing grants (grants.py) and, later, sessions share this pair so a test can
move time in one place. `now()` is wall-clock seconds, `mono()` is monotonic seconds. Both read
`time.time` / `time.monotonic` at call time (so a test that patches those still works), unless a
test installed its own with `install()`. `install()` with no arguments puts the real ones back.
"""
import time

_now = None
_mono = None


def now():
    return (_now or time.time)()


def mono():
    return (_mono or time.monotonic)()


def install(now=None, mono=None):
    """Replace the clocks (tests). Call with no arguments to restore the real ones."""
    global _now, _mono
    _now, _mono = now, mono
