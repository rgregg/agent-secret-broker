"""Run the real client/asb with its poll sleeps shortened (test-only wrapper).

The client sleeps 1-2 s between polls (`asb enroll`, `asb audit --tail`). Running it through this wrapper
keeps every line of the client as it is and only caps `time.sleep` at 100 ms (the broker rate-limits polls, so not lower), so a test does not wait out the
poll interval. It also restores Python's default SIGINT handler: a parent started in the background leaves
SIGINT ignored, which would make a Ctrl-C (as the tail test sends) a no-op.

    python asb_fastpoll.py ARGS...      ==      client/asb ARGS...
"""
import os
import runpy
import signal
import sys
import time

REAL = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "client", "asb"))

_sleep = time.sleep
time.sleep = lambda s: _sleep(min(s, 0.1))
signal.signal(signal.SIGINT, signal.default_int_handler)
sys.argv[0] = REAL
runpy.run_path(REAL, run_name="__main__")
