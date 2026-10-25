"""Run the suite in parallel worker processes (stdlib only), optionally one shard of it.

    python tests/run_tests.py [-j N] [--shard I/N] [--record] [-k SUBSTRING] [--durations K]

The suite is split into units (a few classes of one module, or a slice of a heavy class), each run in its own interpreter
as `python -m unittest ID...`, so module-level state is never shared between units and every test still gets
its own ports (all bound to port 0) and temp dirs. `-j` runs that many units at once. `--shard I/N` takes
the I-th of N balanced groups of units (the split is a pure function of the test ids and timings.json, so
every CI job computes the same one). `--record` rewrites tests/timings.json, the per-test cost estimates
used for balancing. Exit status is non-zero if any test fails or errors.
"""
import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TIMINGS = os.path.join(HERE, "timings.json")
DEFAULT_COST = 0.3          # seconds, for a test that has no recorded timing
UNIT_TARGET = 10.0          # a class costing more than this is split into slices of about this size


def iter_tests(suite):
    for t in suite:
        if isinstance(t, unittest.TestSuite):
            yield from iter_tests(t)
        else:
            yield t


def discover():
    sys.path.insert(0, HERE)
    sys.path.insert(0, ROOT)
    suite = unittest.defaultTestLoader.discover(HERE, top_level_dir=HERE)
    return sorted({t.id() for t in iter_tests(suite)})


def load_timings():
    try:
        with open(TIMINGS) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def plan(ids, timings):
    """[(cost, [ids])]. Classes of one module are packed together up to UNIT_TARGET seconds (each unit is a
    fresh interpreter that imports the module once); a class costing more than that is cut into slices."""
    cost = lambda i: timings.get(i, DEFAULT_COST)    # noqa: E731
    modules = {}
    for i in ids:
        mod, cls = i.split(".")[0], i.rsplit(".", 1)[0]
        modules.setdefault(mod, {}).setdefault(cls, []).append(i)
    units = []
    for _, classes in sorted(modules.items()):
        cur, cur_cost = [], 0.0
        for _, tests in sorted(classes.items()):
            total = sum(cost(i) for i in tests)
            if total > UNIT_TARGET * 1.5:                # a heavy class: its own slices
                n = round(total / UNIT_TARGET)
                bins = [[0.0, []] for _ in range(n)]
                for i in sorted(tests, key=lambda i: (-cost(i), i)):
                    b = min(bins, key=lambda b: b[0])
                    b[0] += cost(i)
                    b[1].append(i)
                units.extend((c, sorted(t)) for c, t in bins if t)
                continue
            if cur and cur_cost + total > UNIT_TARGET:
                units.append((cur_cost, cur))
                cur, cur_cost = [], 0.0
            cur, cur_cost = cur + tests, cur_cost + total
        if cur:
            units.append((cur_cost, cur))
    return units


def shard(units, i, n):
    bins = [[0.0, []] for _ in range(n)]
    for u in sorted(units, key=lambda u: (-u[0], u[1][0])):
        b = min(bins, key=lambda b: b[0])
        b[0] += u[0]
        b[1].append(u)
    return sorted(bins[i - 1][1], key=lambda u: -u[0])


class _Timed(unittest.TextTestResult):
    durs = {}

    def startTest(self, test):
        self._t0 = time.perf_counter()
        super().startTest(test)

    def stopTest(self, test):
        _Timed.durs[test.id()] = time.perf_counter() - self._t0
        super().stopTest(test)


def child(argv):
    """Run the given test ids in this process; write per-test durations to $ASB_TEST_DURATIONS."""
    sys.path.insert(0, HERE)
    sys.path.insert(0, ROOT)
    suite = unittest.defaultTestLoader.loadTestsFromNames(argv)
    r = unittest.TextTestRunner(resultclass=_Timed, verbosity=1).run(suite)
    out = os.environ.get("ASB_TEST_DURATIONS")
    if out:
        with open(out, "w") as f:
            json.dump(_Timed.durs, f)
    return 0 if r.wasSuccessful() else 1


def run_unit(unit, tmp):
    cost, ids = unit
    dur = os.path.join(tmp, f"{abs(hash(tuple(ids)))}.json")
    t = time.time()
    p = subprocess.run([sys.executable, os.path.abspath(__file__), "--child", *ids], cwd=ROOT,
                       env=dict(os.environ, ASB_TEST_DURATIONS=dur), stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, text=True)
    try:
        with open(dur) as f:
            d = json.load(f)
    except (OSError, ValueError):
        d = {}
    return ids, p.returncode, time.time() - t, p.stdout, d


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--child":
        return child(sys.argv[2:])
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-j", type=int, default=os.cpu_count() or 2, help="units to run at once")
    ap.add_argument("--shard", default="1/1", help="I/N: run the I-th of N balanced groups")
    ap.add_argument("--record", action="store_true", help="rewrite tests/timings.json from this run")
    ap.add_argument("-k", default="", help="only tests whose id contains this")
    ap.add_argument("--durations", type=int, default=15, help="print this many slowest tests")
    a = ap.parse_args()
    i, n = (int(x) for x in a.shard.split("/"))
    timings = load_timings()
    ids = [t for t in discover() if a.k in t]
    units = shard(plan(ids, timings), i, n)
    print(f"shard {i}/{n}: {sum(len(u[1]) for u in units)} tests in {len(units)} units, -j {a.j}", flush=True)
    start = time.time()
    failed, measured = [], {}
    import tempfile
    with tempfile.TemporaryDirectory() as tmp, concurrent.futures.ThreadPoolExecutor(a.j) as ex:
        for ids_, rc, secs, out, d in ex.map(lambda u: run_unit(u, tmp), units):
            measured.update(d)
            tail = out.strip().splitlines()[-1] if out.strip() else "(no output)"
            print(f"{'ok  ' if rc == 0 else 'FAIL'} {ids_[0].split('.')[0]} ({len(ids_)} tests, {secs:.1f}s) {tail}",
                  flush=True)
            if rc != 0:
                failed.append(ids_[0])
                print(out, flush=True)
    slow = sorted(measured.items(), key=lambda kv: -kv[1])[:a.durations]
    if slow:
        print("slowest tests:")
        for k, v in slow:
            print(f"  {v:6.2f}s {k}")
    if a.record:
        merged = dict(timings)
        merged.update({k: round(v, 3) for k, v in measured.items()})
        merged = {k: v for k, v in merged.items() if k in set(discover())}
        with open(TIMINGS, "w") as f:
            json.dump(dict(sorted(merged.items())), f, indent=0)
            f.write("\n")
    print(f"{sum(len(u[1]) for u in units)} tests, {len(failed)} failing unit(s), {time.time() - start:.1f}s")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
