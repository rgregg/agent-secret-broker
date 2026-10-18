#!/usr/bin/env python3
"""Evaluate a risk classifier over tools/risk_eval/cases.jsonl.

    asb openrouter -- python tools/risk_eval/run.py --provider jev
    python tools/risk_eval/run.py --dry-run          # stub model, no network

The API key is read from the environment variable OPENROUTER_TOKEN (override the
name with --key-env) and is never printed. Cases are split deterministically
into "train" (tune on these) and "holdout" (about 25%, do not tune on these) by
a hash of the case id. Cases marked `ambiguous: true` are reported separately
and excluded from the headline rates.
"""
import argparse
import collections
import concurrent.futures
import hashlib
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
from secret_broker import riskmodel  # noqa: E402

LEVELS = riskmodel.LEVELS
DEFAULT_CASES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cases.jsonl")


def split_of(case_id):
    return "holdout" if hashlib.sha1(case_id.encode()).digest()[0] % 4 == 0 else "train"


def load_cases(path):
    cases = []
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            c = json.loads(line)
            for k in ("id", "mode", "names", "spec", "expected"):
                if k not in c:
                    raise ValueError(f"{path}:{n}: missing {k}")
            if c["expected"] not in LEVELS:
                raise ValueError(f"{path}:{n}: bad expected level {c['expected']!r}")
            c.setdefault("ambiguous", False)
            c["split"] = split_of(c["id"])
            cases.append(c)
    ids = [c["id"] for c in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate case ids")
    return cases


class StubAnalyzer:
    """Dry-run model: a crude method/command heuristic. No network."""

    last_cost = 0.0

    def analyze(self, mode, names, spec):
        time.sleep(0.001)
        if mode == "ssh_sign":
            lvl = "high"
        elif mode == "http":
            m = spec.get("method", "GET").upper()
            lvl = "low" if m in ("GET", "HEAD", "OPTIONS") else "high" if m == "DELETE" else "medium"
        elif mode == "store":
            lvl = "medium"
        else:
            cmd = " ".join(spec.get("argv") or [])
            lvl = "high" if any(w in cmd for w in ("rm ", "| sh", "sudo")) else "low"
        return {"summary": "stub", "risk": lvl, "cost": 0.0}


def make_analyzer(args, key):
    if args.dry_run:
        return StubAnalyzer()
    if args.provider == "jev":
        return riskmodel.JevAnalyzer(
            key, args.model or riskmodel.DEFAULT_JEV_MODEL, timeout=args.timeout,
            high_threshold=args.high_threshold, low_threshold=args.low_threshold,
            summary_mode="none")
    return riskmodel.ChatAnalyzer(key, args.model or "openai/gpt-5-mini", timeout=args.timeout,
                                  prompt=args.prompt, max_content_chars=300)


def run_case(analyzer, case, floor):
    t0 = time.time()
    try:
        if floor:
            got = riskmodel.FloorAnalyzer(analyzer).analyze(case["mode"], case["names"], case["spec"])
        else:
            got = analyzer.analyze(case["mode"], case["names"], case["spec"])
    except Exception:  # noqa: BLE001
        got = None
    dt = time.time() - t0
    got = got or {}
    raw = got.get("risk")
    return {"id": case["id"], "split": case["split"], "expected": case["expected"],
            "ambiguous": case["ambiguous"], "predicted": raw if raw in LEVELS else "high",
            "failed": raw not in LEVELS, "latency": dt, "cost": got.get("cost"),
            "note": case.get("note", "")}


def pct(a, b):
    return f"{100.0 * a / b:5.1f}%" if b else "  n/a "


def quantile(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else float("nan")


def report(results, label, out):
    firm = [r for r in results if not r["ambiguous"]]
    amb = [r for r in results if r["ambiguous"]]
    p = lambda *a: print(*a, file=out)
    p(f"=== {label}: {len(results)} cases ({len(firm)} firm, {len(amb)} ambiguous) ===")
    if not firm:
        return
    ok = sum(r["expected"] == r["predicted"] for r in firm)
    p(f"accuracy: {ok}/{len(firm)} {pct(ok, len(firm))}")
    for lv in LEVELS:
        rows = [r for r in firm if r["expected"] == lv]
        p(f"  expected {lv:6}: {sum(r['predicted'] == lv for r in rows)}/{len(rows)} correct {pct(sum(r['predicted'] == lv for r in rows), len(rows))}")
    conf = collections.Counter((r["expected"], r["predicted"]) for r in firm)
    p("confusion (rows expected, cols predicted):")
    p("           " + "".join(f"{lv:>8}" for lv in LEVELS))
    for e in LEVELS:
        p(f"  {e:8} " + "".join(f"{conf[(e, g)]:>8}" for g in LEVELS))
    lowmed = [r for r in firm if r["expected"] in ("low", "medium")]
    over = sum(r["predicted"] == "high" for r in lowmed)
    hi = [r for r in firm if r["expected"] == "high"]
    under = sum(r["predicted"] == "low" for r in hi)
    p(f"OVER-FLAG  (expected low/medium, rated high): {over}/{len(lowmed)} {pct(over, len(lowmed))}")
    lows = [r for r in firm if r["expected"] == "low"]
    p(f"  of which expected low rated high: {sum(r['predicted'] == 'high' for r in lows)}/{len(lows)}")
    p(f"UNDER-FLAG (expected high, rated low): {under}/{len(hi)} {pct(under, len(hi))}"
      f"; rated low or medium: {sum(r['predicted'] != 'high' for r in hi)}/{len(hi)}")
    lat = [r["latency"] for r in results]
    p(f"latency p50 {quantile(lat, .5) * 1000:.0f} ms, p95 {quantile(lat, .95) * 1000:.0f} ms")
    costs = [r["cost"] for r in results if isinstance(r["cost"], (int, float))]
    p(f"cost: ${sum(costs):.6f} over {len(costs)} reporting calls"
      + (f" (~${sum(costs) / len(costs):.7f} per call)" if costs else ""))
    fails = sum(r["failed"] for r in results)
    p(f"no usable verdict (counted as high): {fails}")
    misses = [r for r in firm if r["expected"] != r["predicted"]]
    p(f"misses ({len(misses)}):")
    for r in sorted(misses, key=lambda r: r["id"]):
        tag = "UNDER" if r["predicted"] == "low" and r["expected"] == "high" else \
              "over " if r["predicted"] == "high" else "     "
        p(f"  {tag} {r['id']:32} expected {r['expected']:6} got {r['predicted']:6}{' (no verdict)' if r['failed'] else ''}")
    if amb:
        p("ambiguous cases (not scored):")
        for r in sorted(amb, key=lambda r: r["id"]):
            p(f"  {r['id']:32} expected {r['expected']:6} got {r['predicted']}")
    p("")


def main(argv=None, out=sys.stdout):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--provider", choices=("jev", "chat"), default="jev")
    ap.add_argument("--model", help="default: typesafe/jev-1.14 (jev) or openai/gpt-5-mini (chat)")
    ap.add_argument("--prompt", choices=("legacy", "rubric"), default="legacy",
                    help="chat provider only: the current prompt, or the new rubric")
    ap.add_argument("--cases", default=DEFAULT_CASES)
    ap.add_argument("--split", choices=("all", "train", "holdout"), default="all")
    ap.add_argument("--dry-run", action="store_true", help="stub model, no network, no key needed")
    ap.add_argument("--floor", action="store_true", help="apply the ssh_sign HIGH floor (default: raw model)")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--high-threshold", type=float, default=0.5)
    ap.add_argument("--low-threshold", type=float, default=0.5)
    ap.add_argument("--key-env", default="OPENROUTER_TOKEN")
    ap.add_argument("--out", help="write per-case results as JSONL here (no key, no request bodies)")
    args = ap.parse_args(argv)

    key = os.environ.get(args.key_env, "")
    if not args.dry_run and not key:
        print(f"error: set {args.key_env} (e.g. run under `asb openrouter -- ...`) or use --dry-run",
              file=sys.stderr)
        return 2
    cases = load_cases(args.cases)
    analyzer = make_analyzer(args, key)
    if args.split != "all":
        cases = [c for c in cases if c["split"] == args.split]
    desc = "dry-run stub" if args.dry_run else (
        f"jev {args.model or riskmodel.DEFAULT_JEV_MODEL} thresholds high>={args.high_threshold} low>={args.low_threshold}"
        if args.provider == "jev" else f"chat {args.model or 'openai/gpt-5-mini'} prompt={args.prompt}")
    print(f"provider: {desc}; floor={'on' if args.floor else 'off'}; cases: {len(cases)}", file=out)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        results = list(ex.map(lambda c: run_case(analyzer, c, args.floor), cases))
    for sp in ("train", "holdout"):
        sub = [r for r in results if r["split"] == sp]
        if sub:
            report(sub, sp, out)
    report(results, "all", out)
    if args.out:
        with open(args.out, "w") as f:
            for r in results:
                f.write(json.dumps(r) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
