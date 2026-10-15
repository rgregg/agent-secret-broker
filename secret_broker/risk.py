"""Risk assessment: deterministic floor, optionally raised by a model.

final = max(baseline, model). The model's input is client-supplied text, so it
can be steered by prompt injection; taking the max means it can only make a
request look *more* risky, never less than the rules say.

Baseline inputs: the secret's configured `sensitivity` (default "medium",
because an unlabelled secret should not read as low), HTTP method, mode,
destructive keywords in the URL path or body, and opaque shell commands.
"""
import re
import urllib.parse

LEVELS = ("low", "medium", "high")

_DESTRUCTIVE = re.compile(
    r"delete|destroy|remove|purge|wipe|erase|reset|reboot|restart|shutdown|poweroff|"
    r"\bstop\b|kill|format|\bdrop\b|truncate|revoke|rotate|factory", re.I)
_PRIVILEGE = re.compile(r"/admin|/users?\b|/tokens?\b|/keys?\b|/permissions?|/roles?\b|/write\b|/execute\b", re.I)
_OPAQUE_SHELL = {"sh", "bash", "zsh", "dash", "eval", "python", "python3", "node", "perl", "ruby"}
_ENV_DUMP = {"env", "printenv", "set", "export", "declare"}


def rank(level):
    return LEVELS.index(level)


def worst(*levels):
    return max((l for l in levels if l), key=rank, default="low")


def baseline(mode, names, spec, secrets_cfg):
    """Return (level, reasons)."""
    level, reasons = "low", []

    def raise_to(new, why):
        nonlocal level
        if rank(new) > rank(level):
            level = new
        reasons.append(why)

    for n in names:
        sc = secrets_cfg.get(n)
        if sc is None:                      # a secret that does not exist yet (store/create)
            continue
        sens = sc.get("sensitivity", "medium")
        if rank(sens) > rank("low"):
            raise_to(sens, f"{n} is marked {sens}-sensitivity" if "sensitivity" in sc
                     else f"{n} has no sensitivity set (assumed medium)")

    if mode == "http":
        method = spec["method"].upper()
        u = urllib.parse.urlsplit(spec["url"])
        if method == "DELETE":
            raise_to("high", "DELETE request")
        elif method not in ("GET", "HEAD", "OPTIONS"):
            raise_to("medium", f"{method} can change state")
        text = f"{u.path} {spec.get('body') or ''}"
        if _DESTRUCTIVE.search(text):
            raise_to("high", "destructive keyword in path or body")
        if _PRIVILEGE.search(u.path):
            raise_to("medium", "admin/credential/write path")
        if spec.get("body_b64") is not None:
            raise_to("medium", "binary body cannot be inspected")
    elif mode == "store":
        if spec.get("op") == "create":
            raise_to("medium", "stores a new credential whose value the broker cannot verify")
        else:
            raise_to("high", "overwrites an existing credential")
    else:
        raise_to("medium", "secret value is released to the requesting host")
        argv = spec.get("argv") or []
        exe = argv[0].rsplit("/", 1)[-1] if argv else ""
        if exe in _OPAQUE_SHELL:
            raise_to("high", f"opaque command ({exe}) cannot be vetted")
        if exe in _ENV_DUMP or any("/proc/" in a for a in argv):
            raise_to("high", "command can expose the environment")
        if _DESTRUCTIVE.search(" ".join(argv)):
            raise_to("high", "destructive keyword in command")
    return level, reasons


def assess(mode, names, spec, secrets_cfg, analyzer=None):
    """Combine baseline and optional model analysis into one record."""
    base, reasons = baseline(mode, names, spec, secrets_cfg)
    summary, model_risk = None, None
    if analyzer is not None:
        try:
            if hasattr(analyzer, "analyze"):
                got = analyzer.analyze(mode, names, spec) or {}
                summary, model_risk = got.get("summary"), got.get("risk")
            else:
                summary = analyzer.summarize(mode, names, spec)
        except Exception:
            summary, model_risk = None, None
    if model_risk not in LEVELS:
        model_risk = None
    final = worst(base, model_risk)
    if model_risk and rank(model_risk) > rank(base):
        reasons.append(f"model rated it {model_risk}")
    return {"level": final, "baseline": base, "model": model_risk,
            "reasons": reasons, "summary": summary}
