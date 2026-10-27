"""Risk assessment: the level is whatever the analysis model says.

There are no per-secret ratings and no rule baseline. If the model is not
configured, fails, times out or returns something that is not low/medium/high,
the request is treated as HIGH, so a missing verdict can only make the broker
ask more, never less.

The model's input is client-supplied text and can be steered by prompt
injection, so its verdict is advisory to a human who also sees the raw request.
It matters most for secrets set to `approval: allow`: there it decides whether
the request is released without a prompt (see `risk.auto_approve_max`).

One exception: creating a new credential (`store`) is always low. It cannot
read or alter anything that exists, so it needs no tap unless `store.create` is
`prompt` (see broker._auto_allowed). Updating an existing credential still takes
the model's verdict (or high) and always needs a human.

Two more floors need no model: an SSH signature and an agent's guidance proposal are
always high.
"""

from . import guidance as guidance_mod

LEVELS = ("low", "medium", "high")
AUTO_MAX = ("none",) + LEVELS       # values of risk.auto_approve_max


def rank(level):
    return LEVELS.index(level)


def assess(mode, names, spec, analyzer=None, guidance=None):
    """Return {"level", "model", "reasons", "summary", "summary_model",
    "summary_source", "summary_reason"}."""
    if mode == "guidance":
        # an agent's guidance proposal: high by code, and neither the proposal text nor
        # the request ever reaches a model (see proposals.py)
        return {"level": "high", "model": None, "summary": None, "summary_model": None,
                "summary_source": None, "summary_reason": None,
                "reasons": ["guidance proposals always need a human review; always high"]}
    if mode == "credential":
        # an agent asking a human for a credential: high by code, and no model sees the request
        # (the purpose is untrusted agent text; there is no value at request time)
        return {"level": "high", "model": None, "summary": None, "summary_model": None,
                "summary_source": None, "summary_reason": None,
                "reasons": ["credential requests always need a human to supply the value; always high"]}
    if mode == "sudo":
        # a root command: high by code, no model sees it (the command is untrusted text and the human reads it)
        return {"level": "high", "model": None, "summary": None, "summary_model": None,
                "summary_source": None, "summary_reason": None,
                "reasons": ["root commands always need a human to read the exact command; always high"]}
    if mode == "session":
        # an http session: high by code, no model sees the request (the purpose is untrusted agent text)
        return {"level": "high", "model": None, "summary": None, "summary_model": None,
                "summary_source": None, "summary_reason": None,
                "reasons": ["an HTTP session always needs a human to approve it; always high"]}
    summary, model_risk, summary_model, src, why = None, None, None, None, None
    rule, late = None, {}
    if analyzer is not None:
        try:
            if hasattr(analyzer, "analyze"):
                got = guidance_mod.call(analyzer.analyze, mode, names, spec, guidance) or {}
                summary, model_risk = got.get("summary"), got.get("risk")
                summary_model = got.get("summary_model")
                src, why = got.get("summary_source"), got.get("summary_reason")
                rule = got.get("summary_rule")
                late = {k: got.get(k) for k in ("summary_pending", "summary_late", "rating_late") if got.get(k)}
            else:
                summary = analyzer.summarize(mode, names, spec)
        except Exception:  # noqa: BLE001
            summary, model_risk, summary_model, src, why, rule, late = None, None, None, None, None, None, {}
    if model_risk not in LEVELS:
        model_risk = None
    out = {"summary": summary, "summary_model": summary_model, "summary_source": src,
           "summary_reason": why, "summary_rule": rule, **late}
    if mode == "store" and spec.get("op") == "create":
        # adding a credential cannot read or change an existing one, and a human
        # always approves it, so it is low whatever the model thinks
        return {"level": "low", "model": model_risk, **out,
                "reasons": ["adds a new credential (it cannot read or change an existing one)"]}
    if mode == "ssh_sign":
        # a signature authenticates as the user to a server: high whatever the model says
        return {"level": "high", "model": model_risk, **out,
                "reasons": ["an SSH signature authenticates as you; always high"]}
    if model_risk is None:
        return {"level": "high", "model": None, **out,
                "reasons": ["no model verdict; treated as high"]}
    return {"level": model_risk, "model": model_risk, **out,
            "reasons": [f"model rated it {model_risk}"]}


def parse_auto_approve_max(raw, field="risk"):
    """Validate the `risk` config object -> (auto_approve_max, warning or None).

    `risk.auto_approve_max` is the highest model risk level at which an
    auto-eligible request is released without a prompt (`none` = never). The
    legacy `risk.escalate_auto_at` X means "prompt at X or above", i.e. a max
    one level below X; it is only read when `auto_approve_max` is absent.
    Default `low`.
    """
    raw = raw or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{field} must be an object")
    new, old = raw.get("auto_approve_max"), raw.get("escalate_auto_at")
    if new is not None and new not in AUTO_MAX:
        raise ValueError(f"{field}.auto_approve_max must be one of {', '.join(AUTO_MAX)}")
    if old is not None and old not in LEVELS:
        raise ValueError(f"{field}.escalate_auto_at must be one of {', '.join(LEVELS)}")
    if new is not None:
        warn = (f"{field}.escalate_auto_at is ignored: {field}.auto_approve_max is set"
                if old is not None else None)
        return new, warn
    if old is not None:
        return AUTO_MAX[LEVELS.index(old)], None     # "low" -> none, "medium" -> low, ...
    return "low", None


AUTO_MODES = ("http", "env")        # values of risk.auto_modes


def parse_auto_modes(raw, field="risk"):
    """Validate `risk.auto_modes` -> list of modes an `approval: allow` credential
    is auto-eligible for when it has no `auto_modes` of its own. Default
    ["http", "env"]; [] makes nothing auto-eligible by default."""
    raw = raw or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{field} must be an object")
    modes = raw.get("auto_modes")
    if modes is None:
        return list(AUTO_MODES)
    if (not isinstance(modes, list) or not all(isinstance(m, str) and m in AUTO_MODES for m in modes)
            or len(set(modes)) != len(modes)):
        raise ValueError(f"{field}.auto_modes must be a list of {' and/or '.join(AUTO_MODES)}")
    return list(modes)


def auto_ok(level, auto_max):
    """True when a request rated `level` may be auto-approved under `auto_max`.
    A missing or unrecognised level counts as high."""
    if auto_max == "none":
        return False
    if level not in LEVELS:
        level = "high"
    return rank(level) <= rank(auto_max)
