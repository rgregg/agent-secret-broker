"""Agent-proposed risk guidance: the agent writes, a human reviews and applies.

Risk guidance (see guidance.py) can LOWER ratings, so an agent must never be able
to write it: it would weaken its own approvals. This module lets the agent PROPOSE
guidance text (request mode `guidance`), which a human reviews on the approval page
and applies entry by entry. Nothing here applies anything; applying goes through
Broker.set_guidance, the same path as the Policies-tab editor.

Invariants (enforced in broker.py, tested in tests/test_guidance_proposals.py):
  * a proposal is always HIGH by code: no model call, the text is never sent to
    any model, and it has no guidance of its own;
  * it can never be auto-approved (legacy `approval: allow`, Always, timed grants,
    SSH rules) and no notification button can decide it; only the dashboard or the
    approval-link page can, after the human has seen the text;
  * the proposal text appears ONLY on the approval card/page: never in
    notifications, the audit log, history rows, discovery, status or agent results;
  * the text is dropped from memory as soon as the proposal is decided or expires.

This module holds the config parser, entry validation, the lint, the line diff and
the review card.
"""
import html
import re

from . import guidance as guidance_mod

MAX_ENTRIES = 25
MAX_PENDING = 3                 # open proposals at once
BODY_CAP = 100 * 1024           # whole request body, bytes
DEFAULTS = {"enabled": True, "ttl_s": 3600}
TTL_MIN, TTL_MAX = 300, 86400
INLINE_OPEN = 5                 # entries shown expanded; more are collapsed
WARNING = ("This text tells the risk classifier how to rate requests made with these credentials. "
           "It can lower ratings. Review each one.")
REASON = "guidance proposals always need a human review; always high"


def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def parse_config(raw, field="guidance_proposals"):
    """Validate `guidance_proposals` -> {"enabled", "ttl_s"}. None means the defaults.
    Raises ValueError naming the field."""
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
    if not _int(out["ttl_s"]) or not TTL_MIN <= out["ttl_s"] <= TTL_MAX:
        raise ValueError(f"{field}.ttl_s must be a whole number of seconds from {TTL_MIN} to {TTL_MAX}")
    return out


def validate_entries(entries, known):
    """The agent's `entries` -> [{"name", "text"}] with cleaned text. `known` is the
    catalog (a container of names). Raises ValueError for anything malformed."""
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_ENTRIES:
        raise ValueError(f"entries must be a list of 1 to {MAX_ENTRIES} items")
    out, seen = [], set()
    for e in entries:
        if not isinstance(e, dict) or set(e) != {"name", "text"}:
            raise ValueError('each entry must be {"name": ..., "text": ...}')
        name = e["name"]
        if not isinstance(name, str) or name not in known:
            raise ValueError("unknown secret name")
        if name in seen:
            raise ValueError(f"duplicate entry for {name}")
        seen.add(name)
        try:
            text = guidance_mod.validate_text(e["text"])
        except guidance_mod.HiddenCharsError as ex:
            raise ValueError(f"entry {name}: {ex}") from None
        out.append({"name": name, "text": text})
    return out


def names_of(entries):
    """Best-effort names from an unvalidated `entries` value (for the rejected log)."""
    if not isinstance(entries, list):
        return []
    return [e["name"] for e in entries[:MAX_ENTRIES]
            if isinstance(e, dict) and isinstance(e.get("name"), str)]


def outcome(req, status):
    """The agent-facing result for a proposal that ended with `status` and no apply
    step (denied, expired, failed): names only."""
    names = list(req.names)
    if status == "failed":
        return {"applied": [], "denied": [], "failed": names}
    return {"applied": [], "denied": names, "failed": []}


# ---------------------------------------------------------------- lint
# Phrases that look like lowering a rating or steering the classifier. Highlighted for
# the reviewer, never a block. Case-insensitive and word-bounded.
_LINT = (
    ("always low", r"always\s+low"),
    ("never high", r"never\s+high"),
    ("rate low", r"rate\s+(?:it\s+)?low"),
    ("ignore", r"ignore"),
    ("disregard", r"disregard"),
    ("override", r"override"),
    ("approve", r"approve"),
    ("safe", r"safe"),
    ("trusted", r"trusted"),
    ("no risk", r"no\s+risk"),
)
_LINT_RE = [(label, re.compile(r"(?<![A-Za-z0-9_])(?:" + rx + r")(?![A-Za-z0-9_])", re.I))
            for label, rx in _LINT]


def lint(text):
    """Labels of the flagged phrases found in `text`, in a fixed order."""
    return [label for label, rx in _LINT_RE if rx.search(text or "")]


# ---------------------------------------------------------------- diff
def line_diff(old, new):
    """Deterministic line diff -> [(op, line)] with op "=", "-" or "+". Longest common
    subsequence of lines; within a changed stretch removals come before additions."""
    a = old.split("\n") if old else []
    b = new.split("\n") if new else []
    n, m = len(a), len(b)
    lcs = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        for j in range(m - 1, -1, -1):
            lcs[i][j] = (lcs[i + 1][j + 1] + 1 if a[i] == b[j]
                         else max(lcs[i + 1][j], lcs[i][j + 1]))
    out, i, j = [], 0, 0
    while i < n and j < m:
        if a[i] == b[j]:
            out.append(("=", a[i]))
            i += 1
            j += 1
        elif lcs[i + 1][j] >= lcs[i][j + 1]:
            out.append(("-", a[i]))
            i += 1
        else:
            out.append(("+", b[j]))
            j += 1
    out += [("-", x) for x in a[i:]] + [("+", x) for x in b[j:]]
    return out


# ---------------------------------------------------------------- card
CSS = """
.gprop{margin:.6rem 0}
.gentry{border:1px solid var(--line);border-radius:.6rem;margin:.5rem 0;background:var(--card)}
.gentry>summary{cursor:pointer;display:flex;flex-wrap:wrap;align-items:center;gap:.3rem .6rem;padding:.5rem .7rem;
min-height:2.25rem;list-style:none}
.gentry>summary::-webkit-details-marker{display:none}
.gbody{padding:0 .7rem .7rem}
.gcols{display:grid;grid-template-columns:1fr;gap:.6rem}
@media (min-width:44rem){.gcols{grid-template-columns:1fr 1fr}}
.gcol h4{margin:.2rem 0;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
.gtext{border:1px solid var(--line);border-radius:.4rem;background:var(--bg);padding:.3rem 0;font:.82rem/1.4 ui-monospace,monospace;
max-height:22rem;overflow:auto}
.gl{display:flex;gap:.4rem;padding:0 .5rem;white-space:pre-wrap;overflow-wrap:anywhere}
.gm{flex:none;width:.8rem;color:var(--muted)}
.gadd{background:var(--okbg);color:var(--okfg)}
.gdel{background:var(--badbg);color:var(--bad)}
.gu{background:var(--wbg);color:var(--wfg);border-radius:.25rem;padding:0 .15rem}
.gnone{padding:0 .5rem;color:var(--muted);font-style:italic}
.gflag{margin:.5rem 0 0;padding:.4rem .6rem;border:1px solid var(--warn);border-radius:.5rem;background:var(--wbg);color:var(--wfg);font-size:.85rem}
.gpick{display:flex;align-items:center;gap:.5rem;min-height:2.5rem;margin-top:.5rem;font-weight:600}
.gpick input{width:1.2rem;height:1.2rem}
"""

JS = r"""
function asbChecked(root){var o=[];root.querySelectorAll('input[data-gapply]').forEach(function(c){
  if(c.checked)o.push(c.name+'@'+(c.closest('article[data-id]')?c.closest('article[data-id]').getAttribute('data-id'):''));});return o;}
function asbRecheck(root,keys){root.querySelectorAll('input[data-gapply]').forEach(function(c){
  var a=c.closest('article[data-id]');if(keys.indexOf(c.name+'@'+(a?a.getAttribute('data-id'):''))>=0)c.checked=true;});}
function asbGSync(root){(root||document).querySelectorAll('button[data-gapply-btn]').forEach(function(b){
  var f=b.form;if(!f)return;b.disabled=!f.querySelector('input[data-gapply]:checked');});}
"""

# run once in a real page (kept apart from JS so the helper functions load without a document)
JS_INIT = r"""
;document.addEventListener('change',function(e){if(e.target&&e.target.hasAttribute&&e.target.hasAttribute('data-gapply'))asbGSync(document);});
asbGSync(document);
"""


def describe_html(req):
    """(what_html, note_html) for the card header: the count and the warning. No
    proposal text."""
    n = len(req.spec["entries"])
    e = html.escape
    return (f"<b>Guidance proposal</b>: {n} credential{'' if n == 1 else 's'}<br>"
            f"<span class=muted>{e(WARNING)}</span>",
            "Proposed by the requesting agent. Nothing changes unless you tick an entry and press "
            "Apply selected. Deny and expiry change nothing.")


def _esc(line):
    """HTML for one line where every non-ASCII character is shown as <U+XXXX> (the real
    character in the tooltip), so a look-alike cannot pass for an ASCII letter."""
    return "".join(
        html.escape(ch) if ord(ch) < 128 else
        f"<span class=gu title=\"{html.escape(ch)}\">&lt;U+{ord(ch):04X}&gt;</span>" for ch in line)


def _col(lines, mark, cls, empty):
    if not lines:
        return f"<div class=gtext><div class=gnone>{html.escape(empty)}</div></div>"
    rows = []
    for op, line in lines:
        flag = cls if op == mark else ""
        sign = {"-": "-", "+": "+"}.get(op, "") if op == mark else ""
        rows.append(f"<div class='gl {flag}'><span class=gm aria-hidden=true>{sign}</span>"
                    f"<span>{_esc(line) or '&nbsp;'}</span></div>")
    return f"<div class=gtext>{''.join(rows)}</div>"


def entry_html(broker, i, ent, total):
    e = html.escape
    name, new = ent["name"], ent["text"]
    cur = (broker.cfg["secrets"].get(name) or {}).get("guidance") or ""
    diff = line_diff(cur, new)
    flags = lint(new)
    stale = (guidance_mod.digest(cur) or "") != ent["base"]
    pills = [f"<span class='pill plain'>{len(new)} chars</span>"]
    if not new:
        pills.append("<span class='pill warn'>removes guidance</span>")
    na = guidance_mod.non_ascii_count(new)
    if na:
        pills.append(f"<span class='pill warn'>Non-ASCII characters: {na} "
                     "(shown escaped as U+XXXX in the box below)</span>")
    if flags:
        pills.append(f"<span class='pill warn'>Flagged: {e(', '.join(flags))}</span>")
    if stale:
        pills.append("<span class='pill warn'>changed since proposed</span>")
    notes = ""
    if flags:
        notes += (f"<p class=gflag>Flagged: {e(', '.join(flags))}. These phrases look like they lower a "
                  "rating or steer the classifier. Read the whole text.</p>")
    if stale:
        notes += ("<p class=gflag>Changed since proposed: the current guidance is different from what it "
                  "was when the agent wrote this, so the diff below is against the new current text. "
                  "Tick the box only if you still want this applied.</p>")
    return (
        f"<details class=gentry{' open' if total <= INLINE_OPEN else ''}><summary><b>{e(name)}</b> "
        f"{' '.join(pills)}</summary><div class=gbody><div class=gcols>"
        f"<div class=gcol><h4>Current guidance</h4>{_col([d for d in diff if d[0] != '+'], '-', 'gdel', 'none')}</div>"
        f"<div class=gcol><h4>Proposed guidance</h4>"
        f"{_col([d for d in diff if d[0] != '-'], '+', 'gadd', '(empty: removes the guidance)')}</div></div>"
        f"{notes}<label class=gpick><input type=checkbox name='apply_{i}' value=1 data-gapply> "
        f"Apply this one</label></div></details>")


def actions_html(broker, req):
    """The review entries and the two buttons, inside the decision form. Not selected by
    default; no Always, no timed grant, no approve-everything shortcut."""
    entries = req.spec["entries"]
    body = "".join(entry_html(broker, i, ent, len(entries)) for i, ent in enumerate(entries))
    return (f"<div class=gprop>{body}</div>"
            "<div class=decide-row><button class='btn approve' name=decision value=approve "
            "data-gapply-btn>Apply selected</button>"
            "<button class='btn deny' name=decision value=deny>Deny all</button></div>"
            "<p class=scope><small class=muted>Only ticked entries are applied; the rest are denied. "
            "No standing approval can cover a guidance proposal.</small></p>")
