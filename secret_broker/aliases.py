"""Aliases: other names for one credential (its former names, kept after a rename).

The pure rules, shared by the catalog loader, the editor and the request path (see Broker.resolve_names, the one
place a requested name becomes a canonical name):

* `parse` validates the `aliases` list in a credential's `broker` metadata (called by Broker._entry, the validator
  the catalog loader runs, so the editor cannot save what the loader would reject).
* `build_map` turns the loaded catalog into `{alias: canonical}`. A name that is also a credential name never
  becomes an alias (the credential wins), and an alias two credentials claim belongs to neither (fail closed, as a
  credential name claimed twice already does).
* `resolve` rewrites requested names to canonical names. Everything after it (deny lists, destination guard,
  policies, rules, grants, risk) therefore only ever sees the canonical name.
* `note_html` is the "requested as OLD" line a card shows when a request used an alias.

An alias is never listed to an agent: it exists only as an input to `resolve`.
"""
import html

MAX_ALIASES = 10


def parse(raw, own_name, name_re, reserved):
    """The validated alias tuple for a metadata value (None when there are none). ValueError, with a fixed text
    that never includes the offending value, otherwise."""
    if raw is None:
        return None
    if not isinstance(raw, list):
        raise ValueError("aliases must be a list of credential names")
    if len(raw) > MAX_ALIASES:
        raise ValueError(f"aliases can hold at most {MAX_ALIASES} names")
    out = []
    for a in raw:
        if not isinstance(a, str) or not name_re.match(a) or a in reserved:
            raise ValueError("aliases must be credential names (1-41 chars of a-z 0-9 _ -)")
        if a == own_name:
            raise ValueError("aliases cannot repeat the credential's own name")
        if a in out:
            raise ValueError("aliases cannot repeat a name")
        out.append(a)
    return tuple(out) or None


def build_map(entries):
    """({alias: canonical}, sorted names dropped) for a catalog `{name: entry}`."""
    claims = {}
    for name, entry in entries.items():
        for a in entry.get("aliases") or ():
            claims.setdefault(a, []).append(name)
    amap, dropped = {}, []
    for a, owners in claims.items():
        if a in entries or len(owners) > 1:
            dropped.append(a)
        else:
            amap[a] = owners[0]
    return amap, sorted(dropped)


def resolve(amap, names):
    """(names with every alias replaced by its credential, {alias: canonical} for those that were). Anything that
    is not a known alias (a canonical name, an unknown name, a non-string, a non-list) is passed through."""
    if not isinstance(names, (list, tuple)):
        return names, {}
    used, out = {}, []
    for n in names:
        c = amap.get(n) if isinstance(n, str) else None
        if c is not None:
            used[n] = c
        out.append(c if c is not None else n)
    return out, used


def note_html(used):
    """The one-line flag for a card or a detail view, or ''. Names only (they are escaped here)."""
    if not used:
        return ""
    e = html.escape
    parts = ", ".join(f"<code>{e(a)}</code> (now <code>{e(c)}</code>)" for a, c in sorted(used.items()))
    return (f"<p class=scope><small class=muted>Requested as {parts}: the agent used a former name. "
            f"Remove it on the credential's page to stop that.</small></p>")
