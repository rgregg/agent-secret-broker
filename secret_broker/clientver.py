"""The version of `asb` a client runs, and when to recommend an upgrade.

A client names its version in its `User-Agent` (`asb/1.1 (+https://...)`). That header is the client's own text, so
only a bounded digits-and-dots version is ever kept: anything else (another tool, no header, a malformed one) is
"unknown", which is shown as such and is never flagged as outdated. The comparison is numeric, field by field.

Outdated means older than the threshold: `clients.min_version` in the broker config when set (`none` turns the
recommendation off), else the newest client this build of the broker knows (`LATEST_CLIENT_VERSION`). Bump the
latter, with `CLI_VERSION` in client/asb and `USER_AGENT` in crates/asb-cli/src/broker.rs, when a CLI release should
make older ones show "upgrade recommended"; tests pin the three together.
"""
import re

LATEST_CLIENT_VERSION = "1.1"
MAX_LEN = 24
_VER = re.compile(r"[0-9]{1,4}(?:\.[0-9]{1,4}){0,3}")
_UA = re.compile(r"asb/([0-9]{1,4}(?:\.[0-9]{1,4}){0,3})(?:\s|\Z)")


def parse_user_agent(ua):
    """The `asb` version in a User-Agent header, or '' when it carries none that is well formed."""
    if not isinstance(ua, str):
        return ""
    m = _UA.match(ua[:200])
    return m.group(1) if m else ""


def valid(v):
    return isinstance(v, str) and _VER.fullmatch(v) is not None


def _tuple(v):
    return tuple(int(x) for x in v.split(".")) if valid(v) else None


def outdated(version, threshold):
    """True when `version` is older than `threshold`; False when not; None when either is unknown (never flagged)."""
    a, b = _tuple(version), _tuple(threshold)
    if a is None or b is None:
        return None
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)) < b + (0,) * (n - len(b))


def threshold(configured):
    """The version below which a client is flagged: the configured one, else the newest known; None = never flag."""
    if configured is None:
        return LATEST_CLIENT_VERSION
    return None if configured == "none" else configured


def expected(configured, notice_enabled=True):
    """The one version string the broker tells clients (`latest_client_version` in its answers), or None to say nothing.

    It is the version a client is judged against (see `threshold`), the same for every client. Clients print an
    "update is available" notice from it, with their own compiled-in URL and text: the broker sends no text, no link.
    `clients.update_notice: false`, `clients.min_version: "none"` or an invalid value send nothing.
    """
    t = threshold(configured) if notice_enabled else None
    return t if valid(t) else None


def label(version):
    return version if valid(version) else "unknown"
