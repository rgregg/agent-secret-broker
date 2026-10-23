"""Fixed failure labels for the release/exchange path.

An exception raised while a credential is being used (reading the vault, filling a request,
connecting, sending) can carry the filled-in value: http.client quotes the offending header
value or path in its message, urllib quotes the url, and so on. Nothing that crosses a trust
boundary (agent response, audit, history, request details, logs, notifications, pages) may
therefore ever contain `str(exc)` for such an exception. This module is the one place that turns
an exception into text: a fixed label from a closed set.
"""
import http.client
import socket
import ssl
import urllib.error

from .destguard import DestinationRefused

TIMEOUT, TLS, DNS, CONNECTION = "timeout", "tls", "dns", "connection"
INVALID, VAULT, DENIED, OTHER = "invalid request", "vault", "destination not allowed", "other"
LABELS = (TIMEOUT, TLS, DNS, CONNECTION, INVALID, VAULT, DENIED, OTHER)


class InvalidRequest(ValueError):
    """The filled-in request cannot be sent. Carries no text: the label is the whole message."""

    def __init__(self):
        super().__init__(INVALID)


class ReleaseFailed(Exception):
    """A release that failed, reduced to its label before it leaves the code that saw the cause."""

    def __init__(self, label):
        super().__init__("release failed: " + label)
        self.label = label if label in LABELS else OTHER


def classify(exc):
    """The label for `exc`: one of LABELS. Never its text."""
    if isinstance(exc, ReleaseFailed):
        return exc.label
    seen = 0
    while isinstance(exc, urllib.error.URLError) and not isinstance(exc, urllib.error.HTTPError) \
            and isinstance(exc.reason, BaseException) and seen < 4:
        exc, seen = exc.reason, seen + 1
    if isinstance(exc, DestinationRefused):
        return DENIED
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return TIMEOUT
    if isinstance(exc, ssl.SSLError) or isinstance(exc, ssl.CertificateError):
        return TLS
    if isinstance(exc, socket.gaierror):
        return DNS
    if isinstance(exc, http.client.InvalidURL):
        return INVALID
    if isinstance(exc, (ConnectionError, OSError, http.client.HTTPException)):
        return CONNECTION
    if isinstance(exc, (ValueError, UnicodeError, LookupError)):
        return INVALID
    if type(exc).__name__.startswith("Backend"):
        return VAULT
    return OTHER


def public(label):
    """The label an AGENT may see. A guard refusal reads as a plain connection failure, so a call
    cannot be used to probe which addresses the broker is willing to reach; the real reason
    (`destination not allowed`) goes to the operator audit only, as `reason_class`."""
    return CONNECTION if label == DENIED else label


def release_text(exc):
    """The only text a failed release carries anywhere an agent, a log or a page could see it."""
    return "release failed: " + public(classify(exc))
