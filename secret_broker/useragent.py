"""The User-Agent the broker sends on its own outbound HTTP and WebSocket requests.

urllib's default (`Python-urllib/3.x`) is blocked outright by Cloudflare and similar services, and
says nothing about who is calling. This names the tool, its build and where to read about it, so an
operator can allow-list it and a service's owner can tell what it is. A request that already carries
its own User-Agent (an agent may set one on an http call or session) keeps it; this is only the default.
"""
import os

PROJECT_URL = "https://github.com/rgregg/agent-secret-broker"


def _version():
    sha = "".join(c for c in (os.environ.get("BROKER_GIT_SHA") or "") if c.isalnum())[:12]
    return sha or "dev"


USER_AGENT = f"agent-secret-broker/{_version()} (+{PROJECT_URL})"
