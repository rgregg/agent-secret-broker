"""The backend registry: `backend.type` -> `BackendSpec`.

The broker never imports a concrete backend. `__main__` calls `build_backend(cfg)`,
which validates the `backend` block through the registered spec and builds it.
Bundled specs: bw, local, file. A third-party package adds its own through the
`secret_broker.backends` entry-point group (the entry point loads a `BackendSpec`,
or a zero-argument callable returning one), or by calling `register()` itself.
A plugin that fails to load is logged and skipped, never fatal."""
import logging
import threading

from .base import BackendConfigError, BackendSpec

log = logging.getLogger("secret_broker.backends")
ENTRY_POINT_GROUP = "secret_broker.backends"

_specs = {}
_lock = threading.Lock()
_plugins_loaded = False


def register(spec, replace=False):
    """Add a backend type. Refuses to shadow an existing name unless `replace`."""
    if not isinstance(spec, BackendSpec) or not spec.name or not callable(spec.build) \
            or not callable(spec.validate):
        raise TypeError("register() needs a BackendSpec with a name, build and validate")
    with _lock:
        if spec.name in _specs and not replace:
            raise ValueError(f"backend type {spec.name!r} is already registered")
        _specs[spec.name] = spec


def load_plugins(entry_points=None):
    """Load third-party specs from the entry-point group. Safe: every failure is
    logged and skipped. `entry_points` (an iterable of objects with .name and
    .load()) is for tests."""
    if entry_points is None:
        try:
            from importlib.metadata import entry_points as eps
            entry_points = eps(group=ENTRY_POINT_GROUP)
        except Exception as e:  # noqa: BLE001
            log.warning("cannot list %s entry points: %s", ENTRY_POINT_GROUP, e)
            return []
    loaded = []
    for ep in entry_points:
        try:
            obj = ep.load()
            spec = obj() if callable(obj) and not isinstance(obj, BackendSpec) else obj
            register(spec)
            loaded.append(spec.name)
        except Exception as e:  # noqa: BLE001 - a broken plugin must not stop the broker
            log.warning("backend plugin %s not loaded: %s: %s", getattr(ep, "name", "?"),
                        type(e).__name__, e)
    return loaded


def _ensure():
    global _plugins_loaded
    with _lock:
        first = not _specs
    if first:
        from . import bitwarden, file, local, memory
        for spec in (bitwarden.SPEC, local.SPEC, file.SPEC, memory.SPEC):
            try:
                register(spec)
            except ValueError:
                pass
    if not _plugins_loaded:
        _plugins_loaded = True
        load_plugins()


def known():
    _ensure()
    return sorted(_specs)


def get_spec(name):
    _ensure()
    return _specs.get(name)


def validate_config(cfg):
    """The matching spec for cfg["backend"], after validating the block. Raises
    BackendConfigError naming the field."""
    b = cfg.get("backend")
    if not isinstance(b, dict):
        raise BackendConfigError("backend: required (an object with a type)")
    kind = b.get("type")
    spec = get_spec(kind) if isinstance(kind, str) else None
    if spec is None:
        raise BackendConfigError(f"backend.type: must be one of {known()}, got {kind!r}")
    spec.validate(b)
    return spec


def build_backend(cfg):
    return validate_config(cfg).build(cfg["backend"])
