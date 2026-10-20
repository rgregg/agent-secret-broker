"""Secret backends: the contract (base), the bundled implementations and the registry.

    from secret_broker.backends import VaultBackend, BackendError, ...

The broker core imports only from here and only the contract names. Concrete
backends are built through `registry.build_backend(cfg)`."""
from .base import (META_FIELD, AutoShape, BackendConfigError, BackendConflict, BackendError,
                   BackendInvalid, BackendNotFound, BackendRateLimited, BackendSpec,
                   BackendUnavailable, CatalogRow, Item, NotSupported, VaultBackend, error_class)
from .bitwarden import BwBackend, BwServeBackend, _auto_info  # noqa: F401
from .file import FileBackend
from .local import LocalBackend
from .memory import MemoryBackend
from .registry import build_backend, known, load_plugins, register

__all__ = [
    "META_FIELD", "AutoShape", "BackendConfigError", "BackendConflict", "BackendError",
    "BackendInvalid", "BackendNotFound", "BackendRateLimited", "BackendSpec",
    "BackendUnavailable", "CatalogRow", "Item", "NotSupported", "VaultBackend", "error_class",
    "BwBackend", "BwServeBackend", "FileBackend", "LocalBackend", "MemoryBackend",
    "build_backend", "known", "load_plugins", "register",
]
