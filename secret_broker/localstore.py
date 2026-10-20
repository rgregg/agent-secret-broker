"""`python -m secret_broker.localstore`: the admin CLI for the encrypted local store.

The store itself lives in secret_broker/backends/localstore.py; this module keeps
the old import path working and is the thin `-m` entry point."""
from .backends.localstore import *  # noqa: F401,F403
from .backends.localstore import (BackendConfigError, EnvKeySource, FileKeySource, Key,  # noqa: F401
                                   LocalStore, StoreError, atomic_write, create_store,
                                   key_source_from_config, make_wrap)
from .backends.local import LocalBackend  # noqa: F401

if __name__ == "__main__":
    from .localstore_cli import main
    raise SystemExit(main())
