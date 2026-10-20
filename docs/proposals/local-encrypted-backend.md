# Proposal: local encrypted backend (no Bitwarden required)

Status: **implemented** (store, backend, admin CLI, imports, backend contract and
conformance suite). See "Implementation notes and deviations" at the end. Relates to
issue #6 (file backend). Supersedes its `.env` idea: secrets are kept in an encrypted
store, never a plaintext file.

## Goal

Run the broker with no Bitwarden/Vaultwarden account. Credentials live in one
encrypted file on the broker's disk, with the same behavior as the vault
backend: the store is the catalog, items carry `broker` metadata or are
auto-adopted, and `store`/`update`/"always allow"/Revoke persist.

## Scope

In v1:
- one encrypted file, key from an **environment variable or a file**;
- `type: "local"` backend, an admin CLI, one-time imports.

Deferred (not designed here): OS keychains, systemd-creds/TPM, an unlock page,
SQLite/SQLCipher, native credential-store backends, multi-broker sync.

## What encryption at rest buys

Encryption only helps if the key is not stored next to the data. It protects
against stolen disks, backups, snapshots and other local users reading the
file. It does **not** protect against anything that can read both the file and
the key source while the broker runs. Docs must say: run the broker as its own
user or container, mount the store and the key only into it, and keep the
agent's account away from both.

## Store format

One file, default `<data>/store.enc`, mode 0600, directory 0700. Whole-file
encryption, so item names and metadata are hidden too.

    header (plain JSON, authenticated as AAD):
      v: 1
      cipher: "aes-256-gcm"
      wraps: [ {id, kdf: {alg: "scrypt", n, r, p, salt}, nonce, wrapped_dek} ... ]
    body: nonce || ciphertext(JSON document) || tag

- A random 256-bit **data key (DEK)** encrypts the body. Each wrap holds the
  DEK encrypted under a key derived from one passphrase/key. Changing the
  passphrase or adding a recovery key re-wraps the DEK only. Rotating the DEK
  re-encrypts the body.
- Fresh random nonce every write; the header is AAD, so it cannot be swapped
  or downgraded. Uses `cryptography` (already a dependency).
- Document mirrors a vault item so everything downstream is unchanged:

      {"items": {"grafana": {"type": "login", "username": "...", "password": "...",
                             "notes": "...", "uris": ["https://..."],
                             "fields": {"API Key": "..."},
                             "broker": {...nested object...},
                             "previous_value": "...", "previous_replaced_at": "..."}}}

  `broker` is a real nested object. Logins and secure notes without a
  `broker` field are auto-adopted with `approval: prompt`, as today.
- Writes: temp file in the same directory, fsync, rename, fsync directory; one
  `store.enc.bak` generation kept; `flock` guards concurrent writers. mtime is
  checked at each catalog refresh so a restore or the admin CLI is picked up.
- Decrypted state lives in memory only and is dropped after `idle_timeout`;
  the next use re-reads the key source and decrypts again.

## Key source (v1: env var or file)

| `key_source` | How |
|---|---|
| `file` | Passphrase (or raw 32-byte base64 key) read from a file, e.g. a Docker/Compose secret |
| `env` | Same value from an environment variable; discouraged in docs (visible in `docker inspect` and `/proc`) |

Passphrases go through scrypt (n=2^15 minimum, tuned at `init`, 16-byte salt per
wrap); raw keys skip the KDF. A file key source warns, not fails, on loose
modes, since secret mounts are often 0444. The key is trimmed of one trailing
newline.

## Configuration changes

New backend type `local`; `bw` is unchanged; the old plaintext `file` type
stays for tests only and logs a warning outside tests.

    "backend": {
      "type": "local",
      "path": "/data/store.enc",
      "key_source": {"type": "file", "path": "/run/secrets/broker_store_key"},
      "idle_timeout": 300
    }

or `"key_source": {"type": "env", "name": "BROKER_STORE_KEY"}`.

- Missing or unknown fields fail at startup with a message naming the field.
- `build_backend` becomes a small registry (`type` -> class), so a later
  backend needs no edit to `__main__.py`.

## Managing the store

An admin CLI that runs on the broker host only:

    python -m secret_broker.localstore init              # create store, print recovery key once
    python -m secret_broker.localstore list|show NAME    # names/shapes only; never prints values
    python -m secret_broker.localstore add NAME ...      # values from stdin
    python -m secret_broker.localstore set-meta NAME FILE
    python -m secret_broker.localstore change-key        # re-wrap under a new passphrase
    python -m secret_broker.localstore import-bw         # one-time copy from a vault collection
    python -m secret_broker.localstore import-env FILE   # one-time: each key -> an env-mode item

Day to day, `asb store` and `asb update` keep working unchanged (create needs no
tap, update needs approval). `.env` files are import-only; afterwards the store
is the only place values live, and the importer says to delete the source.

## Backend contract

Implemented as `secret_broker/backends/base.py` (`VaultBackend`) and documented in
`docs/reference.md` ("Backend contract"): `get`, `put(create, keep_previous, meta)`,
`catalog`, `set_meta`, `delete`, plus capabilities (`set_meta`, `create_login`,
`edit_item`, `warm`, `on_event`, `adopts`, `export_items`, `import_items`) the core
checks instead of probing with `hasattr`. Errors are `BackendError` subclasses with
a message safe to log; never put a value in an exception.

## Audit

Names only, never values: `store_unlocked`, `store_locked` (idle), `store_unlock_failed`,
`store_written`, `store_reloaded`.

## Failure modes

- **Wrong or missing key:** broker stays up, catalog empty, requests fail with a
  clear error and an audit event; no partial reads.
- **Corrupt or truncated file:** AEAD failure is fatal for that file; the broker
  refuses to overwrite it and points at `.bak`.
- **Concurrent edit:** flock plus mtime reload, so no lost updates between the
  broker and the admin CLI.
- **Lost key and recovery key:** unrecoverable by design; `init` says so.
- **Unknown format version:** refused, never guessed at.

## Phases

1. **Core store (M).** `secret_broker/localstore.py` (format, AEAD, wraps,
   atomic write, flock, mtime reload), `LocalBackend` (contract + adoption
   shape), `file`/`env` key sources, `type: local`, backend registry. Tests:
   round trip, tamper detection (body, header, downgrade), wrong key, kill
   during write, concurrent writers, `previous_value`, adoption, and the
   existing backend-facing tests also run against `LocalBackend`.
2. **Admin CLI and migration (S-M).** The commands above; a vault-free quick
   start in `setup.md` with the threat-model note.
3. **Contract docs (S).** `reference.md` backend section.

## Calls made in this draft (change any of them)

- `init` generates a recovery key by default (printed once; `--no-recovery`
  skips it).
- Legacy plaintext `file` backend is kept for tests only.
- Admin CLI is `python -m secret_broker.localstore`, no new entry point.
- The `unlock` page is deferred with the other key sources.

## Implementation notes and deviations

- **Package, not a module.** `secret_broker/backends/` holds `base.py` (contract, error
  classes, neutral `Item` model), `registry.py`, `bitwarden.py`, `local.py`,
  `localstore.py`, `file.py`, `memory.py`. `secret_broker.localstore` remains as the
  `python -m` entry and an import shim.
- **Registry and plugins.** `type` -> `BackendSpec(name, build, validate, doc)`; third
  parties register through the `secret_broker.backends` entry-point group.
- **Admin CLI** (`secret_broker/localstore_cli.py`) adds `rotate-dek`, `export-names`,
  `import-bw` with read-back verification, `--generate-key` and `--force` (old file kept
  as `.replaced`). `add` takes values from stdin, `--json` or a hidden prompt only.
  The CLI refuses a group/world-readable store; key files only warn (as decided).
- **SSH keys.** The store also holds `ssh_key` items (private and public half), so the
  SSH signing features work on the local backend as they do with Bitwarden type-5 items.
- **Wrong key.** Verified at startup with `background_load` both off and on: the broker
  starts, the catalog is empty, `store_unlock_failed` and `catalog_error` are audited,
  requests for unknown names fail, and the next refresh recovers once the key is fixed.
- **Not done (still deferred):** OS keychains, systemd-creds/TPM, an unlock page, SQLCipher,
  multi-broker sync. Rotation history (`previous_value`) is not carried by `import-bw`.
