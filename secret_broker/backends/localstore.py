"""Local encrypted secret store: one AES-256-GCM file, no vault server needed.

File layout: one line of canonical JSON (the header), a newline, then the body
`nonce(12) || ciphertext || tag`. The header is the AEAD associated data, so a
changed `v`, `cipher` or wrap makes the body fail to authenticate. A random data
key (DEK) encrypts the body; each wrap holds the DEK encrypted under a key
derived from one passphrase (scrypt) or used directly (raw 32-byte key).

The decrypted document lives in memory only and is dropped after `idle_timeout`.
Writes take a flock on `<path>.lock`, re-read the current file, apply the change
and replace the file atomically (one `.bak` generation is kept), so a second
writer (the admin CLI) cannot lose an update. See docs/proposals/. The backend that
uses it is local.py.
"""
import base64
import contextlib
import copy
import fcntl
import json
import logging
import os
import threading
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .base import BackendConfigError, BackendUnavailable

log = logging.getLogger("secret_broker.localstore")

FORMAT_VERSION = 1
CIPHER = "aes-256-gcm"
SCRYPT_MIN_N = 2 ** 15
SCRYPT_MAX_N = 2 ** 20          # a header is authenticated only after the wrap is tried
SCRYPT_DEFAULT = {"n": SCRYPT_MIN_N, "r": 8, "p": 1}


class StoreError(BackendUnavailable):
    """A store problem. `reason` is a short stable code for the audit log; the
    message never contains key material or secret values."""

    def __init__(self, message, reason="error"):
        super().__init__(message)
        self.reason = reason


def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _unb64(s, field):
    try:
        return base64.b64decode(s, validate=True)
    except (ValueError, TypeError):
        raise StoreError(f"store header field {field} is malformed", "corrupt") from None


# -- key sources ---------------------------------------------------------------
class Key:
    """Key material as read from a key source: a passphrase, or a raw 32-byte key
    (given as base64). Never printed."""

    def __init__(self, text):
        self.text = text
        self.raw = None
        try:
            cand = base64.b64decode(text, validate=True)
            if len(cand) == 32:
                self.raw = cand
        except (ValueError, TypeError):
            pass

    def __repr__(self):
        return "Key(...)"


def _trim_newline(data):
    if data.endswith(b"\r\n"):
        return data[:-2]
    return data[:-1] if data.endswith(b"\n") else data


def _key_from_bytes(data, what):
    data = _trim_newline(data)
    if not data:
        raise StoreError(f"{what} is empty", "key_missing")
    try:
        return Key(data.decode("utf-8"))
    except UnicodeDecodeError:
        raise StoreError(f"{what} is not valid UTF-8", "key_missing") from None


class FileKeySource:
    _warned = set()

    def __init__(self, path):
        self.path = path

    def read(self):
        try:
            st = os.stat(self.path)
            with open(self.path, "rb") as f:
                data = f.read()
        except OSError as e:
            raise StoreError(f"cannot read key file {self.path}: {e.strerror}", "key_missing") from None
        if st.st_mode & 0o077 and self.path not in FileKeySource._warned:
            FileKeySource._warned.add(self.path)        # secret mounts are often 0444: warn once
            log.warning("key file %s is readable by other users (mode %o)", self.path,
                        st.st_mode & 0o777)
        return _key_from_bytes(data, f"key file {self.path}")


class EnvKeySource:
    def __init__(self, name):
        self.name = name

    def read(self):
        val = os.environ.get(self.name)
        if val is None:
            raise StoreError(f"environment variable {self.name} is not set", "key_missing")
        return _key_from_bytes(val.encode("utf-8"), f"environment variable {self.name}")


def key_source_from_config(ks):
    """Build a key source from the `key_source` settings block; errors name the field."""
    if not isinstance(ks, dict):
        raise BackendConfigError("backend.key_source: required (an object with a type)")
    kind = ks.get("type")
    if kind == "file":
        want = {"type", "path"}
    elif kind == "env":
        want = {"type", "name"}
    else:
        raise BackendConfigError(f"backend.key_source.type: must be 'file' or 'env', got {kind!r}")
    for k in ks:
        if k not in want:
            raise BackendConfigError(f"backend.key_source.{k}: unknown field")
    for k in want - {"type"}:
        if not isinstance(ks.get(k), str) or not ks[k]:
            raise BackendConfigError(f"backend.key_source.{k}: required (a non-empty string)")
    return FileKeySource(ks["path"]) if kind == "file" else EnvKeySource(ks["name"])


# -- format --------------------------------------------------------------------
def _canon(header):
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("ascii")


def _wrap_aad(wid):
    return b"asb-wrap\0" + wid.encode("utf-8") + b"\0" + str(FORMAT_VERSION).encode() + b"\0" + CIPHER.encode()


def _derive_kek(kdf, key):
    """The 32-byte key-encryption key for one wrap, or None if this key cannot
    apply (a raw wrap needs a raw key)."""
    alg = kdf.get("alg") if isinstance(kdf, dict) else None
    if alg == "raw":
        return key.raw
    if alg != "scrypt":
        raise StoreError("store uses an unknown key derivation", "unsupported")
    try:
        n, r, p = int(kdf["n"]), int(kdf["r"]), int(kdf["p"])
        salt = _unb64(kdf["salt"], "kdf.salt")
    except (KeyError, TypeError, ValueError):
        raise StoreError("store header has a malformed key derivation", "corrupt") from None
    if not SCRYPT_MIN_N <= n <= SCRYPT_MAX_N or n & (n - 1) or not 1 <= r <= 32 or not 1 <= p <= 16:
        raise StoreError("store key derivation parameters are out of range", "corrupt")
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(key.text.encode("utf-8"))


def make_wrap(wid, dek, key, kdf=None):
    """Wrap `dek` under `key`: scrypt for a passphrase, direct for a raw key."""
    if key.raw is not None:
        kdf = {"alg": "raw"}
    else:
        kdf = {"alg": "scrypt", **(kdf or SCRYPT_DEFAULT), "salt": _b64(os.urandom(16))}
        if kdf["n"] < SCRYPT_MIN_N:
            raise StoreError("scrypt n must be at least 2**15", "error")
    kek = _derive_kek(kdf, key)
    nonce = os.urandom(12)
    return {"id": wid, "kdf": kdf, "nonce": _b64(nonce),
            "wrapped_dek": _b64(AESGCM(kek).encrypt(nonce, dek, _wrap_aad(wid)))}


def parse(raw):
    """(header dict, header bytes, body bytes). Checks version and cipher first."""
    head, sep, body = raw.partition(b"\n")
    if not sep:
        raise StoreError("store file is not in the expected format", "corrupt")
    try:
        header = json.loads(head)
    except ValueError:
        raise StoreError("store file header is not valid JSON", "corrupt") from None
    if not isinstance(header, dict):
        raise StoreError("store file header is malformed", "corrupt")
    if header.get("v") != FORMAT_VERSION:
        raise StoreError(f"unsupported store format version {header.get('v')!r}", "unsupported")
    if header.get("cipher") != CIPHER:
        raise StoreError(f"unsupported store cipher {header.get('cipher')!r}", "unsupported")
    if not isinstance(header.get("wraps"), list) or not header["wraps"]:
        raise StoreError("store file header has no key wraps", "corrupt")
    return header, head, body


def unwrap_dek(header, key):
    """The DEK, by trying each wrap with `key`. Raises StoreError(wrong_key)."""
    for w in header["wraps"]:
        try:
            kek = _derive_kek(w["kdf"], key)
            if kek is None:
                continue
            return AESGCM(kek).decrypt(_unb64(w["nonce"], "wrap.nonce"),
                                       _unb64(w["wrapped_dek"], "wrap.wrapped_dek"),
                                       _wrap_aad(str(w["id"])))
        except InvalidTag:
            continue
        except (KeyError, TypeError):
            raise StoreError("store header has a malformed key wrap", "corrupt") from None
    raise StoreError("the key does not open this store (wrong key, or a damaged header)", "wrong_key")


def decrypt_body(dek, head_bytes, body):
    if len(body) < 12 + 16:
        raise StoreError("store body is truncated", "corrupt")
    try:
        plain = AESGCM(dek).decrypt(body[:12], body[12:], head_bytes)
        doc = json.loads(plain)
    except InvalidTag:
        raise StoreError("store failed authentication (corrupt or tampered); "
                         "not overwritten, a previous copy may be at the .bak file", "corrupt") from None
    except ValueError:
        raise StoreError("store document is not valid JSON", "corrupt") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("items", {}), dict):
        raise StoreError("store document is malformed", "corrupt")
    doc.setdefault("items", {})
    return doc


def encrypt_store(header, dek, doc):
    head = _canon(header)
    nonce = os.urandom(12)
    return head + b"\n" + nonce + AESGCM(dek).encrypt(nonce, json.dumps(doc).encode("utf-8"), head)


def _fsync_dir(d):
    fd = os.open(d, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path, data):
    """Temp file in the same directory, fsync, keep one .bak, rename, fsync the
    directory. A failure at any step leaves the old file in place."""
    d = os.path.dirname(os.path.abspath(path))
    tmp = f"{path}.tmp.{os.getpid()}.{os.urandom(4).hex()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if os.path.exists(path):
            bak_tmp = path + ".bak.tmp"
            with contextlib.suppress(FileNotFoundError):
                os.unlink(bak_tmp)
            os.link(path, bak_tmp)              # the old inode is never modified: we rename over it
            os.replace(bak_tmp, path + ".bak")
        os.replace(tmp, path)
    except BaseException:
        for leftover in (tmp, path + ".bak.tmp"):
            with contextlib.suppress(OSError):
                os.unlink(leftover)
        raise
    _fsync_dir(d)


@contextlib.contextmanager
def _flock(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)                             # closing releases the lock


def create_store(path, key, doc=None, recovery_key=None, kdf=None):
    """Write a new store. `key` is a Key; `recovery_key` an optional second Key
    with its own wrap. Refuses to overwrite an existing file."""
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, mode=0o700, exist_ok=True)
    if os.path.exists(path):
        raise StoreError(f"{path} already exists", "error")
    dek = os.urandom(32)
    wraps = [make_wrap("primary", dek, key, kdf)]
    if recovery_key is not None:
        wraps.append(make_wrap("recovery", dek, recovery_key, kdf))
    header = {"v": FORMAT_VERSION, "cipher": CIPHER, "wraps": wraps}
    with _flock(path + ".lock"):
        atomic_write(path, encrypt_store(header, dek, doc if doc is not None else {"items": {}}))


# -- the store -------------------------------------------------------------------
class LocalStore:
    """Decrypts on demand, holds the document for `idle_timeout` seconds, and
    applies changes under flock. Thread-safe."""

    _warned = set()

    def __init__(self, path, key_source, idle_timeout=300):
        self.path = path
        self._key_source = key_source
        self._idle_timeout = idle_timeout
        self._lock = threading.RLock()
        self._doc = self._dek = self._wraps = self._sig = None
        self._timer = None
        self._last_used = 0.0
        self.on_event = None

    def _emit(self, name, **fields):
        if self.on_event:
            try:
                self.on_event(name, **fields)
            except Exception:  # noqa: BLE001
                pass

    # -- idle drop ---------------------------------------------------------
    def _touch(self):
        self._last_used = time.monotonic()
        if self._timer is not None:
            self._timer.cancel()
        if self._idle_timeout and self._idle_timeout > 0:
            self._timer = threading.Timer(self._idle_timeout, self._idle_drop)
            self._timer.daemon = True
            self._timer.start()

    def _idle_drop(self):
        with self._lock:
            if self._doc is None:
                return
            if time.monotonic() - self._last_used < self._idle_timeout - 0.05:
                return
            self._doc = self._dek = self._wraps = self._sig = self._timer = None
        self._emit("store_locked", idle_seconds=self._idle_timeout)

    def close(self):
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
            self._doc = self._dek = self._wraps = self._sig = self._timer = None

    # -- reading -----------------------------------------------------------
    def _signature(self):
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            raise StoreError(f"store {self.path} does not exist", "not_found") from None
        except OSError as e:
            raise StoreError(f"cannot stat store {self.path}: {e.strerror}", "error") from None
        if st.st_mode & 0o077 and self.path not in LocalStore._warned:
            LocalStore._warned.add(self.path)           # warn once per path, never fail
            log.warning("store %s is accessible by other users (mode %o); chmod 600 it",
                        self.path, st.st_mode & 0o777)
        return (st.st_mtime_ns, st.st_size, st.st_ino)

    def _load(self):
        """Current (doc, header) from disk, using the cached DEK when the wraps are
        unchanged. Call with the lock held."""
        had_state = self._doc is not None
        try:
            sig = self._signature()
            if had_state and sig == self._sig:
                return
            with open(self.path, "rb") as f:
                raw = f.read()
            header, head, body = parse(raw)
            dek = self._dek if self._dek is not None and header["wraps"] == self._wraps else None
            fresh_key = dek is None
            if fresh_key:
                dek = unwrap_dek(header, self._key_source.read())
            doc = decrypt_body(dek, head, body)
        except StoreError as e:
            self._doc = self._dek = self._wraps = self._sig = None
            self._emit("store_unlock_failed", reason=e.reason)
            raise
        except OSError as e:
            raise StoreError(f"cannot read store {self.path}: {e.strerror}", "error") from None
        self._doc, self._dek, self._wraps, self._sig = doc, dek, header["wraps"], sig
        if had_state:
            self._emit("store_reloaded", items=len(doc["items"]))
        else:
            self._emit("store_unlocked", items=len(doc["items"]))

    def read(self, fn):
        """fn(items) -> result, on the current document. fn must not retain or
        mutate `items`."""
        with self._lock:
            self._load()
            self._touch()
            return fn(self._doc["items"])

    def warm(self):
        self.read(lambda items: None)

    # -- writing -----------------------------------------------------------
    def mutate(self, fn):
        """Apply fn(items) to the freshest document and write it back. If fn raises,
        or the write fails, nothing changes on disk or in memory."""
        with self._lock, _flock(self.path + ".lock"):
            self._load()                        # sees whatever is on disk now
            doc = copy.deepcopy(self._doc)
            result = fn(doc["items"])
            header = {"v": FORMAT_VERSION, "cipher": CIPHER, "wraps": self._wraps}
            atomic_write(self.path, encrypt_store(header, self._dek, doc))
            self._doc, self._sig = doc, self._signature()
            self._touch()
            self._emit("store_written", items=len(doc["items"]))
            return result

    # -- key management (admin CLI) ------------------------------------------
    def wrap_ids(self):
        """The ids of the key wraps in the file (names only)."""
        with self._lock:
            self._load()
            return [str(w.get("id")) for w in self._wraps]

    def rewrap(self, wid, key, kdf=None):
        """Replace (or add) the wrap `wid` so that `key` opens it. The data key and
        the other wraps are unchanged; the body is re-encrypted because the header is
        its associated data."""
        with self._lock, _flock(self.path + ".lock"):
            self._load()
            wraps = [w for w in self._wraps if w.get("id") != wid]
            wraps.append(make_wrap(wid, self._dek, key, kdf))
            self._write_header(wraps, self._dek)

    def drop_wrap(self, wid):
        with self._lock, _flock(self.path + ".lock"):
            self._load()
            wraps = [w for w in self._wraps if w.get("id") != wid]
            if len(wraps) == len(self._wraps) or not wraps:
                raise StoreError(f"cannot remove wrap {wid!r}", "error")
            self._write_header(wraps, self._dek)

    def rotate_dek(self, keys, kdf=None):
        """New data key; every wrap named in `keys` ({wid: Key}) is rebuilt under it
        and all other wraps are dropped (they could not open the new key)."""
        if not keys:
            raise StoreError("rotate_dek needs at least one key", "error")
        with self._lock, _flock(self.path + ".lock"):
            self._load()
            dek = os.urandom(32)
            self._write_header([make_wrap(wid, dek, k, kdf) for wid, k in keys.items()], dek)

    def _write_header(self, wraps, dek):
        header = {"v": FORMAT_VERSION, "cipher": CIPHER, "wraps": wraps}
        atomic_write(self.path, encrypt_store(header, dek, self._doc))
        self._dek, self._wraps, self._sig = dek, wraps, self._signature()
        self._touch()
        self._emit("store_rekeyed", wraps=len(wraps))
