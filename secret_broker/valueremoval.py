"""What removing one variable from a credential must do to the vault.

Pure rules (no vault access), shared by `Broker.remove_value` and its tests. A variable names a vault field and,
for a structured field, a key inside it. Removal really deletes the value, but never more than that variable owned:

  key_dropped    the variable has a `key` no other variable reads: only that key leaves the field's text (the field and its other keys
                 stay); if no key is left the field itself goes
  field_kept     another variable still uses the same field: only the metadata changes, the vault is untouched
  field_deleted  nobody else uses the field: the field is removed (a built-in field is cleared)

`previous_value` is ONE slot per item (see backends/base.py), not one per field, so it may hold the removed value
whatever field it came from: it is deleted whenever the vault is changed destructively, and kept when it is not.

"The same field" is deliberately wide: the item's natural slot can be named `auto`, `password`, `notes` or
`private_key`, and only the backend knows which one `auto` is, so those four count as one slot. Too wide only
means a field is kept (and the page says so); it never means a shared value is deleted.
"""
KEY_DROPPED, FIELD_KEPT, FIELD_DELETED = "key_dropped", "field_kept", "field_deleted"

_NATURAL = frozenset({"auto", "password", "notes", "private_key", ""})


def _slot(ref):
    f = (ref if isinstance(ref, dict) else {}).get("field") or "auto"
    return "<natural>" if f in _NATURAL else f


def plan(vars_, var):
    """(outcome, field) for removing `var` from the metadata's `vars` map. `field` is the vault field to act on
    (as written in the variable's reference; `auto` when it names none)."""
    ref = vars_[var] if isinstance(vars_[var], dict) else {}      # the loader reads a non-object reference as {}
    field = ref.get("field") or "auto"
    mine = _slot(ref)
    if ref.get("key"):
        # another variable that reads the same key (or the whole field) still needs it
        for v, r in vars_.items():
            r = r if isinstance(r, dict) else {}
            if v != var and _slot(r) == mine and (not r.get("key") or r.get("key") == ref["key"]):
                return FIELD_KEPT, field
        return KEY_DROPPED, field
    if any(_slot(r) == mine for v, r in vars_.items() if v != var):
        return FIELD_KEPT, field
    return FIELD_DELETED, field
