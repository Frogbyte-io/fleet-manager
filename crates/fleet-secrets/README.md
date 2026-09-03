# fleet-secrets

The controller's encrypted secret records: provider credentials and other
sensitive values the controller must keep, sealed under a separately mounted
master key. Nothing here decrypts anything for display; resolution happens
just in time for the operation that needs the value, and the value redacts
every rendering.

## Envelope

Each value is stored as a binary envelope:

| Bytes | Content |
|---|---|
| 4 | Magic `FSEK` |
| 1 | Envelope format version (currently `1`) |
| 4 | Key version, little-endian |
| 24 | XChaCha20-Poly1305 nonce (fresh OS randomness per seal) |
| n+16 | Ciphertext and AEAD tag |

The AEAD's additional data binds the ciphertext to its record id and key
version, so a value copied between records — or a nonce replayed against a
different record — fails authentication. A known-vector unit test pins this
layout; changing it is a reviewed migration, not drift.

## Master key file

The key file is a small text file, owned by the controller's user and mode
`0600` (enforced: the store refuses a more exposed file). Lines are
`<version> <64 hex chars>` (a 32-byte key), with `#` comments and blank lines
allowed:

```
# current key first; older keys follow for rewrap
3  4f2c...9a
2  b17e...02
1  a1a2...c0
```

The **first line is the current key** and must carry the strictly greatest
version. Every later line is an older key kept only so records sealed under
it can still be read and rewrapped. Versions must be unique; the file must
contain at least one key.

Generate a key with 32 bytes of OS randomness, e.g.:

```sh
printf '1 %s\n' "$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')" > master_key
chmod 600 master_key
```

## Rotation

1. Generate a new key, prepend it to the key file with a higher version, and
   move the previous current line below it.
2. Restart (or reopen) the controller so the store parses the new file.
3. Run rewrap: every record still sealed under an older version is decrypted
   with the retained key and re-sealed under the current one. No external
   provider is involved, nothing is deleted, and records stay resolvable
   throughout.

The compose deployment mounts this file as the Docker secret `master_key`
(see `deploy/README.md`); the configuration validates its presence and
permissions before readiness.
