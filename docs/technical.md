# Technical details

The encrypted wallet file layout is:
- nonce: 24 bytes,
- salt: 16 bytes,
- encrypted_header: 80 bytes,
- ciphertext: variable length,

The header key is derived by `argon2id` according to the `difficulty` parameters using as input the `user password` concatenated with the `salt` field. If keyfiles are used, a set of hashes will be deterministically calculated and concatenated to the other inputs. For details see the [key_derivation.rs](./src/key_derivation.rs) file.

Using [XChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305#XChaCha20-Poly1305_%E2%80%93_extended_nonce_variant) and the `nonce` field the `encrypted_header` header is encrypted/decrypted using above derived header key.

Once decrypted, the header layout is:
- key: 32 bytes,
- nonce: 24 bytes,
- version: 4 bytes,
- length: 4 bytes,

The `key` encrypts/decrypts the first `length` bytes of `ciphertext` using the header `nonce` and `XChaCha20-Poly1305`.

Once decrypted we have two options depending on `version`:
- for version = 0, a gzipped json containing exactly what's in show in the `show-secrets` command.
- for version = 1 or 2, the seed entropy

By default we use [libsodium](https://doc.libsodium.org/)'s implementation of `argon2id` and `XChaCha20-Poly1305`, but there are tests cross-checking alternative libraries. So they can easily be used in future releases if necessary.

## About padding

The ciphertext is padded to a minimum value to avoid exposing the json size and thus avoiding exposing some information about the secrets.

Also by default random bytes are added (see `--min-additional-padding-bytes` and `--max-additional-padding-bytes` on `singlesig-generate` and `multisig-generate`) to make the file size unpredictable.

Note that this layout makes it perfectly possible to write the encrypted wallet directly to a block device (like a SD card).