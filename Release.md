# Release

In order to verify the release, you'll need to have gpg installed on your system. Once you've obtained a copy (and hopefully verified that as well), you'll first need to import the keys of the maintainers that sign releases if you haven't done so already:

```bash
curl https://raw.githubusercontent.com/planktonlabs/frozenkrill/master/keys/dr.asc | gpg --import
curl https://raw.githubusercontent.com/planktonlabs/frozenkrill/master/keys/douglaz.asc | gpg --import
```

These are the release signing keys:

| Key file | Owner | Fingerprint |
|---|---|---|
| `keys/dr.asc` | Data Retriever | `6ABC EF68 60AA A3C8 F167  5F6F E1D2 0729 1D10 41E5` |
| `keys/douglaz.asc` | Allan Douglas | `6C5A D2D5 3951 7CC0 4C0A  8278 1EF1 5FB7 C0CC 66C1` |

Once you have the required PGP keys, you can verify the files. For instance after downloading a file and its signature `.sig`, run on the same directory:

```bash
gpg --verify frozenkrill-x86_64-linux.tar.gz.sig
```

You should see something like:

```
gpg: assuming signed data in 'frozenkrill-x86_64-linux.tar.gz'
gpg: Signature made Thu Nov 12 18:44:36 2026 UTC
gpg:                using EDDSA key 6C5AD2D539517CC04C0A82781EF15FB7C0CC66C1
gpg: Good signature from "Allan Douglas <allandouglas@gmail.com>" [unknown]
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: 6C5A D2D5 3951 7CC0 4C0A  8278 1EF1 5FB7 C0CC 66C1
```

`Good signature` is what matters. The `WARNING` only means you haven't certified the key yourself: check that the `Primary key fingerprint` is one of the fingerprints in the table above.

The above procedure should be enough to verify integrity and authenticity, but the checksums may be checked separately by downloading `sha512-manifest-checksums.txt` and then running:

```bash
sha512sum --ignore-missing -c sha512-manifest-checksums.txt
```
