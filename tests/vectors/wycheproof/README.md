# Wycheproof test vectors (vendored)

Source: [C2SP/wycheproof](https://github.com/C2SP/wycheproof)
Commit: `6d9d6de30f02e229dfc160323722c3ddac866181`
License: Apache-2.0

## Files

- `ecdsa_secp256r1_sha256_p1363_test.json` — ECDSA P-256 / SHA-256, P1363 signature format (raw `r||s`, matches WebCrypto)
- `hkdf_sha256_test.json` — HKDF-SHA256, RFC 5869 coverage incl. edge cases

Used by `tests/test-wycheproof.js` to validate the PinChat `IdentityKeyManager.verify` and `DoubleRatchet.hkdf` wrappers.

To refresh: re-run the snippet in `CHANGELOG.md` for the relevant version and bump the commit hash above.
