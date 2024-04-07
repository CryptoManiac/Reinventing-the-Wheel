
# Elliptic curve cryptography

## The memory-safe implementation of Ed25519/Curve25519. Based on the work of the ed25519-donna project.

* Supported features:
    * Deterministic and random key generation
    * EdDH shared secret derivation
    * Deterministic and non-deterministic message signing
    * Signature verification
    * Private and public key tweak by scalar

* Features:
    * Based on the value and ref value types, all objects can be allocated on stack without any heap heap allocations.
    * In-memory copies of the secret values are scrambled by random value.

## Implementation details on memory safety:

See ECDSA project for details.

## Security notice

Please note that current EdDH implementation is not guaranteed to be a constant-time operation.
