## Elliptic cryptography

## The memory-safe reimplementation of the uECC library

* The unsafe code blocks are used to ensure deterministic memory allocation. Logic of the algorithms themselves is not dependent on them.

* Supported features:
    * Deterministic and random key generation
    * ECDH shared secret derivation
    * Deterministic and non-deterministic message signing
    * Signature verification
    * Private and public key tweak by scalar

* Supported curves:
    * secp521r1, secp384r1, secp256k1, secp256r1 and secp224r1.

* Features:
    * Based on the value and ref value types, all objects can be allocated on stack without any heap heap allocations.
    * In-memory copies of the secret values are scrambled by random value.
