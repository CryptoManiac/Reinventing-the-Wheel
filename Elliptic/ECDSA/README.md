## Elliptic cryptography

## The memory-safe reimplementation of the uECC library

* Supported features:
    * Deterministic key generation
    * ECDH
    * Message signing
    * Signature verification
    * Private and public key tweak by scalar

* Limitations:
    * Only secp256k1 curve is supported.

* Features:
    * Based on the value and ref value types, all objects can be allocated on stack without any heap heap allocations.
    * In-memory copies of the secret values are scrambled by random value.
