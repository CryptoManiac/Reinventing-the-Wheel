## Elliptic cryptography

## The memory-safe reimplementation of the uECC library

* Supported features:
    * Deterministic and random key generation
    * ECDH shared secret derivation
    * Deterministic and non-deterministic message signing
    * Signature verification
    * Private and public key tweak by scalar

* Supported curves:
    * secp521r1, secp384r1, secp256k1, secp256r1, secp224r1, secp192r1 and secp160r1.

* Features:
    * Based on the value and ref value types, all objects can be allocated on stack without any heap heap allocations.
    * In-memory copies of the secret values are scrambled by random value.

## Implementation details on memory safety:

* Just like other implementations in this project, all of the defined structures (ECPrivateKey, ECPublicKey, etc.) have a fixed size to ensure the determinism of stack memory allocation.
* As the result, there are some unsafe code blocks that are being used to implement wrappers over these buffers. There is typically one readonly getter property per object. The said property contains wrapper code that is returning a memory span to the caller.
* Logic of the algorithms themselves is not dependent on these fixed buffers as it is interacting with them only through the memory-safe wrappers. To the algorithms, it's no different that working with bound-checked arrays and no overruns or whatever bad stuff are possible to happen.

## Security notice

The ```secp160r1``` is available solely for the compatibility purposes. Please note that, although there is no substantial evidence of this algorithm being broken, it is still considered too weak for the practical use. It's year 2024 after all.
