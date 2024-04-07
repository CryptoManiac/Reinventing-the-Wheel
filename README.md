# Reinventing the wheel

## Disclaimer

Provided without any warranty.

## Contents

### Hashing functions

The well tested implementations of the following hash functions are provided as a bonus:

* RIPEMD-160
* SHA-256, SHA-224
* SHA-512, SHA-384, SHA-512/256, SHA-512-224
* SHA3-512, SHA3-384, SHA3-256
* Keccak-512, Keccak-384, Keccak-256

### HMAC

* HMAC-SHA-224, HMAC-SHA-256
* HMAC-SHA-512_224, HMAC-SHA-512_256, HMAC-SHA-384, HMAC-SHA-512

### Key derivation

* The generic implementation of PBKDF2 which is able to work on top of all HMAC hashers

### Elliptic cryptography

* The reimplementation of uECC
    * Supports secp521r1, secp384r1, secp256k1, secp256r1, secp224r1, secp192r1 and secp160r1 curves
    * Deterministic and random key generation
    * Deterministic and non-deterministic message signing
    * Signature verification
    * ECDH shared secret derivation
    * Private and public key tweak by scalar

* Memory-safe Ed25519 implementation
    * Deterministic and random key generation
    * Deterministic and non-deterministic message signing
    * Signature verification
    * ECDH shared secret derivation
    * Private and public key tweak by scalar

### Symmetric cryptography

* AES256-CTR with PKCS7 padding

### MISC

* ShamirUtil for secret sharing with optional master password

## API

All hashers are implementing the well known Init - Update - Finalize paradighm. 

### Hashing

The hash function implementations are derived from the `IHasher` interface which is declaring the following method signatures:

```csharp
/// Reset the hasher's internal state
public void Reset()

/// Write bytes to hasher state
public void Update(ReadOnlySpan<byte> input)

/// Write hash into provided span or array
//  Note: This implies the Reset() operation
public void Digest(Span<byte> hash)

/// This property returns size of the 
// result buffer for the Digest() call
public int HashSz;
```

### HMAC

The HMAC implementation is a generic which is derived from `IMac` interface.

The IMac is defining these signatures:

```csharp
/// Initialize or re-initialize hasher with a given key
///  Note: It will overwrite any existing state
public void Init(ReadOnlySpan<byte> key);

/// Write bytes to hasher state
public void Update(ReadOnlySpan<byte> input);

/// Reset the hasher to the post-initialized state
public void Reset();

/// Write hash into provided span or array
///  Note: This implies the Reset() operation
public void Digest(Span<byte> hash);

/// Reset hasher to non-initialized state
///  All internal structures will be either zeroed or set to their standard defined initial values
public void Dispose();

/// This property returns size of the buffer
// which you need to provide for the Digest() call
public int HashSz;
```

To initialize new HMAC hasher you need to provide an implementation of the underlying hash function as a generic agrument. Doing something like this will suffice:

```csharp
HMAC<SHA512> ctx = new();
```

You can replace the SHA512 with a hasher of your choice among those that are provided by the ```Hashing``` library, i.e. make it look like ```HMAC<SHA384>```, ```HMAC<SHA256>```, ```HMAC<SHA512_224>``` or whatever. Please note that, while theoretically any of the implemented hasher should work, so far only SHA2 functions have been throughly tested with HMAC.

## Notable features

All hashers are implemented as structures of the deterministic size, which is designed to be known at the compile time. This allows you to allocate them on stack. This can be done either directly, using `stackalloc` operator, or indirectly by letting the compiler to decide. Stack allocated structures are avoiding the garbage collecting overhead since their living cycle is limited by that of the function's stack memory. The fact that they're not placed in the CLR heap is a good thing as well, especially for security.

