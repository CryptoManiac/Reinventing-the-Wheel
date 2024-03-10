# Reinventing the wheel

## Disclaimer

Don't take this seriously. Just fooling around with the Visual Studio for Mac to see how usable it is.

## Contents

The well tested implementations of the following hash functions are provided as a bonus:

* RIPEMD-160
* SHA-256, SHA-224
* SHA-512, SHA-384, SHA-512/256, SHA-512-224

## Recent ports

* SHA3-512, SHA3-384, SHA3-256
* Keccak-512, Keccak-384, Keccak-256

## API

All classes are implementing the well known Init - Update - Finalize paradighm. The implementations are derived from `IHasher` interface which is declaring the following method signatures:

```csharp
/// Reset the hasher's internal state
public void Reset()

/// Write bytes to hasher state
public void Update(byte[] input)

/// Return hash as a new byte array
//  Note: This implies the Reset() operation
public byte[] Digest()

/// Write hash into provided span or array
//  Note: This implies the Reset() operation
public void Digest(Span<byte> hash)
```
