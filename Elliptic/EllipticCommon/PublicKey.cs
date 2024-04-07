using System.Security.Cryptography;

namespace Wheel.Crypto.Elliptic.EllipticCommon;

public interface IPublicKey
{
    /// <summary>
    /// ECC implementation to use
    /// </summary>
    public IGenericCurve curve { get; }

    /// <summary>
    /// Does this instance contain a valid key or not
    /// </summary>
    public bool IsValid { get; }

    /// <summary>
    /// Encoded data size in bytes
    /// </summary>
    public int EncodedSize { get; }

    /// <summary>
    /// Encoded key size in bytes
    /// </summary>
    public int CompressedSize { get; }

    /// <summary>
    /// Erase object state
    /// </summary>
    public void Reset();

    /// <summary>
    /// Serialize the native key into big endian number
    /// </summary>
    /// <param name="public_point">Native point data</param>
    /// <returns>True if successful and this key is valid</returns>
    public bool Serialize(Span<byte> public_point);

    /// <summary>
    /// Try to init using the provided bytes
    /// </summary>
    /// <param name="public_key">Serialized point data</param>
    /// <returns>True if successful</returns>
    public bool Parse(ReadOnlySpan<byte> public_key);

    /// <summary>
    /// Public key tweak by scalar
    /// </summary>
    /// <param name="result">New public key to be filled</param>
    /// <param name="scalar">Scalar to be used for addition</param>
    /// <returns>True on success</returns>
    public bool KeyTweak(out IPublicKey result, ReadOnlySpan<byte> scalar);

    /// <summary>
    /// Verify an ECDSA signature.
    /// Usage: Compute the hash of the signed data using the same hash as the signer and
    /// pass it to this function along with the signer's public key and the signature values (r and s).
    /// </summary>
    /// <param name="signature">The compact signature object</param>
    /// <param name="message_hash">The hash of the signed data</param>
    /// <returns></returns>
    public bool VerifySignature(ISignature signature, ReadOnlySpan<byte> message_hash);
}
