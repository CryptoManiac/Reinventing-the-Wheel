using Wheel.Hashing;
using Wheel.Hashing.HMAC;
namespace Wheel.Crypto.Elliptic.EllipticCommon;

public interface IPrivateKey
{
    /// <summary>
    /// ECC implementation to use
    /// </summary>
    public ICurve curve { get; }

    /// <summary>
    /// Does this instance contain a valid key or not
    /// </summary>
    public bool IsValid { get; }

    /// <summary>
    /// Encoded data size in bytes
    /// </summary>
    public int EncodedSize { get; }

    /// <summary>
    /// Erase object state
    /// </summary>
    public void Reset();

    /// <summary>
    /// Serialize the native key into big endian number
    /// </summary>
    /// <param name="secret_scalar"></param>
    /// <returns>True if successful and this key is valid</returns>
    public bool Serialize(Span<byte> secret_scalar);

    /// <summary>
    /// Try to init using the provided bytes
    /// </summary>
    /// <param name="private_key">Serialized scalar data</param>
    /// <returns>True if successful</returns>
    public bool Parse(ReadOnlySpan<byte> private_key);

    /// <summary>
    /// Compute the corresponding public key for a private key.
    /// </summary>
    /// <param name="public_key">Will be filled in with the corresponding public key</param>
    /// <returns>True if the key was computed successfully, False if an error occurred.</returns>
    public bool ComputePublicKey(out IPublicKey public_key);

    /// <summary>
    /// Private key tweak by scalar
    /// </summary>
    /// <param name="result">New private key to be filled</param>
    /// <param name="scalar">Scalar to be used for addition</param>
    /// <returns>True on success</returns>
    public bool KeyTweak(out IPrivateKey result, ReadOnlySpan<byte> scalar);

    /// <summary>
    /// Generate a signature for a given hash value, using a deterministic algorithm
    /// 
    /// Usage: Compute a hash of the data you wish to sign and pass it to this function.
    /// </summary>
    /// <typeparam name="HMAC_IMPL">HMAC implementation to use</typeparam>
    /// <param name="signature">Will be filled in with the signature value. Curve settings will be overwritten.</param>
    /// <param name="message_hash">The hash of the message to sign</param>
    /// <returns></returns>
    public bool SignDeterministic<HMAC_IMPL>(out ISignature signature, ReadOnlySpan<byte> message_hash) where HMAC_IMPL : unmanaged, IMac;

    /// <summary>
    /// Generate a signature for a given hash value, using a non-deterministic algorithm
    /// 
    /// Usage: Compute a hash of the data you wish to sign and pass it to this function.
    /// </summary>
    /// <param name="signature">Will be filled in with the signature value. Curve settings will be overwritten.</param>
    /// <param name="message_hash">The hash of the message to sign</param>
    /// <returns></returns>
    public bool Sign(out ISignature signature, ReadOnlySpan<byte> message_hash);

    /// <summary>
    /// Compute a shared secret given your secret key and someone else's public key.
    ///
    /// Note: It is recommended that you hash the result of Derive() before using it for
    /// symmetric encryption or HMAC.
    /// </summary>
    /// <param name="public_key">The public key of the remote party.</param>
    /// <param name="shared">Will be filled in with the encapsulated shared secret.</param>
    /// <returns>True if the shared secret was generated successfully, False if an error occurred.</returns>
    public bool ECDH(in IPublicKey public_key, out IPrivateKey shared);

    /// <summary>
    /// Encode the secret into big endian format and calculate
    ///  its hash using the provided IHasher implementation.
    /// May be used to hash the ECDH derived shared keys.
    /// </summary>
    /// <typeparam name="HASHER_IMPL">Hasher to use</typeparam>
    /// <param name="secret_hash"></param>
    /// <returns>True if successful</returns>
    public bool CalculateKeyHash<HASHER_IMPL>(Span<byte> secret_hash) where HASHER_IMPL : unmanaged, IHasher;
}
