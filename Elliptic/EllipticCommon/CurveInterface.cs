using Wheel.Hashing.HMAC;
namespace Wheel.Crypto.Elliptic.EllipticCommon;

/// <summary>
/// Some abstract ellipric curve interface
/// </summary>
public interface ICurve
{
    /// <summary>
    /// Random instance identifier
    /// </summary>
    public ulong randomId { get; }

    #region Curve's point coordinate size
    public int NUM_N_BITS { get; }

    #region Calculated lengths
    public int NUM_WORDS { get; }
    public int NUM_BYTES { get; }
    #endregion
    #endregion

    /// <summary>
    /// Size of encoded private key in bytes
    /// </summary>
    public int PrivateKeySize { get; }

    /// <summary>
    /// Size of uncompressed public key in bytes
    /// </summary>
    public int UncompressedPublicKeySize { get; }

    /// <summary>
    /// Size of compressed public key in bytes
    /// </summary>
    public int CompressedPublicKeySize { get; }

    /// <summary>
    /// Maximum size of DER signature in bytes
    /// </summary>
    public int DERSignatureSize { get; }

    /// <summary>
    /// Size of compact signature in bytes
    /// </summary>
    public int CompactSignatureSize { get; }

    /// <summary>
    /// Check whether the provided byte array contains a valid public key
    /// </summary>
    /// <param name="data">Public key bytes</param>
    /// <returns>True if valid</returns>
    public bool IsValidPublicKey(ReadOnlySpan<byte> data);

    /// <summary>
    /// Check whether the provided byte array contains a valid private key
    /// </summary>
    /// <param name="data">Private key bytes</param>
    /// <returns>True if valid</returns>
    public bool IsValidPrivateKey(ReadOnlySpan<byte> data);

    /// <summary>
    /// Generation of a random secret bytes on top of the .NET RandomNumberGenerator API. The security of this key will depend
    /// on the quality of the local RNG implementation and the quality of the entropy array being used as well. I suggest that
    /// you should treat these keys as unsecure by default, use this API with caution and never use the generated keys directly,
    /// without hashing. It will be a good idea to use the DeriveHMAC method to derive the children keys from them.
    /// </summary>
    /// <param name="result">Private key bytes to be filled</param>
    /// <param name="entropy">Additional entropy</param>
    /// <returns>True on success</returns>
    public void GenerateRandomSecret(Span<byte> result, ReadOnlySpan<byte> entropy);

    /// <summary>
    /// Deterministically generate the new secret bytes from the seed, using HMAC-based generator
    /// </summary>
    /// <typeparam name="HMAC_IMPL">HMAC implementation to use</typeparam>
    /// <param name="result">Private key to be filled</param>
    /// <param name="seed">Secret seed to generate from</param>
    /// <param name="personalization">Personalization argument bytes (to generate more than one key from the same seed)</param>
    /// <param name="sequence">Generation sequence number (to generate more than one key from the same seed + personalization pair)</param>
    public void GenerateDeterministicSecret<HMAC_IMPL>(Span<byte> result, ReadOnlySpan<byte> seed, ReadOnlySpan<byte> personalization, int sequence) where HMAC_IMPL : unmanaged, IMac;
}
