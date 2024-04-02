using Wheel.Hashing.HMAC;
namespace Wheel.Crypto.Elliptic.EllipticCommon
{
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
        /// Make an empty (invalid) public key for this curve
        /// </summary>
        /// <returns>A zero-initialized public key</returns>
        public IPublicKey MakePublicKey();

        /// <summary>
        /// Make an empty (invalid) private key for this curve
        /// </summary>
        /// <returns>A zero-initialized private key</returns>
        public IPrivateKey MakePrivateKey();

        /// <summary>
        /// Make an empty (invalid) DER signature for this curve
        /// </summary>
        /// <returns>A zero-initialized DER signature</returns>
        public DERSignature MakeDERSignature();

        /// <summary>
        /// Make an empty (invalid) compact signature for this curve
        /// </summary>
        /// <returns>A zero-initialized compact signature</returns>
        public CompactSignature MakeCompactSignature();

        /// <summary>
        /// Parse public key bytes and construct new instance from them
        /// </summary>
        /// <param name="data">Public key bytes</param>
        /// <returns>A new copy of public key structure</returns>
        public IPublicKey MakePublicKey(ReadOnlySpan<byte> data);

        /// <summary>
        /// Parse private key bytes and construct new instance from them
        /// </summary>
        /// <param name="data">Private key bytes</param>
        /// <returns>A new copy of private key structure</returns>
        public IPrivateKey MakePrivateKey(ReadOnlySpan<byte> data);

        /// <summary>
        /// Parse DER signature bytes and construct new instance from them
        /// </summary>
        /// <param name="data">DER signature bytes</param>
        /// <returns>A new copy of DER signature structure</returns>
        public DERSignature MakeDERSignature(ReadOnlySpan<byte> data);

        /// <summary>
        /// Parse compact signature bytes and construct new instance from them
        /// </summary>
        /// <param name="data">Compact signature bytes</param>
        /// <returns>A new copy of compact signature structure</returns>
        public CompactSignature MakeCompactSignature(ReadOnlySpan<byte> data);

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
        /// Generation of a random secret key on top of the .NET RandomNumberGenerator API. The security of this key will depend
        /// on the quality of the local RNG implementation and the quality of the entropy array being used as well. I suggest that
        /// you should treat these keys as unsecure by default, use this API with caution and never use the generated keys directly,
        /// without hashing. It will be a good idea to use the DeriveHMAC method to derive the children keys from them.
        /// </summary>
        /// <param name="result">Private key to be filled</param>
        /// <param name="entropy">Additional entropy</param>
        /// <returns>True on success</returns>
        public void GenerateRandomSecret(out IPrivateKey result, ReadOnlySpan<byte> entropy);

        /// <summary>
        /// Deterministically generate the new private key from seed, using HMAC-based generator
        /// </summary>
        /// <typeparam name="HMAC_IMPL">HMAC implementation to use</typeparam>
        /// <param name="result">Private key to be filled</param>
        /// <param name="seed">Secret seed to generate from</param>
        /// <param name="personalization">Personalization argument bytes (to generate more than one key from the same seed)</param>
        /// <param name="sequence">Generation sequence number (to generate more than one key from the same seed + personalization pair)</param>
        public void GenerateDeterministicSecret<HMAC_IMPL>(out IPrivateKey result, ReadOnlySpan<byte> seed, ReadOnlySpan<byte> personalization, int sequence) where HMAC_IMPL : unmanaged, IMac;
    }
}

