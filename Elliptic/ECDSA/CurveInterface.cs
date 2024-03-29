using Wheel.Crypto.Elliptic.ECDSA;
using Wheel.Hashing.HMAC;

namespace Wheel.Crypto.Elliptic.ECDSA
{
	public interface IECDSACurve
	{
        /// <summary>
        /// Construct empty public key
        /// </summary>
        public ECPublicKey MakePublicKey();
        /// <summary>
        /// Construct empty private key
        /// </summary>
        public ECPrivateKey MakePrivateKey();
        /// <summary>
        /// Unserialize public key
        /// </summary>
        public ECPublicKey MakePublicKey(ReadOnlySpan<byte> data);
        /// <summary>
        /// Unserialize private key
        /// </summary>
        public ECPrivateKey MakePrivateKey(ReadOnlySpan<byte> data);
        /// <summary>
        /// Construct empty signature
        /// </summary>
        public DERSignature MakeDERSignature();
        /// <summary>
        /// Construct empty signature
        /// </summary>
        public CompactSignature MakeCompactSignature();
        /// <summary>
        /// Unserialize signature
        /// </summary>
        public DERSignature MakeDERSignature(ReadOnlySpan<byte> data);
        /// <summary>
        /// Unserialize signature
        /// </summary>
        public CompactSignature MakeCompactSignature(ReadOnlySpan<byte> data);

        /// <summary>
        /// Deterministic derivation of a new private key
        /// </summary>
        /// <typeparam name="HMAC_IMPL"></typeparam>
        /// <param name="curve">ECC implementation to use</param>
        /// <param name="result">Resulting key to be filled</param>
        /// <param name="seed">Secret seed</param>
        /// <param name="personalization">Personalization (to generate the different keys for the same seed)</param>
        /// <param name="sequence">Key sequence (to generate the different keys for the same seed and personalization bytes array pair)</param>
        public void GenerateSecret<HMAC_IMPL>(out ECPrivateKey result, ReadOnlySpan<byte> seed, ReadOnlySpan<byte> personalization, int sequence) where HMAC_IMPL : unmanaged, IMac;
    }
}

