using Wheel.Hashing.HMAC;
namespace Wheel.Crypto.Elliptic.EllipticCommon
{
	public interface ICurve
	{
        /// <summary>
        /// Random instance identifier
        /// </summary>
        public ulong randomId { get; }

        #region Curve's point coordinate size
        public int NUM_BITS { get; }
        public int NUM_N_BITS { get; }

        #region Calculated lengths
        public int NUM_WORDS { get; }
        public int NUM_N_WORDS { get; }
        public int NUM_BYTES { get; }
        public int NUM_N_BYTES { get; }
        #endregion
        #endregion

        public IPublicKey MakePublicKey();
        public IPrivateKey MakePrivateKey();
        public DERSignature MakeDERSignature();
        public CompactSignature MakeCompactSignature();

        public IPublicKey MakePublicKey(ReadOnlySpan<byte> data);
        public IPrivateKey MakePrivateKey(ReadOnlySpan<byte> data);
        public DERSignature MakeDERSignature(ReadOnlySpan<byte> data);
        public DERSignature MakeDERSignature(ReadOnlySpan<byte> data, bool nonCanonical);
        public CompactSignature MakeCompactSignature(ReadOnlySpan<byte> data);

        public bool IsValidPublicKey(ReadOnlySpan<byte> data);
        public bool IsValidPrivateKey(ReadOnlySpan<byte> data);

        public void GenerateSecret<HMAC_IMPL>(out IPrivateKey result, ReadOnlySpan<byte> seed, ReadOnlySpan<byte> personalization, int sequence) where HMAC_IMPL : unmanaged, IMac;
    }
}

