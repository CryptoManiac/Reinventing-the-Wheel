using System;

namespace Wheel.Crypto.Elliptic.EllipticCommon
{
	public interface IPublicKey
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
        /// Erase object state
        /// </summary>
        public void Reset();

        /// <summary>
        /// Dump the native point data
        /// </summary>
        /// <param name="native"></param>
        /// <returns>True if point is valid and copying has been successful</returns>
        public bool UnWrap(Span<ulong> native_out);

        /// <summary>
        /// Set native point data to given value
        /// </summary>
        /// <param name="native_in"></param>
        /// <returns>True if point is valid and copying has been successful</returns>
        public bool Wrap(ReadOnlySpan<ulong> native_in);

        /// <summary>
        /// Serialize the native key into big endian number
        /// </summary>
        /// <param name="public_point"></param>
        /// <returns>True if successful and this key is valid</returns>
        public bool Serialize(Span<byte> public_point);

        /// <summary>
        /// Try to init using the provided bytes
        /// </summary>
        /// <param name="public_key">Serialized point data</param>
        /// <returns>True if successful</returns>
        public bool Parse(ReadOnlySpan<byte> public_key);

        /// <summary>
        /// Parse compressed public key
        /// </summary>
        /// <param name="compressed">Compressed point data</param>
        /// <returns>True if successful</returns>
        public bool Decompress(ReadOnlySpan<byte> compressed);

        /// <summary>
        /// Serialize the native key into a compressed point
        /// </summary>
        /// <param name="compressed"></param>
        /// <returns>True if successful and this key is valid</returns>
        public bool Compress(Span<byte> compressed);

        /// <summary>
        /// EC public key tweak by scalar
        /// </summary>
        /// <param name="result"></param>
        /// <param name="scalar"></param>
        /// <returns></returns>
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
}

