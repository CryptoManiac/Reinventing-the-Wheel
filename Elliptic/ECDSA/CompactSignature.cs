using Wheel.Crypto.Elliptic.EllipticCommon;
using Wheel.Crypto.Elliptic.ECDSA.Internal;

namespace Wheel.Crypto.Elliptic.ECDSA
{
    /// <summary>
    /// ECDSA Compact signature value pair
    /// </summary>
    public struct CompactSignature : IECDSASignature
    {
        /// <summary>
        /// ECC implementation to use
        /// </summary>
        private readonly ECCurve _curve { get; }

        /// <summary>
        /// Public property for unification purposes
        /// </summary>
        public readonly ICurve curve => _curve;

        /// <summary>
        /// R part of the signature
        /// </summary>
        public readonly unsafe Span<ulong> r
        {
            get
            {
                fixed (ulong* ptr = &signature_data[0])
                {
                    return new Span<ulong>(ptr, _curve.NUM_WORDS);
                }
            }
        }

        /// <summary>
        /// S part of the signature
        /// </summary>
        public readonly unsafe Span<ulong> s
        {
            get
            {
                fixed (ulong* ptr = &signature_data[curve.NUM_WORDS])
                {
                    return new Span<ulong>(ptr, _curve.NUM_WORDS);
                }
            }
        }

        /// <summary>
        /// Encoded data size in bytes
        /// </summary>
        public readonly int EncodedSize => GetEncodedSize(_curve);

        /// <summary>
        /// The r and s are sliced from this hidden array.
        /// </summary>
        private unsafe fixed ulong signature_data[2 * VLI.ECC_MAX_WORDS];

        public CompactSignature()
        {
            throw new SystemException("The default constructor should never be called");
        }

        /// <summary>
        /// Construct the empty signature for given curve
        /// </summary>
        /// <param name="curve">ECC implementation</param>
        public CompactSignature(ECCurve curve)
        {
            _curve = curve;
            // Sanity check constraint
            if (curve.NUM_WORDS > VLI.ECC_MAX_WORDS)
            {
                throw new SystemException("The configured curve point coordinate size is unexpectedly big");
            }
        }

        /// <summary>
        /// Create instance and parse provided data
        /// </summary>
        /// <param name="curve">ECC implementation</param>
        public CompactSignature(ECCurve curve, ReadOnlySpan<byte> bytes) : this(curve)
        {
            if (!Parse(bytes))
            {
                throw new InvalidDataException("Invalid signature format");
            }
        }

        /// <summary>
        /// Write signature data in compact format
        /// </summary>
        /// <param name="encoded"></param>
        /// <returns>Number of bytes written/to write</returns>
        public readonly int Encode(Span<byte> encoded)
        {
            byte lenR = (byte)_curve.NUM_BYTES;
            byte lenS = (byte)_curve.NUM_BYTES;

            int reqSz = lenS + lenR;
            if (encoded.Length >= reqSz)
            {
                VLI.NativeToBytes(encoded[..lenR], lenR, r);
                VLI.NativeToBytes(encoded.Slice(lenR, lenS), lenS, s);
            }
            return reqSz;
        }

        /// <summary>
        /// Parse input and construct signature from its contents
        /// </summary>
        /// <param name="encoded"></param>
        /// <returns>True on success</returns>
        public bool Parse(ReadOnlySpan<byte> encoded)
        {
            byte lenR = (byte)_curve.NUM_BYTES;
            byte lenS = (byte)_curve.NUM_BYTES;

            int reqLen = lenS + lenR;

            if (encoded.Length != reqLen)
            {
                // Must be long enough to contain two encoded integer values
                return false;
            }

            // Decode R and S values
            VLI.BytesToNative(r, encoded[..lenR], lenR);
            VLI.BytesToNative(s, encoded.Slice(lenR, lenS), lenS);

            return true;
        }

        /// <summary>
        /// Size of encoded signature for a given curve
        /// </summary>
        /// <param name="curve"></param>
        /// <returns></returns>
        public static int GetEncodedSize(ICurve curve)
        {
            return 2 * curve.NUM_BYTES;
        }
    }
}

