using Wheel.Crypto.Elliptic.EllipticCommon;
using Wheel.Crypto.Elliptic.EllipticCommon.VeryLongInt;

namespace Wheel.Crypto.Elliptic.EllipticCommon
{
    /// <summary>
    /// DER encapsulated signature value pair
    /// </summary>
    public struct DERSignature : ISignature
    {
        /// <summary>
        /// ECC implementation to use
        /// </summary>
        public ICurve curve { get; private set; }

        /// <summary>
        /// R part of the signature
        /// </summary>
        public readonly unsafe Span<ulong> r
        {
            get
            {
                fixed (ulong* ptr = &signature_data[0])
                {
                    return new Span<ulong>(ptr, curve.NUM_WORDS);
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
                    return new Span<ulong>(ptr, curve.NUM_WORDS);
                }
            }
        }

        /// <summary>
        /// Encoded data size in bytes
        /// </summary>
        public readonly int EncodedSize => GetEncodedSize(curve);

        /// <summary>
        /// The r and s are sliced from this hidden array.
        /// </summary>
        private unsafe fixed ulong signature_data[2 * VLI.ECC_MAX_WORDS];

        public DERSignature()
        {
            throw new SystemException("The default constructor should never be called");
        }

        /// <summary>
        /// Construct the empty signature for given curve
        /// </summary>
        /// <param name="curve">ECC implementation</param>
        public DERSignature(ICurve curve)
        {
            // Sanity check constraint
            if (curve.NUM_WORDS > VLI.ECC_MAX_WORDS)
            {
                throw new SystemException("The configured curve point coordinate size is unexpectedly big");
            }

            this.curve = curve;
            r.Clear();
            s.Clear();
        }

        /// <summary>
        /// Create instance and parse provided data
        /// </summary>
        /// <param name="curve">ECC implementation</param>
        public DERSignature(ICurve curve, ReadOnlySpan<byte> bytes, bool nonCanonical=false) : this(curve)
        {
            if (!Parse(bytes, nonCanonical))
            {
                throw new InvalidDataException("Provided DER signature is not valid");
            }
        }

        public readonly int Encode(Span<byte> encoded)
        {
            int offset = 0;
            int reqSz = GetEncodedSize(curve);

            if (encoded.Length >= reqSz)
            {
                // Fill the DER encoded signature skeleton:

                // Sequence tag
                encoded[0] = 0x30;

                byte lenR = (byte)curve.NUM_BYTES;
                byte lenS = (byte)curve.NUM_BYTES;
                int seqSz = 4 + lenR + lenS;

                if (seqSz > 127)
                {
                    // Special case for two byte value
                    encoded[1] = 1 | 0x80;
                    offset = 1;
                }

                // Total data length
                encoded[1 + offset] = (byte)(seqSz & 0xff);
                // Integer tag for R
                encoded[2 + offset] = 0x02;
                // R length prefix
                encoded[3 + offset] = lenR;
                // Integer tag for S
                encoded[4 + offset + lenR] = 0x02;
                // S length prefix
                encoded[5 + offset + lenR] = lenS;

                // Encode the R and S values
                VLI.NativeToBytes(encoded.Slice(4 + offset, lenR), lenR, r);
                VLI.NativeToBytes(encoded.Slice(6 + offset + lenR, lenS), lenS, s);
            }

            return reqSz;
        }

        /// <summary>
        /// Parse DER formatted input and construct signature from its contents
        /// Note: based on parse_der_lax routine from the bitcoin distribution
        /// </summary>
        /// <param name="encoded"></param>
        /// <returns>True on success</returns>
        public bool Parse(ReadOnlySpan<byte> encoded)
        {
            return Parse(encoded);
        }

        /// <summary>
        /// Size of encoded signature for a given curve
        /// </summary>
        /// <param name="curve"></param>
        /// <returns></returns>
        public static int GetEncodedSize(ICurve curve)
        {
            int seqSz = 4 + 2 * curve.NUM_BYTES;
            int reqSz = seqSz + 2;
            if (seqSz > 127) ++reqSz;
            return reqSz;
        }

        /// <summary>
        /// Parse DER formatted input and construct signature from its contents
        /// Note: based on parse_der_lax routine from the bitcoin distribution
        /// </summary>
        /// <param name="encoded"></param>
        /// <param name="lax">Don't fail on negative r or s, negate them if possible</param>
        /// <returns>True on success</returns>
        public bool Parse(ReadOnlySpan<byte> encoded, bool lax = false)
        {
            int rpos, rlen, spos, slen;
            int pos = 0;
            int lenbyte;
            int len;

            int inputlen = encoded.Length;
            int num_bytes = curve.NUM_BYTES;

            // Sequence tag byte
            if (pos == inputlen || encoded[pos] != 0x30)
            {
                return false;
            }
            pos++;

            // Sequence length bytes
            if (pos == inputlen)
            {
                return false;
            }
            len = lenbyte = encoded[pos++];

            if ((lenbyte & 0x80) != 0)
            {
                lenbyte -= 0x80;
                if (lenbyte > inputlen - pos)
                {
                    return false;
                }
                // Save length for
                //  the format check
                len = encoded[pos];
                pos += lenbyte;
            }

            // Integer tag byte for R
            if (pos == inputlen || encoded[pos] != 0x02)
            {
                return false;
            }
            pos++;

            // Integer length for R
            if (pos == inputlen)
            {
                return false;
            }
            lenbyte = encoded[pos++];
            if (Convert.ToBoolean(lenbyte & 0x80))
            {
                lenbyte -= 0x80;
                if (lenbyte > inputlen - pos)
                {
                    return false;
                }
                while (lenbyte > 0 && encoded[pos] == 0)
                {
                    pos++;
                    lenbyte--;
                }
                if (lenbyte >= 4)
                {
                    return false;
                }
                rlen = 0;
                while (lenbyte > 0)
                {
                    rlen = (rlen << 8) + encoded[pos];
                    pos++;
                    lenbyte--;
                }
            }
            else
            {
                rlen = lenbyte;
            }
            if (rlen > inputlen - pos)
            {
                return false;
            }
            rpos = pos;
            pos += rlen;

            // Integer tag byte for S
            if (pos == inputlen || encoded[pos] != 0x02)
            {
                return false;
            }
            pos++;

            // Integer length for S
            if (pos == inputlen)
            {
                return false;
            }
            lenbyte = encoded[pos++];
            if (Convert.ToBoolean(lenbyte & 0x80))
            {
                lenbyte -= 0x80;
                if (lenbyte > inputlen - pos)
                {
                    return false;
                }
                while (lenbyte > 0 && encoded[pos] == 0)
                {
                    pos++;
                    lenbyte--;
                }
                if (lenbyte >= 4)
                {
                    return false;
                }
                slen = 0;
                while (lenbyte > 0)
                {
                    slen = (slen << 8) + encoded[pos];
                    pos++;
                    lenbyte--;
                }
            }
            else
            {
                slen = lenbyte;
            }
            if (slen > inputlen - pos)
            {
                return false;
            }
            spos = pos;

            // Handle invalid sequence length encoding
            if (!lax && len != (4 + slen + rlen) )
            {
                return false;
            }

            // Negate non-canonical r
            if (lax && encoded[rpos] == 0x00)
            {
                rpos++;
                rlen--;
            }

            // Negate non-canonical s
            if (lax && encoded[spos] == 0x00)
            {
                spos++;
                slen--;
            }

            if (rlen > num_bytes || slen > num_bytes)
            {
                // Overflow
                return false;
            }

            // Decode R and S values
            VLI.BytesToNative(r, encoded.Slice(rpos, rlen), rlen);
            VLI.BytesToNative(s, encoded.Slice(spos, slen), slen);

            return true;
        }
    }
}

