using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using Wheel.Crypto.Elliptic.Internal.VeryLongInt;

namespace Wheel.Crypto.Elliptic
{
    /// <summary>
    /// DER encapsulated signature value pair
    /// </summary>
    public ref struct DERSignature
    {
        /// <summary>
        /// ECC implementation to use
        /// </summary>
        public ECCurve curve { get; }

        /// <summary>
        /// R part of the signature
        /// </summary>
        public Span<ulong> r { get; }

        /// <summary>
        /// S part of the signature
        /// </summary>
        public Span<ulong> s { get; }

        /// <summary>
        /// The r and s are sliced from this hidden array.
        /// </summary>
        private unsafe fixed ulong signature_data[2 * VLI_Common.ECC_MAX_WORDS];

        /// <summary>
        /// Construct the empty signature
        /// </summary>
        /// <param name="curve">ECC implementation</param>
        public unsafe DERSignature(ECCurve curve)
        {
            this.curve = curve;

            // Sanity check constraint
            if (curve.NUM_WORDS > VLI_Common.ECC_MAX_WORDS)
            {
                throw new SystemException("The configured curve point coordinate size is unexpectedly big");
            }

            fixed(ulong* ptr = &signature_data[0])
            {
                r = new Span<ulong>(ptr, curve.NUM_WORDS);
                s = new Span<ulong>(ptr + curve.NUM_WORDS, curve.NUM_WORDS);
            }
        }

        /// <summary>
        /// Write signature data in DER format
        /// </summary>
        /// <param name="encoded"></param>
        /// <returns>Number of bytes written/to write</returns>
        public int Encode(Span<byte> der)
        {
            byte lenR = (byte)curve.NUM_BYTES;
            byte lenS = (byte)curve.NUM_BYTES;

            int reqSz = 6 + lenS + lenR;
            if (der.Length >= reqSz)
            {
                // Fill the DER encoded signature skeleton:

                // Sequence tag
                der[0] = 0x30;
                // Total data length
                der[1] = (byte)(4 + lenS + lenR);
                // Integer tag for R
                der[2] = 0x02;
                // R length prefix
                der[3] = lenR;
                // Integer tag for S
                der[4 + lenR] = 0x02;
                // S length prefix
                der[5 + lenR] = lenS;

                // Encode the R and S values
                VLI_Conversion.NativeToBytes(der.Slice(4, lenR), lenR, r);
                VLI_Conversion.NativeToBytes(der.Slice(6 + lenR, lenS), lenS, s);
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
            int rpos, rlen, spos, slen;
            int pos = 0;
            int lenbyte;

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
            lenbyte = encoded[pos++];
            if ((lenbyte & 0x80) != 0)
            {
                lenbyte -= 0x80;
                if (lenbyte > inputlen - pos)
                {
                    return false;
                }
                pos += lenbyte;
            }

            // Integer tag byte for R
            if (pos == inputlen || encoded[pos] != 0x02)
            {
                return false;
            }
            pos++;

            /* Integer length for R */
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

            if (rlen > num_bytes || slen > num_bytes)
            {
                // Overflow
                return false;
            }

            // Decode R and S values
            VLI_Conversion.BytesToNative(r, encoded.Slice(rpos, rlen), rlen);
            VLI_Conversion.BytesToNative(s, encoded.Slice(spos, slen), slen);

            return true;
        }
    }

    /// <summary>
    /// Compact signature value pair
    /// </summary>
    public ref struct CompactSignature
    {
        /// <summary>
        /// ECC implementation to use
        /// </summary>
        public ECCurve curve { get; }

        /// <summary>
        /// R part of the signature
        /// </summary>
        public Span<ulong> r { get; }

        /// <summary>
        /// S part of the signature
        /// </summary>
        public Span<ulong> s { get; }

        /// <summary>
        /// The r and s are sliced from this hidden array.
        /// </summary>
        private unsafe fixed ulong signature_data[2 * VLI_Common.ECC_MAX_WORDS];

        /// <summary>
        /// Construct the empty signature
        /// </summary>
        /// <param name="curve">ECC implementation</param>
        public unsafe CompactSignature(ECCurve curve)
        {
            this.curve = curve;
            // Sanity check constraint
            if (curve.NUM_WORDS > VLI_Common.ECC_MAX_WORDS)
            {
                throw new SystemException("The configured curve point coordinate size is unexpectedly big");
            }

            fixed (ulong* ptr = &signature_data[0])
            {
                r = new Span<ulong>(ptr, curve.NUM_WORDS);
                s = new Span<ulong>(ptr + curve.NUM_WORDS, curve.NUM_WORDS);
            }
        }

        /// <summary>
        /// Write signature data in compact format
        /// </summary>
        /// <param name="encoded"></param>
        /// <returns>Number of bytes written/to write</returns>
        public int Encode(Span<byte> der)
        {
            byte lenR = (byte)curve.NUM_BYTES;
            byte lenS = (byte)curve.NUM_BYTES;

            int reqSz = lenS + lenR;
            if (der.Length >= reqSz)
            {
                VLI_Conversion.NativeToBytes(der.Slice(0, lenR), lenR, r);
                VLI_Conversion.NativeToBytes(der.Slice(lenR, lenS), lenS, s);
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
            byte lenR = (byte)curve.NUM_BYTES;
            byte lenS = (byte)curve.NUM_BYTES;

            int reqLen = lenS + lenR;

            if (encoded.Length != reqLen)
            {
                // Must be long enough to contain two encoded integer values
                return false;
            }

            // Decode R and S values
            VLI_Conversion.BytesToNative(r, encoded.Slice(0, lenR), lenR);
            VLI_Conversion.BytesToNative(s, encoded.Slice(lenR, lenS), lenS);

            return true;
        }
    }
}
