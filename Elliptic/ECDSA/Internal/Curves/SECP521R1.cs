using Wheel.Crypto.Elliptic.EllipticCommon.VeryLongInt;

namespace Wheel.Crypto.Elliptic.ECDSA
{
    /// <summary>
    /// SECP384R1 specific constants and implementations
    /// </summary>
    public readonly partial struct ECCurve
    {
        /// <summary>
        /// Computes result = product % p
        /// </summary>
        public static void MMod_SECP521R1(in ECCurve curve, Span<ulong> result, Span<ulong> product)
        {
            int num_words = curve.NUM_WORDS;
            ReadOnlySpan<ulong> p = curve.P;
            Span<ulong> tmp = stackalloc ulong[num_words];

            // t
            VLI.Set(result, product, num_words);
            result[num_words - 1] &= 0x01FF;

            // s
            for (int i = 0; i < num_words - 1; ++i)
            {
                tmp[i] = (product[num_words - 1 + i] >> 9) | (product[num_words + i] << 55);
            }
            tmp[num_words - 1] = product[2 * num_words - 2] >> 9;

            int carry = (int)VLI.Add(result, result, tmp, num_words);

            while (Convert.ToBoolean(carry) || VLI.VarTimeCmp(p, result, num_words) != 1)
            {
                carry -= (int)VLI.Sub(result, result, p, num_words);
            }
        }
    }
}

