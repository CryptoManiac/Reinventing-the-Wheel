using Wheel.Crypto.Elliptic.EllipticCommon.VeryLongInt;

namespace Wheel.Crypto.Elliptic.ECDSA
{
    /// <summary>
    /// SECP192R1 specific implementations
    /// </summary>
    public readonly partial struct ECCurve
    {
        /// <summary>
        /// Computes result = product % p
        /// </summary>
        public static void MMod_SECP192R1(in ECCurve curve, Span<ulong> result, Span<ulong> product)
        {
            int num_words = curve.NUM_WORDS;
            ReadOnlySpan<ulong> p = curve.p;
            Span<ulong> tmp = stackalloc ulong[num_words];
            int carry = 0;

            VLI.Set(result, product, num_words);
            VLI.Set(tmp, product.Slice(num_words), num_words);

            carry = (int)VLI.Add(result, result, tmp, num_words);

            tmp[0] = 0;
            tmp[1] = product[3];
            tmp[2] = product[4];
            carry += (int)VLI.Add(result, result, tmp, num_words);

            tmp[0] = tmp[1] = product[5];
            tmp[2] = 0;
            carry += (int)VLI.Add(result, result, tmp, num_words);

            while (Convert.ToBoolean(carry) || VLI.VarTimeCmp(p, result, num_words) != 1)
            {
                carry -= (int)VLI.Sub(result, result, p, num_words);
            }
        }
    }
}

