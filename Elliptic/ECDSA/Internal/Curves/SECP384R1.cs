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
        public static void MMod_SECP384R1(in ECCurve curve, Span<ulong> result, Span<ulong> product)
        {
            int num_words = curve.NUM_WORDS;
            ReadOnlySpan<ulong> p = curve.P;
            Span<ulong> tmp = stackalloc ulong[2 * num_words];

            while (!VLI.IsZero(product.Slice(num_words), num_words)) // While c1 != 0
            {
                ulong carry = 0;
                VLI.Clear(tmp, 2 * num_words);
                omega_mult(curve, tmp, product.Slice(num_words));    // tmp = w * c1 */
                VLI.Clear(product.Slice(num_words), num_words); // p = c0

                // (c1, c0) = c0 + w * c1
                for (int i = 0; i < num_words + 3; ++i)
                {
                    ulong sum = product[i] + tmp[i] + carry;
                    if (sum != product[i])
                    {
                        carry = Convert.ToUInt64(sum < product[i]);
                    }
                    product[i] = sum;
                }
            }

            while (VLI.VarTimeCmp(product, p, num_words) > 0)
            {
                VLI.Sub(product, product, p, num_words);
            }
            VLI.Set(result, product, num_words);
        }

        private static void omega_mult(in ECCurve curve, Span<ulong> result, Span<ulong> right)
        {
            int num_words = curve.NUM_WORDS;
            Span<ulong> tmp = stackalloc ulong[2 * num_words];
            ulong carry, diff;

            // Multiply by (2^128 + 2^96 - 2^32 + 1).
            VLI.Set(result, right, num_words); // 1
            carry = VLI.LShift(tmp, right, 32, num_words);
            result[1 + num_words] = carry + VLI.Add(result.Slice(1), result.Slice(1), tmp, num_words);  // 2^96 + 1
            result[2 + num_words] = VLI.Add(result.Slice(2), result.Slice(2), right, num_words);        // 2^128 + 2^96 + 1
            carry += VLI.Sub(result, result, tmp, num_words);                                           // 2^128 + 2^96 - 2^32 + 1
            diff = result[num_words] - carry;
            if (diff > result[num_words])
            {
                // Propagate borrow if necessary.
                for (int i = 1 + num_words; ; ++i)
                {
                    --result[i];
                    if (result[i] != ulong.MaxValue)
                    {
                        break;
                    }
                }
            }
            result[num_words] = diff;
        }
    }
}

