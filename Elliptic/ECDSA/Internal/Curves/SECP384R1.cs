using System;
using Wheel.Crypto.Elliptic.EllipticCommon.VeryLongInt;

namespace Wheel.Crypto.Elliptic.ECDSA.Internal.Curves
{
    /// <summary>
    /// SECP384R1 specific constants and implementations
    /// </summary>
    internal static class SECP384R1
    {
        // Curve constants
        public static int NUM_N_BITS = 384;
        public static ulong[] p = new ulong[] { 0x00000000FFFFFFFF, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF };
        public static ulong[] n = new ulong[] { 0xECEC196ACCC52973, 0x581A0DB248B0A77A, 0xC7634D81F4372DDF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF };
        public static ulong[] half_n = new ulong[] { 0x76760cb5666294b9, 0xac0d06d9245853bd, 0xe3b1a6c0fa1b96ef, 0xffffffffffffffff, 0xffffffffffffffff, 0x7fffffffffffffff };
        public static ulong[] G = new ulong[] {
            0x3A545E3872760AB7, 0x5502F25DBF55296C, 0x59F741E082542A38, 0x6E1D3B628BA79B98, 0x8EB1C71EF320AD74, 0xAA87CA22BE8B0537,
            0x7A431D7C90EA0E5F, 0x0A60B1CE1D7E819D, 0xE9DA3113B5F0B8C0, 0xF8F41DBD289A147C, 0x5D9E98BF9292DC29, 0x3617DE4A96262C6F
        };
        public static ulong[] b = new ulong[] { 0x2A85C8EDD3EC2AEF, 0xC656398D8A2ED19D, 0x0314088F5013875A, 0x181D9C6EFE814112, 0x988E056BE3F82D19, 0xB3312FA7E23EE7E4 };

        /// <summary>
        /// Computes result = left^2 % p
        /// </summary>
        /// <param name="result"></param>
        /// <param name="left"></param>
        public static void ModSquare(Span<ulong> result, ReadOnlySpan<ulong> left)
        {
            int num_words = VLI.BitsToWords(NUM_N_BITS);
            Span<ulong> product = stackalloc ulong[2 * num_words];
            VLI.Square(product, left, num_words);
            // NOTE: MMod is inpractically slow here
            //VLI.MMod(result, product, p, num_words);
            MMod(result, product); 
        }

        /// <summary>
        /// Computes result = (left * right) % p
        /// </summary>
        /// <param name="result"></param>
        /// <param name="left"></param>
        /// <param name="right"></param>
        public static void ModMult(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right)
        {
            int num_words = VLI.BitsToWords(NUM_N_BITS);
            Span<ulong> product = stackalloc ulong[2 * num_words];
            VLI.Mult(product, left, right, num_words);
            // NOTE: MMod is inpractically slow here
            //VLI.MMod(result, product, p, num_words);
            MMod(result, product);
        }

        /// <summary>
        /// Computes result = product % p
        /// </summary>
        private static void MMod(Span<ulong> result, Span<ulong> product)
        {
            int num_words = VLI.BitsToWords(NUM_N_BITS);
            Span<ulong> tmp = stackalloc ulong[2 * num_words];

            while (!VLI.IsZero(product.Slice(num_words), num_words)) // While c1 != 0
            {
                ulong carry = 0;
                VLI.Clear(tmp, 2 * num_words);
                omega_mult(tmp, product.Slice(num_words));    // tmp = w * c1 */
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

        private static void omega_mult(Span<ulong> result, Span<ulong> right)
        {
            int num_words = VLI.BitsToWords(NUM_N_BITS);
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

