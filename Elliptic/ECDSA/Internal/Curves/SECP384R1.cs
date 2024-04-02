using System.Runtime.CompilerServices;
using Wheel.Crypto.Elliptic.EllipticCommon.VeryLongInt;

namespace Wheel.Crypto.Elliptic.ECDSA
{
    /// <summary>
    /// SECP384R1 specific constants and implementations.
    /// NOTE: These methods are declared static on purpose, it allows us to use their addresses in the curve constructor functions.
    /// </summary>
    public readonly partial struct ECCurve
    {
        /// <summary>
        /// Construct a new instance of the secp384r1 context.
        /// <returns></returns>
        public static unsafe ECCurve Get_SECP384R1()
        {
            return new ECCurve(
                384,
                stackalloc ulong[] { 0x00000000FFFFFFFF, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF },
                stackalloc ulong[] { 0xECEC196ACCC52973, 0x581A0DB248B0A77A, 0xC7634D81F4372DDF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF },
                stackalloc ulong[] { 0x76760cb5666294b9, 0xac0d06d9245853bd, 0xe3b1a6c0fa1b96ef, 0xffffffffffffffff, 0xffffffffffffffff, 0x7fffffffffffffff },
                stackalloc ulong[] {
                    0x3A545E3872760AB7, 0x5502F25DBF55296C, 0x59F741E082542A38, 0x6E1D3B628BA79B98, 0x8EB1C71EF320AD74, 0xAA87CA22BE8B0537,
                    0x7A431D7C90EA0E5F, 0x0A60B1CE1D7E819D, 0xE9DA3113B5F0B8C0, 0xF8F41DBD289A147C, 0x5D9E98BF9292DC29, 0x3617DE4A96262C6F
                },
                stackalloc ulong[] { 0x2A85C8EDD3EC2AEF, 0xC656398D8A2ED19D, 0x0314088F5013875A, 0x181D9C6EFE814112, 0x988E056BE3F82D19, 0xB3312FA7E23EE7E4 },
                &MMod_SECP384R1,
                &XSide_Generic,
                &ModSQRT_Generic,
                &DoubleJacobian_Generic
            );
        }

        /// <summary>
        /// Computes result = product % p
        /// </summary>
        [SkipLocalsInit]
        private static void MMod_SECP384R1(in ECCurve curve, Span<ulong> result, Span<ulong> product)
        {
            Span<ulong> tmp = stackalloc ulong[2 * curve.NUM_WORDS];

            while (!VLI.IsZero(product.Slice(curve.NUM_WORDS), curve.NUM_WORDS)) // While c1 != 0
            {
                ulong carry = 0;
                VLI.Clear(tmp, 2 * curve.NUM_WORDS);
                OmegaMult_SECP384R1(curve, tmp, product.Slice(curve.NUM_WORDS));    // tmp = w * c1 */
                VLI.Clear(product.Slice(curve.NUM_WORDS), curve.NUM_WORDS); // p = c0

                // (c1, c0) = c0 + w * c1
                for (int i = 0; i < curve.NUM_WORDS + 3; ++i)
                {
                    ulong sum = product[i] + tmp[i] + carry;
                    if (sum != product[i])
                    {
                        carry = Convert.ToUInt64(sum < product[i]);
                    }
                    product[i] = sum;
                }
            }

            while (VLI.VarTimeCmp(product, curve.P, curve.NUM_WORDS) > 0)
            {
                VLI.Sub(product, product, curve.P, curve.NUM_WORDS);
            }
            VLI.Set(result, product, curve.NUM_WORDS);
        }

        [SkipLocalsInit]
        private static void OmegaMult_SECP384R1(in ECCurve curve, Span<ulong> result, Span<ulong> right)
        {
            Span<ulong> tmp = stackalloc ulong[2 * curve.NUM_WORDS];
            ulong carry, diff;

            // Multiply by (2^128 + 2^96 - 2^32 + 1).
            VLI.Set(result, right, curve.NUM_WORDS); // 1
            carry = VLI.LShift(tmp, right, 32, curve.NUM_WORDS);
            result[1 + curve.NUM_WORDS] = carry + VLI.Add(result.Slice(1), result.Slice(1), tmp, curve.NUM_WORDS);  // 2^96 + 1
            result[2 + curve.NUM_WORDS] = VLI.Add(result.Slice(2), result.Slice(2), right, curve.NUM_WORDS);        // 2^128 + 2^96 + 1
            carry += VLI.Sub(result, result, tmp, curve.NUM_WORDS);                                           // 2^128 + 2^96 - 2^32 + 1
            diff = result[curve.NUM_WORDS] - carry;
            if (diff > result[curve.NUM_WORDS])
            {
                // Propagate borrow if necessary.
                for (int i = 1 + curve.NUM_WORDS; ; ++i)
                {
                    --result[i];
                    if (result[i] != ulong.MaxValue)
                    {
                        break;
                    }
                }
            }
            result[curve.NUM_WORDS] = diff;
        }
    }
}

