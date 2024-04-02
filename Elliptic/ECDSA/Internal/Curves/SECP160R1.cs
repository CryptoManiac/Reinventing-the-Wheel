using System.Runtime.CompilerServices;
using Wheel.Crypto.Elliptic.EllipticCommon.VeryLongInt;

namespace Wheel.Crypto.Elliptic.ECDSA
{
    /// <summary>
    /// SECP192R1 specific implementations.
    /// NOTE: These methods are declared static on purpose, it allows us to use their addresses in the curve constructor functions.
    /// </summary>
    public readonly partial struct ECCurve
    {
        /// <summary>
        /// Construct a new instance of the secp192r1 context.
        /// <returns></returns>
        public static unsafe ECCurve Get_SECP160R1()
        {
            return new ECCurve(
                161,
                stackalloc ulong[] { 0xFFFFFFFF7FFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF },
                stackalloc ulong[] { 0xF927AED3CA752257, 0x000000000001F4C8, 0x0000000100000000 },
                stackalloc ulong[] { 0x7c93d769e53a912b, 0x000000000000fa64, 0x0000000080000000 },
                stackalloc ulong[] { 0x68C38BB913CBFC82, 0x8EF5732846646989, 0x4A96B568, 0x042351377AC5FB32, 0x3168947D59DCC912, 0x23A62855 },
                stackalloc ulong[] { 0x81D4D4ADC565FA45, 0x54BD7A8B65ACF89F, 0x1C97BEFC },
                &MMod_SECP160R1,
                &XSide_Generic,
                &ModSQRT_Generic,
                &DoubleJacobian_Generic
            );
        }

        /// <summary>
        /// Computes result = product % p
        /// </summary>
        [SkipLocalsInit]
        private static void MMod_SECP160R1(in ECCurve curve, Span<ulong> result, Span<ulong> product)
        {
            Span<ulong> tmp = stackalloc ulong[2 * curve.NUM_WORDS];
            VLI.Clear(tmp, 2 * curve.NUM_WORDS);

            OmegaMult_SECP160R1(curve, tmp, product.Slice(curve.NUM_WORDS - 1)); // (Rq, q) = q * c

            product[curve.NUM_WORDS - 1] &= 0xffffffff;
            ulong copy = tmp[curve.NUM_WORDS - 1];
            tmp[curve.NUM_WORDS - 1] &= 0xffffffff;
            VLI.Add(result, product, tmp, curve.NUM_WORDS); // (C, r) = r + q
            VLI.Clear(product, curve.NUM_WORDS);
            tmp[curve.NUM_WORDS - 1] = copy;
            OmegaMult_SECP160R1(curve, product, tmp.Slice(curve.NUM_WORDS - 1)); // Rq * c
            VLI.Add(result, result, product, curve.NUM_WORDS); // (C1, r) = r + Rq * c

            while (VLI.VarTimeCmp(result, curve.P, curve.NUM_WORDS) > 0)
            {
                VLI.Sub(result, result, curve.P, curve.NUM_WORDS);
            }
        }

        static void OmegaMult_SECP160R1(in ECCurve curve, Span<ulong> result, ReadOnlySpan<ulong> right)
        {
            uint carry;
            int i;

            // Multiply by (2^31 + 1).
            carry = 0;
            for (i = 0; i < curve.NUM_WORDS; ++i)
            {
                ulong tmp = (right[i] >> 32) | (right[i + 1] << 32);
                result[i] = (tmp << 31) + tmp + carry;
                carry = (uint)((tmp >> 33) + Convert.ToUInt32(result[i] < tmp || (Convert.ToBoolean(carry) && result[i] == tmp)));
            }
            result[i] = carry;
        }
    }
}

