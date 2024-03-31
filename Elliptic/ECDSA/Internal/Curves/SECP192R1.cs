using System;
using Wheel.Crypto.Elliptic.EllipticCommon.VeryLongInt;

namespace Wheel.Crypto.Elliptic.ECDSA.Internal.Curves
{
    /// <summary>
    /// SECP256K1 specific constants and implementations
    /// </summary>
    internal static class SECP192R1
    {
        // Curve constants
        public static int NUM_N_BITS = 192;
        public static readonly ulong[] p = new ulong[] { 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF };
        public static readonly ulong[] n = new ulong[] { 0x146BC9B1B4D22831, 0xFFFFFFFF99DEF836, 0xFFFFFFFFFFFFFFFF };
        public static readonly ulong[] half_n = new ulong[] { 0x0a35e4d8da691418, 0xffffffffccef7c1b, 0x7fffffffffffffff };
        public static readonly ulong[] G = new ulong[] { 0xF4FF0AFD82FF1012, 0x7CBF20EB43A18800, 0x188DA80EB03090F6, 0x73F977A11E794811, 0x631011ED6B24CDD5, 0x07192B95FFC8DA78 };
        public static readonly ulong[] b = new ulong[] { 0xFEB8DEECC146B9B1, 0x0FA7E9AB72243049, 0x64210519E59C80E7 };

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
            //VLI.MMod(result, product, p, num_words);
            MMod(result, product);
        }

        /// <summary>
        /// Computes result = product % p
        /// </summary>
        private static void MMod(Span<ulong> result, Span<ulong> product)
        {
            int num_words = VLI.BitsToWords(NUM_N_BITS);
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

