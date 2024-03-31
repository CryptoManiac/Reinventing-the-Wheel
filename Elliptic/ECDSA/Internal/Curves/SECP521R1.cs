using System;
using Wheel.Crypto.Elliptic.EllipticCommon.VeryLongInt;

namespace Wheel.Crypto.Elliptic.ECDSA.Internal.Curves
{
    /// <summary>
    /// SECP384R1 specific constants and implementations
    /// </summary>
    internal static class SECP521R1
    {
        // Curve constants
        public static int NUM_N_BITS = 521;
        public static readonly ulong[] p = new ulong[] {
            0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
            0x000001FF };
        public static readonly ulong[] n = new ulong[] {
            0xBB6FB71E91386409, 0x3BB5C9B8899C47AE, 0x7FCC0148F709A5D0, 0x51868783BF2F966B,
            0xFFFFFFFFFFFFFFFA, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
            0x000001FF };
        public static readonly ulong[] half_n = new ulong[] {
            0x5db7db8f489c3204, 0x1ddae4dc44ce23d7, 0xbfe600a47b84d2e8, 0x28c343c1df97cb35,
            0xfffffffffffffffd, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
            0x00000ff
        };
        public static readonly ulong[] G = new ulong[] {
            0xF97E7E31C2E5BD66, 0x3348B3C1856A429B, 0xFE1DC127A2FFA8DE, 0xA14B5E77EFE75928,
            0xF828AF606B4D3DBA, 0x9C648139053FB521, 0x9E3ECB662395B442, 0x858E06B70404E9CD,
            0x000000C6,
            0x88BE94769FD16650, 0x353C7086A272C240, 0xC550B9013FAD0761, 0x97EE72995EF42640,
            0x17AFBD17273E662C, 0x98F54449579B4468, 0x5C8A5FB42C7D1BD9, 0x39296A789A3BC004,
            0x00000118
        };
        public static readonly ulong[] b = new ulong[] {
            0xEF451FD46B503F00, 0x3573DF883D2C34F1, 0x1652C0BD3BB1BF07, 0x56193951EC7E937B,
            0xB8B489918EF109E1, 0xA2DA725B99B315F3, 0x929A21A0B68540EE, 0x953EB9618E1C9A1F,
            0x00000051
        };

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

