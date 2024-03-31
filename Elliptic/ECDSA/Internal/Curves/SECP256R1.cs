using Wheel.Crypto.Elliptic.EllipticCommon.VeryLongInt;

namespace Wheel.Crypto.Elliptic.ECDSA.Internal.Curves
{
	/// <summary>
	/// SECP256K1 specific constants and implementations
	/// </summary>
	internal static class SECP256R1
	{
        // Curve constants
        public static int NUM_N_BITS = 256;
        public static ulong[] p = new ulong[] { 0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF, 0x0000000000000000, 0xFFFFFFFF00000001 };
        public static ulong[] n = new ulong[] { 0xF3B9CAC2FC632551, 0xBCE6FAADA7179E84, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF00000000 };
        public static ulong[] half_n = new ulong[] { 0x79dce5617e3192a8, 0xde737d56d38bcf42, 0x7fffffff80000000, 0x7fffffff80000000 };
        public static ulong[] G = new ulong[] { 0xF4A13945D898C296, 0x77037D812DEB33A0, 0xF8BCE6E563A440F2, 0x6B17D1F2E12C4247, 0xCBB6406837BF51F5, 0x2BCE33576B315ECE, 0x8EE7EB4A7C0F9E16, 0x4FE342E2FE1A7F9B };
        public static ulong[] b = new ulong[] { 0x3BCE3C3E27D2604B, 0x651D06B0CC53B0F6, 0xB3EBBD55769886BC, 0x5AC635D8AA3A93E7 };

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

            // t
            VLI.Set(result, product, num_words);

            // s1
            tmp[0] = 0;
            tmp[1] = product[5] & 0xffffffff00000000;
            tmp[2] = product[6];
            tmp[3] = product[7];
            int carry = (int)VLI.Add(tmp, tmp, tmp, num_words);
            carry += (int)VLI.Add(result, result, tmp, num_words);

            // s2
            tmp[1] = product[6] << 32;
            tmp[2] = (product[6] >> 32) | (product[7] << 32);
            tmp[3] = product[7] >> 32;
            carry += (int)VLI.Add(tmp, tmp, tmp, num_words);
            carry += (int)VLI.Add(result, result, tmp, num_words);

            // s3
            tmp[0] = product[4];
            tmp[1] = product[5] & 0xffffffff;
            tmp[2] = 0;
            tmp[3] = product[7];
            carry += (int)VLI.Add(result, result, tmp, num_words);

            // s4
            tmp[0] = (product[4] >> 32) | (product[5] << 32);
            tmp[1] = (product[5] >> 32) | (product[6] & 0xffffffff00000000);
            tmp[2] = product[7];
            tmp[3] = (product[6] >> 32) | (product[4] << 32);
            carry += (int)VLI.Add(result, result, tmp, num_words);

            // d1 
            tmp[0] = (product[5] >> 32) | (product[6] << 32);
            tmp[1] = (product[6] >> 32);
            tmp[2] = 0;
            tmp[3] = (product[4] & 0xffffffff) | (product[5] << 32);
            carry -= (int)VLI.Sub(result, result, tmp, num_words);

            // d2 
            tmp[0] = product[6];
            tmp[1] = product[7];
            tmp[2] = 0;
            tmp[3] = (product[4] >> 32) | (product[5] & 0xffffffff00000000);
            carry -= (int)VLI.Sub(result, result, tmp, num_words);

            // d3 
            tmp[0] = (product[6] >> 32) | (product[7] << 32);
            tmp[1] = (product[7] >> 32) | (product[4] << 32);
            tmp[2] = (product[4] >> 32) | (product[5] << 32);
            tmp[3] = (product[6] << 32);
            carry -= (int)VLI.Sub(result, result, tmp, num_words);

            // d4 
            tmp[0] = product[7];
            tmp[1] = product[4] & 0xffffffff00000000;
            tmp[2] = product[5];
            tmp[3] = product[6] & 0xffffffff00000000;
            carry -= (int)VLI.Sub(result, result, tmp, num_words);

            if (carry < 0)
            {
                do
                {
                    carry += (int)VLI.Add(result, result, p, num_words);
                } while (carry < 0);
            }
            else
            {
                while (Convert.ToBoolean(carry) || VLI.VarTimeCmp(p, result, num_words) != 1)
                {
                    carry -= (int)VLI.Sub(result, result, p, num_words);
                }
            }
        }
    }
}

