using Wheel.Crypto.Elliptic.EllipticCommon.VeryLongInt;

namespace Wheel.Crypto.Elliptic.ECDSA.Internal.Curves
{
	/// <summary>
	/// SECP256K1 specific constants and implementations
	/// </summary>
	internal static class SECP256R1
	{
        // Curve constants
        public static int NUM_N_BITS = VLI.ECC_MAX_WORDS * VLI.WORD_BITS;
        public static ulong[] p = new ulong[] { 0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF, 0x0000000000000000, 0xFFFFFFFF00000001 };
        public static ulong[] n = new ulong[] { 0xF3B9CAC2FC632551, 0xBCE6FAADA7179E84, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF00000000 };
        public static ulong[] half_n = new ulong[] { 0x79dce5617e3192a8, 0xde737d56d38bcf42, 0x7fffffff80000000, 0x7fffffff80000000 };
        public static ulong[] G = new ulong[] { 0xF4A13945D898C296, 0x77037D812DEB33A0, 0xF8BCE6E563A440F2, 0x6B17D1F2E12C4247, 0xCBB6406837BF51F5, 0x2BCE33576B315ECE, 0x8EE7EB4A7C0F9E16, 0x4FE342E2FE1A7F9B };
        public static ulong[] b = new ulong[] { 0x3BCE3C3E27D2604B, 0x651D06B0CC53B0F6, 0xB3EBBD55769886BC, 0x5AC635D8AA3A93E7 };

        /// <summary>
        /// Computes result = x^3 + b. Result must not overlap x.
        /// </summary>
        /// <param name="result"></param>
        /// <param name="x"></param>
        public static void XSide(Span<ulong> result, ReadOnlySpan<ulong> x)
        {
            Span<ulong> _3 = stackalloc ulong[VLI.ECC_MAX_WORDS] { 3, 0, 0, 0 }; // -a = 3
            int num_words = VLI.BitsToWords(NUM_N_BITS);

            ModSquare(result, x);                             // r = x^2
            VLI.ModSub(result, result, _3, p, num_words);       // r = x^2 - 3
            ModMult(result, result, x);                // r = x^3 - 3x
            VLI.ModAdd(result, result, b, p, num_words); // r = x^3 - 3x + b
        }

        /// <summary>
        /// Computes result = left^2 % p
        /// </summary>
        /// <param name="result"></param>
        /// <param name="left"></param>
        public static void ModSquare(Span<ulong> result, ReadOnlySpan<ulong> left)
        {
            Span<ulong> product = stackalloc ulong[2 * VLI.ECC_MAX_WORDS];
            int num_words = VLI.BitsToWords(NUM_N_BITS);
            VLI.Square(product, left, num_words);
            //VLI.MMod(result, product, p, num_words);
            MMod(result, product); 
        }

        /// <summary>
        /// Compute a = sqrt(a) (mod curve_p)
        /// </summary>
        /// <param name="a"></param>
        public static void ModSQRT(Span<ulong> a)
        {
            Span<ulong> p1 = stackalloc ulong[VLI.ECC_MAX_WORDS];
            Span<ulong> l_result = stackalloc ulong[VLI.ECC_MAX_WORDS];
            p1[0] = l_result[0] = 1;

            int num_words = VLI.BitsToWords(NUM_N_BITS);

            // When curve_secp256k1.p == 3 (mod 4), we can compute
            //   sqrt(a) = a^((curve_secp256k1.p + 1) / 4) (mod curve_secp256k1.p).

            VLI.Add(p1, p, p1, num_words); // p1 = curve_p + 1
            for (int i = VLI.NumBits(p1, num_words) - 1; i > 1; --i)
            {
                ModSquare(l_result, l_result);
                if (VLI.TestBit(p1, i))
                {
                    ModMult(l_result, l_result, a);
                }
            }
            VLI.Set(a, l_result, num_words);
        }

        /// <summary>
        /// Computes result = (left * right) % p
        /// </summary>
        /// <param name="result"></param>
        /// <param name="left"></param>
        /// <param name="right"></param>
        public static void ModMult(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right)
        {
            Span<ulong> product = stackalloc ulong[2 * VLI.ECC_MAX_WORDS];
            int num_words = VLI.BitsToWords(NUM_N_BITS);
            VLI.Mult(product, left, right, num_words);
            //VLI.MMod(result, product, p, num_words);
            MMod(result, product);
        }

        /// <summary>
        /// Double in place
        /// </summary>
        /// <param name="X1"></param>
        /// <param name="Y1"></param>
        /// <param name="Z1"></param>
        public static void DoubleJacobian(Span<ulong> X1, Span<ulong> Y1, Span<ulong> Z1)
        {
            // t1 = X, t2 = Y, t3 = Z
            Span<ulong> t4 = stackalloc ulong[VLI.ECC_MAX_WORDS];
            Span<ulong> t5 = stackalloc ulong[VLI.ECC_MAX_WORDS];
            int num_words = VLI.BitsToWords(NUM_N_BITS);

            if (VLI.IsZero(Z1, num_words))
            {
                return;
            }

            ModSquare(t4, Y1);   // t4 = y1^2
            ModMult(t5, X1, t4); // t5 = x1*y1^2 = A
            ModSquare(t4, t4);   // t4 = y1^4 */
            ModMult(Y1, Y1, Z1); // t2 = y1*z1 = z3
            ModSquare(Z1, Z1);   // t3 = z1^2

            VLI.ModAdd(X1, X1, Z1, p, num_words); // t1 = x1 + z1^2
            VLI.ModAdd(Z1, Z1, Z1, p, num_words); // t3 = 2*z1^2
            VLI.ModSub(Z1, X1, Z1, p, num_words); // t3 = x1 - z1^2
            ModMult(X1, X1, Z1);                // t1 = x1^2 - z1^4

            VLI.ModAdd(Z1, X1, X1, p, num_words); // t3 = 2*(x1^2 - z1^4)
            VLI.ModAdd(X1, X1, Z1, p, num_words); // t1 = 3*(x1^2 - z1^4)
            if (VLI.TestBit(X1, 0))
            {
                ulong l_carry = VLI.Add(X1, X1, p, num_words);
                VLI.RShift1(X1, num_words);
                X1[num_words - 1] |= l_carry << (VLI.WORD_BITS - 1);
            }
            else
            {
                VLI.RShift1(X1, num_words);
            }
            // t1 = 3/2*(x1^2 - z1^4) = B

            ModSquare(Z1, X1);                  // t3 = B^2
            VLI.ModSub(Z1, Z1, t5, p, num_words); // t3 = B^2 - A
            VLI.ModSub(Z1, Z1, t5, p, num_words); // t3 = B^2 - 2A = x3
            VLI.ModSub(t5, t5, Z1, p, num_words); // t5 = A - x3
            ModMult(X1, X1, t5);         // t1 = B * (A - x3)
            VLI.ModSub(t4, X1, t4, p, num_words); // t4 = B * (A - x3) - y1^4 = y3

            VLI.Set(X1, Z1, num_words);
            VLI.Set(Z1, Y1, num_words);
            VLI.Set(Y1, t4, num_words);
        }

        private static void MMod(Span<ulong> result, Span<ulong> product)
        {
            Span<ulong> tmp = stackalloc ulong[VLI.ECC_MAX_WORDS];
            int num_words = VLI.BitsToWords(NUM_N_BITS);
            int carry;

            // t
            VLI.Set(result, product, num_words);

            // s1
            tmp[0] = 0;
            tmp[1] = product[5] & 0xffffffff00000000;
            tmp[2] = product[6];
            tmp[3] = product[7];
            carry = (int)VLI.Add(tmp, tmp, tmp, num_words);
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

