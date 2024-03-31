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
        /// Computes result = x^3 + b. Result must not overlap x.
        /// </summary>
        /// <param name="result"></param>
        /// <param name="x"></param>
        public static void XSide(Span<ulong> result, ReadOnlySpan<ulong> x)
        {
            int num_words = VLI.BitsToWords(NUM_N_BITS);
            Span<ulong> _3 = stackalloc ulong[num_words];
            _3[0] = 3; // -a = 3

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
            int num_words = VLI.BitsToWords(NUM_N_BITS);
            Span<ulong> product = stackalloc ulong[2 * num_words];
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
            int num_words = VLI.BitsToWords(NUM_N_BITS);
            Span<ulong> p1 = stackalloc ulong[num_words];
            Span<ulong> l_result = stackalloc ulong[num_words];
            p1[0] = l_result[0] = 1;

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
            int num_words = VLI.BitsToWords(NUM_N_BITS);
            Span<ulong> product = stackalloc ulong[2 * num_words];
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
            int num_words = VLI.BitsToWords(NUM_N_BITS);

            // t1 = X, t2 = Y, t3 = Z
            Span<ulong> t4 = stackalloc ulong[num_words];
            Span<ulong> t5 = stackalloc ulong[num_words];

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

