using System;
using Wheel.Crypto.Elliptic.EllipticCommon.VeryLongInt;

namespace Wheel.Crypto.Elliptic.ECDSA.Internal.Curves
{
    /// <summary>
    /// SECP256K1 specific constants and implementations
    /// </summary>
    internal static class SECP224R1
    {
        // Curve constants
        public static int NUM_N_BITS = 224;

        public static readonly ulong[] p = new ulong[] { 0x0000000000000001, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF };
        public static readonly ulong[] n = new ulong[] { 0x13DD29455C5C2A3D, 0xFFFF16A2E0B8F03E, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF };
        public static readonly ulong[] half_n = new ulong[] { 0x09ee94a2ae2e151e, 0xffff8b51705c781f, 0xffffffffffffffff, 0x7fffffff };
        public static readonly ulong[] G = new ulong[] { 0x343280D6115C1D21, 0x4A03C1D356C21122, 0x6BB4BF7F321390B9, 0xB70E0CBD, 0x44D5819985007E34, 0xCD4375A05A074764, 0xB5F723FB4C22DFE6, 0xBD376388 };
        public static readonly ulong[] b = new ulong[] { 0x270B39432355FFB4, 0x5044B0B7D7BFD8BA, 0x0C04B3ABF5413256, 0xB4050A85 };

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
            Span<ulong> e1 = stackalloc ulong[VLI.ECC_MAX_WORDS];
            Span<ulong> f1 = stackalloc ulong[VLI.ECC_MAX_WORDS];
            Span<ulong> d0 = stackalloc ulong[VLI.ECC_MAX_WORDS];
            Span<ulong> e0 = stackalloc ulong[VLI.ECC_MAX_WORDS];
            Span<ulong> f0 = stackalloc ulong[VLI.ECC_MAX_WORDS];
            Span<ulong> d1 = stackalloc ulong[VLI.ECC_MAX_WORDS];

            int num_words = VLI.BitsToWords(NUM_N_BITS);

            // s = a; using constant instead of random value
            mod_sqrt_secp224r1_rp(d0, e0, f0, a, a);           // RP (d0, e0, f0, c, s)
            mod_sqrt_secp224r1_rs(d1, e1, f1, d0, e0, f0);     // RS (d1, e1, f1, d0, e0, f0)
            for (int i = 1; i <= 95; i++)
            {
                VLI.Set(d0, d1, num_words);          // d0 <-- d1
                VLI.Set(e0, e1, num_words);          // e0 <-- e1
                VLI.Set(f0, f1, num_words);          // f0 <-- f1
                mod_sqrt_secp224r1_rs(d1, e1, f1, d0, e0, f0); // RS (d1, e1, f1, d0, e0, f0)
                if (VLI.IsZero(d1, num_words))
                {     // if d1 == 0
                    break;
                }
            }
            VLI.ModInv(f1, e0, p, num_words); // f1 <-- 1 / e0
            ModMult(a, d0, f1);              // a  <-- d0 / e0
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
            int carry = 0;

            // t
            VLI.Set(result, product, num_words);
            result[num_words - 1] &= 0xffffffff;

            // s1
            tmp[0] = 0;
            tmp[1] = product[3] & 0xffffffff00000000;
            tmp[2] = product[4];
            tmp[3] = product[5] & 0xffffffff;
            VLI.Add(result, result, tmp, num_words);

            // s2
            tmp[1] = product[5] & 0xffffffff00000000;
            tmp[2] = product[6];
            tmp[3] = 0;
            VLI.Add(result, result, tmp, num_words);

            // d1
            tmp[0] = (product[3] >> 32) | (product[4] << 32);
            tmp[1] = (product[4] >> 32) | (product[5] << 32);
            tmp[2] = (product[5] >> 32) | (product[6] << 32);
            tmp[3] = product[6] >> 32;
            carry -= (int)VLI.Sub(result, result, tmp, num_words);

            // d2
            tmp[0] = (product[5] >> 32) | (product[6] << 32);
            tmp[1] = product[6] >> 32;
            tmp[2] = tmp[3] = 0;
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
                while (VLI.VarTimeCmp(p, result, num_words) != 1)
                {
                    VLI.Sub(result, result, p, num_words);
                }
            }
        }


        /// <summary>
        /// Routine 3.2.4 RS;  from http://www.nsa.gov/ia/_files/nist-routines.pdf
        /// </summary>
        private static void mod_sqrt_secp224r1_rs(Span<ulong> d1, Span<ulong> e1, Span<ulong> f1, ReadOnlySpan<ulong> d0, ReadOnlySpan<ulong> e0, ReadOnlySpan<ulong> f0) {
            Span<ulong> t = stackalloc ulong[VLI.ECC_MAX_WORDS];
            int num_words = VLI.BitsToWords(NUM_N_BITS);

            ModSquare(t, d0);                               // t <-- d0 ^ 2
            ModMult(e1, d0, e0);                            // e1 <-- d0 * e0
            VLI.ModAdd(d1, t, f0, p, num_words);  // d1 <-- t  + f0
            VLI.ModAdd(e1, e1, e1, p, num_words); // e1 <-- e1 + e1
            ModMult(f1, t, f0);                             // f1 <-- t  * f0
            VLI.ModAdd(f1, f1, f1, p, num_words); // f1 <-- f1 + f1
            VLI.ModAdd(f1, f1, f1, p, num_words); // f1 <-- f1 + f1
        }

        /// <summary>
        /// Routine 3.2.5 RSS;  from http://www.nsa.gov/ia/_files/nist-routines.pdf
        /// </summary>
        private static void mod_sqrt_secp224r1_rss(Span<ulong> d1, Span<ulong> e1, Span<ulong> f1, ReadOnlySpan<ulong> d0, ReadOnlySpan<ulong> e0, ReadOnlySpan<ulong> f0, int j)
        {
            int num_words = VLI.BitsToWords(NUM_N_BITS);
            VLI.Set(d1, d0, num_words); // d1 <-- d0
            VLI.Set(e1, e0, num_words); // e1 <-- e0
            VLI.Set(f1, f0, num_words); // f1 <-- f0
            for (int i = 1; i <= j; ++i)
            {
                mod_sqrt_secp224r1_rs(d1, e1, f1, d1, e1, f1); // RS (d1,e1,f1,d1,e1,f1)
            }
        }

        /// <summary>
        /// Routine 3.2.6 RM;  from http://www.nsa.gov/ia/_files/nist-routines.pdf
        /// </summary>
        private static void mod_sqrt_secp224r1_rm(Span<ulong> d2, Span<ulong> e2, Span<ulong> f2, ReadOnlySpan<ulong> c, ReadOnlySpan<ulong> d0, ReadOnlySpan<ulong> e0, ReadOnlySpan<ulong> d1, ReadOnlySpan<ulong> e1)
        {
            Span<ulong> t1 = stackalloc ulong[VLI.ECC_MAX_WORDS];
            Span<ulong> t2 = stackalloc ulong[VLI.ECC_MAX_WORDS];
            int num_words = VLI.BitsToWords(NUM_N_BITS);

            ModMult(t1, e0, e1); // t1 <-- e0 * e1
            ModMult(t1, t1, c);  // t1 <-- t1 * c
            // t1 <-- p  - t1
            VLI.ModSub(t1, p, t1, p, num_words);
            ModMult(t2, d0, d1);                            // t2 <-- d0 * d1
            VLI.ModAdd(t2, t2, t1, p, num_words); // t2 <-- t2 + t1
            ModMult(t1, d0, e1);                            // t1 <-- d0 * e1
            ModMult(e2, d1, e0);                            // e2 <-- d1 * e0
            VLI.ModAdd(e2, e2, t1, p, num_words); // e2 <-- e2 + t1
            ModSquare(f2, e2);                              // f2 <-- e2^2
            ModMult(f2, f2, c);                             // f2 <-- f2 * c
            // f2 <-- p  - f2
            VLI.ModSub(f2, p, f2, p, num_words);
            VLI.Set(d2, t2, num_words);           // d2 <-- t2
        }

        /// <summary>
        /// Routine 3.2.7 RP;  from http://www.nsa.gov/ia/_files/nist-routines.pdf
        /// </summary>
        private static void mod_sqrt_secp224r1_rp(Span<ulong> d1, Span<ulong> e1, Span<ulong> f1, ReadOnlySpan<ulong> c, ReadOnlySpan<ulong> r)
        {
            Span<ulong> d0 = stackalloc ulong[VLI.ECC_MAX_WORDS];
            Span<ulong> e0 = stackalloc ulong[VLI.ECC_MAX_WORDS] { 1, 0, 0, 0 }; // e0 <-- 1
            Span<ulong> f0 = stackalloc ulong[VLI.ECC_MAX_WORDS];
            int num_words = VLI.BitsToWords(NUM_N_BITS);

            VLI.Set(d0, r, num_words); // d0 <-- r
            // f0 <-- p  - c
            VLI.ModSub(f0, p, c, p, num_words);
            for (int i = 0, pow2i = 1; i <= 6; i++)
            {
                mod_sqrt_secp224r1_rss(d1, e1, f1, d0, e0, f0, pow2i); // RSS (d1,e1,f1,d0,e0,f0,2^i)
                mod_sqrt_secp224r1_rm(d1, e1, f1, c, d1, e1, d0, e0);  // RM (d1,e1,f1,c,d1,e1,d0,e0)
                VLI.Set(d0, d1, num_words);                  // d0 <-- d1
                VLI.Set(e0, e1, num_words);                  // e0 <-- e1
                VLI.Set(f0, f1, num_words);                  // f0 <-- f1
                pow2i *= 2;
            }
        }

    }
}

