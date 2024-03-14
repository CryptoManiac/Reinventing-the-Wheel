using Wheel.Crypto.Elliptic.Internal.VeryLongInt;

namespace Wheel.Crypto.Elliptic.Internal.SECP256K1
{
    /// <summary>
    /// Curve-specific arithmetic functions which are used internally
    /// </summary>
    internal static class ECCUtil
    {
        public static ulong regularize_k(ReadOnlySpan<ulong> k, Span<ulong> k0, Span<ulong> k1)
        {
            const int num_n_words = Constants.NUM_WORDS;
            ulong carry = VLI_Arithmetic.Add(k0, k, Constants.n, num_n_words);
            VLI_Arithmetic.Add(k1, k0, Constants.n, num_n_words);
            return carry;
        }

        public static void mod_sqrt_default(Span<ulong> a)
        {
            int i;
            const int num_words = Constants.NUM_WORDS;
            Span<ulong> p1 = stackalloc ulong[num_words];
            Span<ulong> l_result = stackalloc ulong[num_words];
            p1[0] = l_result[0] = 1;

            // When curve_secp256k1.p == 3 (mod 4), we can compute
            //   sqrt(a) = a^((curve_secp256k1.p + 1) / 4) (mod curve_secp256k1.p).

            VLI_Arithmetic.Add(p1, Constants.p, p1, num_words); // p1 = curve_p + 1
            for (i = VLI_Logic.NumBits(p1, num_words) - 1; i > 1; --i)
            {
                modSquare_fast(l_result, l_result);
                if (VLI_Logic.TestBit(p1, i))
                {
                    modMult_fast(l_result, l_result, a);
                }
            }
            VLI_Arithmetic.Set(a, l_result, num_words);
        }

        /// <summary>
        /// Computes result = x^3 + b. result must not overlap x.
        /// </summary>
        /// <param name="result"></param>
        /// <param name="x"></param>
        public static void x_side(Span<ulong> result, ReadOnlySpan<ulong> x)
        {
            modSquare_fast(result, x);                                // r = x^2
            modMult_fast(result, result, x);                          // r = x^3
            VLI_Arithmetic.ModAdd(result, result, Constants.b, Constants.p, Constants.NUM_WORDS); // r = x^3 + b
        }

        public static void modSquare_fast(Span<ulong> result, ReadOnlySpan<ulong> left)
        {
            const int num_words = Constants.NUM_WORDS;
            Span<ulong> product = stackalloc ulong[2 * num_words];
            VLI_Arithmetic.Square(product, left, num_words);
            VLI_Arithmetic.MMod(result, product, Constants.p, num_words);
        }

        public static void modMult_fast(Span<ulong> result, Span<ulong> left, ReadOnlySpan<ulong> right)
        {
            const int num_words = Constants.NUM_WORDS;
            Span<ulong> product = stackalloc ulong[2 * num_words];
            VLI_Arithmetic.Mult(product, left, right, num_words);
            VLI_Arithmetic.MMod(result, product, Constants.p, num_words);
        }

        /// <summary>
        /// Modify (x1, y1) => (x1 * z^2, y1 * z^3)
        /// </summary>
        /// <param name="X1"></param>
        /// <param name="Y1"></param>
        /// <param name="Z"></param>
        public static void apply_z(Span<ulong> X1, Span<ulong> Y1, ReadOnlySpan<ulong> Z)
        {
            Span<ulong> t1 = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            modSquare_fast(t1, Z);    // z^2
            modMult_fast(X1, X1, t1); // x1 * z^2
            modMult_fast(t1, t1, Z);  // z^3
            modMult_fast(Y1, Y1, t1); // y1 * z^3
        }

        public static void double_jacobian(Span<ulong> X1, Span<ulong> Y1, Span<ulong> Z1)
        {
            const int num_words = Constants.NUM_WORDS;

            if (VLI_Logic.IsZero(Z1, num_words))
            {
                return;
            }

            // t1 = X, t2 = Y, t3 = Z
            Span<ulong> t4 = stackalloc ulong[num_words];
            Span<ulong> t5 = stackalloc ulong[num_words];

            ECCUtil.modSquare_fast(t5, Y1);   // t5 = y1^2
            ECCUtil.modMult_fast(t4, X1, t5); // t4 = x1*y1^2 = A
            ECCUtil.modSquare_fast(X1, X1);   // t1 = x1^2 
            ECCUtil.modSquare_fast(t5, t5);   // t5 = y1^4 
            ECCUtil.modMult_fast(Z1, Y1, Z1); // t3 = y1*z1 = z3 

            VLI_Arithmetic.ModAdd(Y1, X1, X1, Constants.p, num_words); // t2 = 2*x1^2
            VLI_Arithmetic.ModAdd(Y1, Y1, X1, Constants.p, num_words); // t2 = 3*x1^2
            if (VLI_Logic.TestBit(Y1, 0))
            {
                ulong carry = VLI_Arithmetic.Add(Y1, Y1, Constants.p, num_words);
                VLI_Arithmetic.RShift1(Y1, num_words);
                Y1[Constants.NUM_WORDS - 1] |= carry << (VLI_Common.WORD_BITS - 1);
            }
            else
            {
                VLI_Arithmetic.RShift1(Y1, Constants.NUM_WORDS);
            }
            // t2 = 3/2*(x1^2) = B

            ECCUtil.modSquare_fast(X1, Y1);                     // t1 = B^2
            VLI_Arithmetic.ModSub(X1, X1, t4, Constants.p, num_words); // t1 = B^2 - A
            VLI_Arithmetic.ModSub(X1, X1, t4, Constants.p, num_words); // t1 = B^2 - 2A = x3

            VLI_Arithmetic.ModSub(t4, t4, X1, Constants.p, num_words); // t4 = A - x3
            ECCUtil.modMult_fast(Y1, Y1, t4);                   // t2 = B * (A - x3)
            VLI_Arithmetic.ModSub(Y1, Y1, t5, Constants.p, num_words); // t2 = B * (A - x3) - y1^4 = y3
        }

        // P = (x1, y1) => 2P, (x2, y2) => P'
        public static void XYcZ_initial_double(Span<ulong> X1, Span<ulong> Y1, Span<ulong> X2, Span<ulong> Y2, ReadOnlySpan<ulong> initial_Z)
        {
            const int num_words = Constants.NUM_WORDS;
            Span<ulong> z = stackalloc ulong[num_words];

            // Setting Z as it is provided
            VLI_Arithmetic.Set(z, initial_Z, num_words);

            VLI_Arithmetic.Set(X2, X1, num_words);
            VLI_Arithmetic.Set(Y2, Y1, num_words);

            apply_z(X1, Y1, z);
            double_jacobian(X1, Y1, z);
            apply_z(X2, Y2, z);
        }

        // P = (x1, y1) => 2P, (x2, y2) => P'
        public static void XYcZ_double(Span<ulong> X1, Span<ulong> Y1, Span<ulong> X2, Span<ulong> Y2)
        {
            const int num_words = Constants.NUM_WORDS;
            Span<ulong> z = stackalloc ulong[num_words];

            // Version without initial_Z
            VLI_Arithmetic.Clear(z, num_words);
            z[0] = 1;

            VLI_Arithmetic.Set(X2, X1, num_words);
            VLI_Arithmetic.Set(Y2, Y1, num_words);

            apply_z(X1, Y1, z);
            double_jacobian(X1, Y1, z);
            apply_z(X2, Y2, z);
        }

        // Input P = (x1, y1, Z), Q = (x2, y2, Z)
        //   Output P' = (x1', y1', Z3), P + Q = (x3, y3, Z3)
        //   or P => P', Q => P + Q
        public static void XYcZ_add(Span<ulong> X1, Span<ulong> Y1, Span<ulong> X2, Span<ulong> Y2)
        {
            const int num_words = Constants.NUM_WORDS;

            // t1 = X1, t2 = Y1, t3 = X2, t4 = Y2
            Span<ulong> t5 = stackalloc ulong[num_words];

            VLI_Arithmetic.ModSub(t5, X2, X1, Constants.p, num_words); // t5 = x2 - x1
            modSquare_fast(t5, t5);                  // t5 = (x2 - x1)^2 = A
            modMult_fast(X1, X1, t5);                // t1 = x1*A = B
            modMult_fast(X2, X2, t5);                // t3 = x2*A = C
            VLI_Arithmetic.ModSub(Y2, Y2, Y1, Constants.p, num_words); // t4 = y2 - y1
            modSquare_fast(t5, Y2);                  // t5 = (y2 - y1)^2 = D

            VLI_Arithmetic.ModSub(t5, t5, X1, Constants.p, num_words); // t5 = D - B
            VLI_Arithmetic.ModSub(t5, t5, X2, Constants.p, num_words); // t5 = D - B - C = x3
            VLI_Arithmetic.ModSub(X2, X2, X1, Constants.p, num_words); // t3 = C - B
            modMult_fast(Y1, Y1, X2);                // t2 = y1*(C - B)
            VLI_Arithmetic.ModSub(X2, X1, t5, Constants.p, num_words); // t3 = B - x3
            modMult_fast(Y2, Y2, X2);                // t4 = (y2 - y1)*(B - x3)
            VLI_Arithmetic.ModSub(Y2, Y2, Y1, Constants.p, num_words); // t4 = y3
            VLI_Arithmetic.Set(X2, t5, num_words);
        }

        // Input P = (x1, y1, Z), Q = (x2, y2, Z)
        //   Output P + Q = (x3, y3, Z3), P - Q = (x3', y3', Z3)
        //   or P => P - Q, Q => P + Q
        public static void XYcZ_addC(Span<ulong> X1, Span<ulong> Y1, Span<ulong> X2, Span<ulong> Y2)
        {
            const int num_words = Constants.NUM_WORDS;

            // t1 = X1, t2 = Y1, t3 = X2, t4 = Y2
            Span<ulong> t5 = stackalloc ulong[num_words];
            Span<ulong> t6 = stackalloc ulong[num_words];
            Span<ulong> t7 = stackalloc ulong[num_words];

            VLI_Arithmetic.ModSub(t5, X2, X1, Constants.p, num_words); // t5 = x2 - x1
            modSquare_fast(t5, t5);                  // t5 = (x2 - x1)^2 = A
            modMult_fast(X1, X1, t5);                // t1 = x1*A = B
            modMult_fast(X2, X2, t5);                // t3 = x2*A = C
            VLI_Arithmetic.ModAdd(t5, Y2, Y1, Constants.p, num_words); // t5 = y2 + y1
            VLI_Arithmetic.ModSub(Y2, Y2, Y1, Constants.p, num_words); // t4 = y2 - y1

            VLI_Arithmetic.ModSub(t6, X2, X1, Constants.p, num_words); // t6 = C - B
            modMult_fast(Y1, Y1, t6);                // t2 = y1 * (C - B) = E
            VLI_Arithmetic.ModAdd(t6, X1, X2, Constants.p, num_words); // t6 = B + C
            modSquare_fast(X2, Y2);                  // t3 = (y2 - y1)^2 = D
            VLI_Arithmetic.ModSub(X2, X2, t6, Constants.p, num_words); // t3 = D - (B + C) = x3

            VLI_Arithmetic.ModSub(t7, X1, X2, Constants.p, num_words); // t7 = B - x3
            modMult_fast(Y2, Y2, t7);                // t4 = (y2 - y1)*(B - x3)
            VLI_Arithmetic.ModSub(Y2, Y2, Y1, Constants.p, num_words); // t4 = (y2 - y1)*(B - x3) - E = y3

            modSquare_fast(t7, t5);                  // t7 = (y2 + y1)^2 = F
            VLI_Arithmetic.ModSub(t7, t7, t6, Constants.p, num_words); // t7 = F - (B + C) = x3'
            VLI_Arithmetic.ModSub(t6, t7, X1, Constants.p, num_words); // t6 = x3' - B
            modMult_fast(t6, t6, t5);                // t6 = (y2+y1)*(x3' - B)
            VLI_Arithmetic.ModSub(Y1, t6, Y1, Constants.p, num_words); // t2 = (y2+y1)*(x3' - B) - E = y3'

            VLI_Arithmetic.Set(X1, t7, num_words);
        }
    }
}
