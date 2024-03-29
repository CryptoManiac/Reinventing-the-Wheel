using Wheel.Crypto.Elliptic.Internal.VeryLongInt;

namespace Wheel.Crypto.Elliptic.Internal.Curves
{
	/// <summary>
	/// SECP256K1 specific constants and implementations
	/// </summary>
	internal static class SECP256K1
	{
        // Curve constants
        public static int NUM_BITS = VLI.ECC_MAX_WORDS * VLI.WORD_BITS;
        public static int NUM_N_BITS = VLI.ECC_MAX_WORDS * VLI.WORD_BITS;
        public static ulong[] p = new ulong[] { 0xFFFFFFFEFFFFFC2F, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF };
        public static ulong[] n = new ulong[] { 0xBFD25E8CD0364141, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF };
        public static ulong[] half_n = new ulong[] { 0xdfe92f46681b20a0, 0x5d576e7357a4501d, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF };
        public static ulong[] G = new ulong[] { 0x59F2815B16F81798, 0x029BFCDB2DCE28D9, 0x55A06295CE870B07, 0x79BE667EF9DCBBAC, 0x9C47D08FFB10D4B8, 0xFD17B448A6855419, 0x5DA4FBFC0E1108A8, 0x483ADA7726A3C465 };
        public static ulong[] b = new ulong[] { 0x0000000000000007, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 };

        /// <summary>
        /// Computes result = x^3 + b. result must not overlap x.
        /// </summary>
        /// <param name="result"></param>
        /// <param name="x"></param>
        public static void XSide(Span<ulong> result, ReadOnlySpan<ulong> x)
        {
            ModSquare(result, x);                                // r = x^2
            ModMult(result, result, x);                          // r = x^3
            VLI.ModAdd(result, result, b, p, NUM_BITS / VLI.WORD_BITS); // r = x^3 + b
        }

        public static void ModSquare(Span<ulong> result, ReadOnlySpan<ulong> left)
        {
            Span<ulong> product = stackalloc ulong[2 * VLI.ECC_MAX_WORDS];
            int num_words = NUM_BITS / VLI.WORD_BITS;
            VLI.Square(product, left, num_words);
            //VLI_Arithmetic.MMod(result, product, Constants.p, num_words);
            MMod(result, product);
        }

        public static void ModMult(Span<ulong> result, Span<ulong> left, ReadOnlySpan<ulong> right)
        {
            Span<ulong> product = stackalloc ulong[2 * VLI.ECC_MAX_WORDS];
            int num_words = NUM_BITS / VLI.WORD_BITS;
            VLI.Mult(product, left, right, num_words);
            // VLI_Arithmetic.MMod(result, product, Constants.p, num_words);
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
            int num_words = NUM_BITS / VLI.WORD_BITS;

            // t1 = X, t2 = Y, t3 = Z
            Span<ulong> t4 = stackalloc ulong[num_words];
            Span<ulong> t5 = stackalloc ulong[num_words];

            if (VLI.IsZero(Z1, num_words))
            {
                return;
            }

            ModSquare(t5, Y1);   // t5 = y1^2
            ModMult(t4, X1, t5); // t4 = x1*y1^2 = A
            ModSquare(X1, X1);   // t1 = x1^2 
            ModSquare(t5, t5);   // t5 = y1^4 
            ModMult(Z1, Y1, Z1); // t3 = y1*z1 = z3 

            VLI.ModAdd(Y1, X1, X1, p, num_words); // t2 = 2*x1^2
            VLI.ModAdd(Y1, Y1, X1, p, num_words); // t2 = 3*x1^2
            if (VLI.TestBit(Y1, 0))
            {
                ulong carry = VLI.Add(Y1, Y1, p, num_words);
                VLI.RShift1(Y1, num_words);
                Y1[num_words - 1] |= carry << VLI.WORD_BITS - 1;
            }
            else
            {
                VLI.RShift1(Y1, num_words);
            }
            // t2 = 3/2*(x1^2) = B

            ModSquare(X1, Y1);                     // t1 = B^2
            VLI.ModSub(X1, X1, t4, p, num_words); // t1 = B^2 - A
            VLI.ModSub(X1, X1, t4, p, num_words); // t1 = B^2 - 2A = x3

            VLI.ModSub(t4, t4, X1, p, num_words); // t4 = A - x3
            ModMult(Y1, Y1, t4);                   // t2 = B * (A - x3)
            VLI.ModSub(Y1, Y1, t5, p, num_words); // t2 = B * (A - x3) - y1^4 = y3
        }

        private static void MMod(Span<ulong> result, Span<ulong> product)
        {
            Span<ulong> tmp = stackalloc ulong[2 * VLI.ECC_MAX_WORDS];
            ulong carry;

            int num_words = NUM_BITS / VLI.WORD_BITS;

            VLI.Clear(tmp, num_words);
            VLI.Clear(tmp.Slice(num_words), num_words);

            OmegaMult(tmp, product.Slice(num_words)); // (Rq, q) = q * c

            carry = VLI.Add(result, product, tmp, num_words); // (C, r) = r + q
            VLI.Clear(product, num_words);
            OmegaMult(product, tmp.Slice(num_words)); // Rq*c
            carry += VLI.Add(result, result, product, num_words); // (C1, r) = r + Rq*c

            while (carry > 0)
            {
                --carry;
                VLI.Sub(result, result, p, num_words);
            }
            if (VLI.VarTimeCmp(result, p, num_words) > 0)
            {
                VLI.Sub(result, result, p, num_words);
            }
        }

        private static void OmegaMult(Span<ulong> result, ReadOnlySpan<ulong> right)
        {
            ulong r0 = 0;
            ulong r1 = 0;
            ulong r2 = 0;
            int k;

            int num_words = NUM_BITS / VLI.WORD_BITS;

            /* Multiply by (2^32 + 2^9 + 2^8 + 2^7 + 2^6 + 2^4 + 1). */
            for (k = 0; k < num_words; ++k)
            {
                VLI.muladd(0x1000003D1, right[k], ref r0, ref r1, ref r2);
                result[k] = r0;
                r0 = r1;
                r1 = r2;
                r2 = 0;
            }
            result[num_words] = r0;
        }
    }
}

