using Wheel.Crypto.Elliptic.EllipticCommon.VeryLongInt;

namespace Wheel.Crypto.Elliptic.ECDSA
{
    /// <summary>
    /// SECP256K1 specific implementations
    /// </summary>
    public readonly partial struct ECCurve
    {
        /// <summary>
        /// Computes result = x^3 + b. result must not overlap x.
        /// </summary>
        /// <param name="result"></param>
        /// <param name="x"></param>
        public static void XSide_SECP256K1(in ECCurve curve, Span<ulong> result, ReadOnlySpan<ulong> x)
        {
            curve.ModSquare(result, x);                                // r = x^2
            curve.ModMult(result, result, x);                          // r = x^3
            VLI.ModAdd(result, result, curve.b, curve.p, curve.NUM_WORDS); // r = x^3 + b
        }

        /// <summary>
        /// Double in place
        /// </summary>
        /// <param name="X1"></param>
        /// <param name="Y1"></param>
        /// <param name="Z1"></param>
        public static void DoubleJacobian_SECP256K1(in ECCurve curve, Span<ulong> X1, Span<ulong> Y1, Span<ulong> Z1)
        {
            int num_words = curve.NUM_WORDS;

            // t1 = X, t2 = Y, t3 = Z
            Span<ulong> t4 = stackalloc ulong[num_words];
            Span<ulong> t5 = stackalloc ulong[num_words];
            ReadOnlySpan<ulong> p = curve.p;

            if (VLI.IsZero(Z1, num_words))
            {
                return;
            }

            curve.ModSquare(t5, Y1);   // t5 = y1^2
            curve.ModMult(t4, X1, t5); // t4 = x1*y1^2 = A
            curve.ModSquare(X1, X1);   // t1 = x1^2 
            curve.ModSquare(t5, t5);   // t5 = y1^4 
            curve.ModMult(Z1, Y1, Z1); // t3 = y1*z1 = z3 

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

            curve.ModSquare(X1, Y1);                     // t1 = B^2
            VLI.ModSub(X1, X1, t4, p, num_words); // t1 = B^2 - A
            VLI.ModSub(X1, X1, t4, p, num_words); // t1 = B^2 - 2A = x3

            VLI.ModSub(t4, t4, X1, p, num_words); // t4 = A - x3
            curve.ModMult(Y1, Y1, t4);                   // t2 = B * (A - x3)
            VLI.ModSub(Y1, Y1, t5, p, num_words); // t2 = B * (A - x3) - y1^4 = y3
        }

        /// <summary>
        /// Computes result = product % p
        /// </summary>
        public static void MMod_SECP256K1(in ECCurve curve, Span<ulong> result, Span<ulong> product)
        {
            int num_words = curve.NUM_WORDS;
            ReadOnlySpan<ulong> p = curve.p;
            Span<ulong> tmp = stackalloc ulong[2 * num_words];
            ulong carry;

            VLI.Clear(tmp, num_words);
            VLI.Clear(tmp.Slice(num_words), num_words);

            OmegaMult(curve, tmp, product.Slice(num_words)); // (Rq, q) = q * c

            carry = VLI.Add(result, product, tmp, num_words); // (C, r) = r + q
            VLI.Clear(product, num_words);
            OmegaMult(curve, product, tmp.Slice(num_words)); // Rq*c
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

        private static void OmegaMult(in ECCurve curve, Span<ulong> result, ReadOnlySpan<ulong> right)
        {
            ulong r0 = 0;
            ulong r1 = 0;
            ulong r2 = 0;

            int num_words = curve.NUM_WORDS;

            // Multiply by (2^32 + 2^9 + 2^8 + 2^7 + 2^6 + 2^4 + 1).
            for (int k = 0; k < num_words; ++k)
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

