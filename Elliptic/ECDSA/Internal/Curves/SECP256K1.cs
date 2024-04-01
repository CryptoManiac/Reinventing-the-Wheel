using Wheel.Crypto.Elliptic.EllipticCommon.VeryLongInt;

namespace Wheel.Crypto.Elliptic.ECDSA
{
    /// <summary>
    /// SECP256K1 specific implementations.
    /// NOTE: These methods are declared static on purpose, it allows us to use their addresses in the curve constructor functions.
    /// </summary>
    public readonly partial struct ECCurve
    {
        /// <summary>
        /// Construct a new instance of the secp256k1 context.
        /// <returns></returns>
        public static unsafe ECCurve Get_SECP256K1()
        {
            return new ECCurve(
                256,
                stackalloc ulong[] { 0xFFFFFFFEFFFFFC2F, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF },
                stackalloc ulong[] { 0xBFD25E8CD0364141, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF },
                stackalloc ulong[] { 0xdfe92f46681b20a0, 0x5d576e7357a4501d, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF },
                stackalloc ulong[] { 0x59F2815B16F81798, 0x029BFCDB2DCE28D9, 0x55A06295CE870B07, 0x79BE667EF9DCBBAC, 0x9C47D08FFB10D4B8, 0xFD17B448A6855419, 0x5DA4FBFC0E1108A8, 0x483ADA7726A3C465 },
                stackalloc ulong[] { 0x0000000000000007, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 },
                &MMod_SECP256K1,
                &XSide_SECP256K1,
                &ModSQRT_Generic,
                &DoubleJacobian_SECP256K1
            );
        }

        /// <summary>
        /// Computes result = x^3 + b. result must not overlap x.
        /// </summary>
        /// <param name="result"></param>
        /// <param name="x"></param>
        public static void XSide_SECP256K1(in ECCurve curve, Span<ulong> result, ReadOnlySpan<ulong> x)
        {
            curve.ModSquare(result, x);                                // r = x^2
            curve.ModMult(result, result, x);                          // r = x^3
            VLI.ModAdd(result, result, curve.B, curve.P, curve.NUM_WORDS); // r = x^3 + b
        }

        /// <summary>
        /// Double in place
        /// </summary>
        /// <param name="X1"></param>
        /// <param name="Y1"></param>
        /// <param name="Z1"></param>
        public static void DoubleJacobian_SECP256K1(in ECCurve curve, Span<ulong> X1, Span<ulong> Y1, Span<ulong> Z1)
        {
            // t1 = X, t2 = Y, t3 = Z
            Span<ulong> t4 = stackalloc ulong[curve.NUM_WORDS];
            Span<ulong> t5 = stackalloc ulong[curve.NUM_WORDS];

            if (VLI.IsZero(Z1, curve.NUM_WORDS))
            {
                return;
            }

            curve.ModSquare(t5, Y1);   // t5 = y1^2
            curve.ModMult(t4, X1, t5); // t4 = x1*y1^2 = A
            curve.ModSquare(X1, X1);   // t1 = x1^2 
            curve.ModSquare(t5, t5);   // t5 = y1^4 
            curve.ModMult(Z1, Y1, Z1); // t3 = y1*z1 = z3 

            VLI.ModAdd(Y1, X1, X1, curve.P, curve.NUM_WORDS); // t2 = 2*x1^2
            VLI.ModAdd(Y1, Y1, X1, curve.P, curve.NUM_WORDS); // t2 = 3*x1^2
            if (VLI.TestBit(Y1, 0))
            {
                ulong carry = VLI.Add(Y1, Y1, curve.P, curve.NUM_WORDS);
                VLI.RShift1(Y1, curve.NUM_WORDS);
                Y1[curve.NUM_WORDS - 1] |= carry << VLI.WORD_BITS - 1;
            }
            else
            {
                VLI.RShift1(Y1, curve.NUM_WORDS);
            }
            // t2 = 3/2*(x1^2) = B

            curve.ModSquare(X1, Y1);                     // t1 = B^2
            VLI.ModSub(X1, X1, t4, curve.P, curve.NUM_WORDS); // t1 = B^2 - A
            VLI.ModSub(X1, X1, t4, curve.P, curve.NUM_WORDS); // t1 = B^2 - 2A = x3

            VLI.ModSub(t4, t4, X1, curve.P, curve.NUM_WORDS); // t4 = A - x3
            curve.ModMult(Y1, Y1, t4);                   // t2 = B * (A - x3)
            VLI.ModSub(Y1, Y1, t5, curve.P, curve.NUM_WORDS); // t2 = B * (A - x3) - y1^4 = y3
        }

        /// <summary>
        /// Computes result = product % p
        /// </summary>
        private static void MMod_SECP256K1(in ECCurve curve, Span<ulong> result, Span<ulong> product)
        {
            Span<ulong> tmp = stackalloc ulong[2 * curve.NUM_WORDS];
            ulong carry;

            VLI.Clear(tmp, curve.NUM_WORDS);
            VLI.Clear(tmp.Slice(curve.NUM_WORDS), curve.NUM_WORDS);

            OmegaMult_SECP256K1(curve, tmp, product.Slice(curve.NUM_WORDS)); // (Rq, q) = q * c

            carry = VLI.Add(result, product, tmp, curve.NUM_WORDS); // (C, r) = r + q
            VLI.Clear(product, curve.NUM_WORDS);
            OmegaMult_SECP256K1(curve, product, tmp.Slice(curve.NUM_WORDS)); // Rq*c
            carry += VLI.Add(result, result, product, curve.NUM_WORDS); // (C1, r) = r + Rq*c

            while (carry > 0)
            {
                --carry;
                VLI.Sub(result, result, curve.P, curve.NUM_WORDS);
            }
            if (VLI.VarTimeCmp(result, curve.P, curve.NUM_WORDS) > 0)
            {
                VLI.Sub(result, result, curve.P, curve.NUM_WORDS);
            }
        }

        private static void OmegaMult_SECP256K1(in ECCurve curve, Span<ulong> result, ReadOnlySpan<ulong> right)
        {
            ulong r0 = 0;
            ulong r1 = 0;
            ulong r2 = 0;

            // Multiply by (2^32 + 2^9 + 2^8 + 2^7 + 2^6 + 2^4 + 1).
            for (int k = 0; k < curve.NUM_WORDS; ++k)
            {
                VLI.muladd(0x1000003D1, right[k], ref r0, ref r1, ref r2);
                result[k] = r0;
                r0 = r1;
                r1 = r2;
                r2 = 0;
            }
            result[curve.NUM_WORDS] = r0;
        }
    }
}

