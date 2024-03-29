using Wheel.Crypto.Elliptic.Internal.VeryLongInt;

namespace Wheel.Crypto.Elliptic.Internal
{
    /// <summary>
    /// Elliptic Curve point operations
    /// </summary>
    internal static class ECCPoint
    {
        /// <summary>
        /// Returns 1 if 'point' is the point at infinity, 0 otherwise.
        /// </summary>
        /// <param name="point"></param>
        /// <returns></returns>
        public static bool IsZero(ECCurve curve, ReadOnlySpan<ulong> point)
        {
            return VLI.IsZero(point, 2 * curve.NUM_WORDS);
        }

        /// <summary>
        /// Check that point is not an infinity and that it actually exists
        /// </summary>
        /// <param name="point"></param>
        /// <returns></returns>
        public static bool IsValid(ECCurve curve, ReadOnlySpan<ulong> point)
        {
            Span<ulong> tmp1 = stackalloc ulong[VLI.ECC_MAX_WORDS];
            Span<ulong> tmp2 = stackalloc ulong[VLI.ECC_MAX_WORDS];
            int num_words = curve.NUM_WORDS;

            // The point at infinity is invalid.
            if (IsZero(curve, point))
            {
                return false;
            }

            // x and y must be smaller than p.
            if (VLI.VarTimeCmp(curve.p, point, num_words) != 1 || VLI.VarTimeCmp(curve.p, point.Slice(num_words), num_words) != 1)
            {
                return false;
            }

            curve.ModSquare(tmp1, point.Slice(num_words));
            curve.XSide(tmp2, point); // tmp2 = x^3 + ax + b

            // Make sure that y^2 == x^3 + ax + b
            return VLI.Equal(tmp1, tmp2, num_words);
        }

        /// <summary>
        /// ECC Point Addition R = P + Q
        /// </summary>
        /// <param name="R"></param>
        /// <param name="input_P"></param>
        /// <param name="input_Q"></param>
        public static void PointAdd(ECCurve curve, Span<ulong> R, Span<ulong> input_P, ReadOnlySpan<ulong> input_Q)
        {
            Span<ulong> P = stackalloc ulong[VLI.ECC_MAX_WORDS * 2];
            Span<ulong> Q = stackalloc ulong[VLI.ECC_MAX_WORDS * 2];
            Span<ulong> z = stackalloc ulong[VLI.ECC_MAX_WORDS];

            int num_words = curve.NUM_WORDS;

            VLI.Set(P, input_P, num_words);
            VLI.Set(P.Slice(num_words), input_P.Slice(num_words), num_words);
            VLI.Set(Q, input_Q, num_words);
            VLI.Set(Q.Slice(num_words), input_Q.Slice(num_words), num_words);

            ECCUtil.XYcZ_Add(curve, P, P.Slice(num_words), Q, Q.Slice(num_words));

            // Find final 1/Z value.
            curve.ModMult(z, input_P, P.Slice(num_words));
            VLI.ModInv(z, z, curve.p, num_words);
            curve.ModMult(z, z, P);
            curve.ModMult(z, z, input_P.Slice(num_words));

            // End 1/Z calculation

            ECCUtil.ApplyZ(curve, Q, Q.Slice(num_words), z);

            VLI.Set(R, Q, num_words);
            VLI.Set(R.Slice(num_words), Q.Slice(num_words), num_words);
        }

        /// <summary>
        /// ECC Point multiplication by scalar
        /// </summary>
        /// <param name="result"></param>
        /// <param name="point"></param>
        /// <param name="scalar"></param>
        public static void PointMul(ECCurve curve, Span<ulong> result, ReadOnlySpan<ulong> point, ReadOnlySpan<ulong> scalar)
        {
            Span<ulong> tmp1 = stackalloc ulong[VLI.ECC_MAX_WORDS];
            Span<ulong> tmp2 = stackalloc ulong[VLI.ECC_MAX_WORDS];
            VLI.Picker p2 = new(tmp1, tmp2);
            ulong carry = ECCUtil.RegularizeK(curve, scalar, tmp1, tmp2);
            PointMul(curve, result, point, p2[!Convert.ToBoolean(carry)], curve.NUM_N_BITS + 1);
        }

        /// <summary>
        /// ECC Point multiplication by scalar
        /// </summary>
        /// <param name="result"></param>
        /// <param name="point"></param>
        /// <param name="scalar"></param>
        /// <param name="initial_Z"></param>
        /// <param name="num_bits"></param>
        public static void PointMul(ECCurve curve, Span<ulong> result, ReadOnlySpan<ulong> point, ReadOnlySpan<ulong> scalar, ReadOnlySpan<ulong> initial_Z, int num_bits)
        {
            // R0 and R1
            VLI.Picker Rx = new(stackalloc ulong[VLI.ECC_MAX_WORDS], stackalloc ulong[VLI.ECC_MAX_WORDS]);
            VLI.Picker Ry = new(stackalloc ulong[VLI.ECC_MAX_WORDS], stackalloc ulong[VLI.ECC_MAX_WORDS]);
            Span<ulong> z = stackalloc ulong[VLI.ECC_MAX_WORDS];

            int num_words = curve.NUM_WORDS;
            int i;
            ulong nb;

            VLI.Set(Rx[1], point, num_words);
            VLI.Set(Ry[1], point.Slice(num_words), num_words);

            ECCUtil.XYcZ_Initial_Double(curve, Rx[1], Ry[1], Rx[0], Ry[0], initial_Z);

            for (i = num_bits - 2; i > 0; --i)
            {
                nb = Convert.ToUInt64(!VLI.TestBit(scalar, i));
                ECCUtil.XYcZ_addC(curve, Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);
                ECCUtil.XYcZ_Add(curve, Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);
            }

            nb = Convert.ToUInt64(!VLI.TestBit(scalar, 0));
            ECCUtil.XYcZ_addC(curve, Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);

            // Find final 1/Z value.
            VLI.ModSub(z, Rx[1], Rx[0], curve.p, num_words); // X1 - X0
            curve.ModMult(z, z, Ry[1 - nb]);               // Yb * (X1 - X0)
            curve.ModMult(z, z, point);                    // xP * Yb * (X1 - X0)

            VLI.ModInv(z, z, curve.p, num_words);            // 1 / (xP * Yb * (X1 - X0))
                                                             // yP / (xP * Yb * (X1 - X0))
            curve.ModMult(z, z, point.Slice(num_words));
            curve.ModMult(z, z, Rx[1 - nb]); // Xb * yP / (xP * Yb * (X1 - X0))

            // End 1/Z calculation
            ECCUtil.XYcZ_Add(curve, Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);
            ECCUtil.ApplyZ(curve, Rx[0], Ry[0], z);

            VLI.Set(result, Rx[0], num_words);
            VLI.Set(result.Slice(num_words), Ry[0], num_words);
        }

        /// <summary>
        /// ECC Point multiplication by scalar
        /// </summary>
        /// <param name="result"></param>
        /// <param name="point"></param>
        /// <param name="scalar"></param>
        /// <param name="initial_Z"></param>
        /// <param name="num_bits"></param>
        public static void PointMul(ECCurve curve, Span<ulong> result, ReadOnlySpan<ulong> point, ReadOnlySpan<ulong> scalar, int num_bits)
        {
            // R0 and R1
            VLI.Picker Rx = new(stackalloc ulong[VLI.ECC_MAX_WORDS], stackalloc ulong[VLI.ECC_MAX_WORDS]);
            VLI.Picker Ry = new(stackalloc ulong[VLI.ECC_MAX_WORDS], stackalloc ulong[VLI.ECC_MAX_WORDS]);
            Span<ulong> z = stackalloc ulong[VLI.ECC_MAX_WORDS];

            int num_words = curve.NUM_WORDS;

            int i;
            ulong nb;

            VLI.Set(Rx[1], point, num_words);
            VLI.Set(Ry[1], point.Slice(num_words), num_words);

            ECCUtil.XYcZ_Double(curve, Rx[1], Ry[1], Rx[0], Ry[0]);

            for (i = num_bits - 2; i > 0; --i)
            {
                nb = Convert.ToUInt64(!VLI.TestBit(scalar, i));
                ECCUtil.XYcZ_addC(curve, Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);
                ECCUtil.XYcZ_Add(curve, Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);
            }

            nb = Convert.ToUInt64(!VLI.TestBit(scalar, 0));
            ECCUtil.XYcZ_addC(curve, Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);

            // Find final 1/Z value.
            VLI.ModSub(z, Rx[1], Rx[0], curve.p, num_words); // X1 - X0
            curve.ModMult(z, z, Ry[1 - nb]);               // Yb * (X1 - X0)
            curve.ModMult(z, z, point);                    // xP * Yb * (X1 - X0)

            VLI.ModInv(z, z, curve.p, num_words);            // 1 / (xP * Yb * (X1 - X0))
                                                             // yP / (xP * Yb * (X1 - X0))
            curve.ModMult(z, z, point.Slice(num_words));
            curve.ModMult(z, z, Rx[1 - nb]); // Xb * yP / (xP * Yb * (X1 - X0))

            /* End 1/Z calculation */

            ECCUtil.XYcZ_Add(curve, Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);
            ECCUtil.ApplyZ(curve, Rx[0], Ry[0], z);

            VLI.Set(result, Rx[0], num_words);
            VLI.Set(result.Slice(num_words), Ry[0], num_words);
        }

        /// <summary>
        /// Compute the corresponding public key for a private key.
        /// </summary>
        /// <param name="result">Will be filled in with the corresponding public key</param>
        /// <param name="private_key"> The private key to compute the public key for</param>
        /// <returns>True if the key was computed successfully, False if an error occurred.</returns>
        public static bool ComputePublicPoint(ECCurve curve, Span<ulong> result, ReadOnlySpan<ulong> private_key)
        {
            Span<ulong> tmp1 = stackalloc ulong[VLI.ECC_MAX_WORDS];
            Span<ulong> tmp2 = stackalloc ulong[VLI.ECC_MAX_WORDS];
            VLI.Picker p2 = new(tmp1, tmp2);

            ulong carry;

            // Regularize the bitcount for the private key so that attackers cannot use a side channel
            //  attack to learn the number of leading zeros.
            carry = ECCUtil.RegularizeK(curve, private_key, tmp1, tmp2);

            PointMul(curve, result, curve.G, p2[!Convert.ToBoolean(carry)], curve.NUM_N_BITS + 1);

            // Final validation of computed value
            return !IsZero(curve, result);
        }

    }
}
