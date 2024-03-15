using Wheel.Crypto.Elliptic.Internal.VeryLongInt;

namespace Wheel.Crypto.Elliptic.Internal.SECP256K1
{
    /// <summary>
    /// Elliptic Curve point operations
    /// </summary>
    public static class ECCPoint
    {
        /// <summary>
        /// Returns 1 if 'point' is the point at infinity, 0 otherwise.
        /// </summary>
        /// <param name="point"></param>
        /// <returns></returns>
        public static bool IsZero(ReadOnlySpan<ulong> point)
        {
            return VLI_Logic.IsZero(point, 2 * Constants.NUM_WORDS);
        }

        /// <summary>
        /// Check that point is not an infinity and that it actually exists
        /// </summary>
        /// <param name="point"></param>
        /// <returns></returns>
        public static bool IsValid(ReadOnlySpan<ulong> point)
        {
            Span<ulong> tmp1 = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            Span<ulong> tmp2 = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            const int num_words = Constants.NUM_WORDS;

            // The point at infinity is invalid.
            if (IsZero(point))
            {
                return false;
            }

            // x and y must be smaller than p.
            if (VLI_Logic.CmpUnsafe(Constants.p, point, num_words) != 1 || VLI_Logic.CmpUnsafe(Constants.p, point.Slice(num_words), num_words) != 1)
            {
                return false;
            }

            ECCUtil.modSquare_fast(tmp1, point.Slice(num_words));
            ECCUtil.x_side(tmp2, point); // tmp2 = x^3 + ax + b 

            // Make sure that y^2 == x^3 + ax + b
            return VLI_Logic.Equal(tmp1, tmp2, num_words);
        }

        /// <summary>
        /// ECC Point Addition R = P + Q
        /// </summary>
        /// <param name="R"></param>
        /// <param name="input_P"></param>
        /// <param name="input_Q"></param>
        public static void PointAdd(Span<ulong> R, Span<ulong> input_P, ReadOnlySpan<ulong> input_Q)
        {
            Span<ulong> P = stackalloc ulong[VLI_Common.ECC_MAX_WORDS * 2];
            Span<ulong> Q = stackalloc ulong[VLI_Common.ECC_MAX_WORDS * 2];
            Span<ulong> z = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];

            const int num_words = Constants.NUM_WORDS;

            VLI_Arithmetic.Set(P, input_P, num_words);
            VLI_Arithmetic.Set(P.Slice(num_words), input_P.Slice(num_words), num_words);
            VLI_Arithmetic.Set(Q, input_Q, num_words);
            VLI_Arithmetic.Set(Q.Slice(num_words), input_Q.Slice(num_words), num_words);

            ECCUtil.XYcZ_add(P, P.Slice(num_words), Q, Q.Slice(num_words));

            // Find final 1/Z value.
            ECCUtil.modMult_fast(z, input_P, P.Slice(num_words));
            VLI_Arithmetic.ModInv(z, z, Constants.p, num_words);
            ECCUtil.modMult_fast(z, z, P);
            ECCUtil.modMult_fast(z, z, input_P.Slice(num_words));
            // End 1/Z calculation

            ECCUtil.apply_z(Q, Q.Slice(num_words), z);

            VLI_Arithmetic.Set(R, Q, num_words);
            VLI_Arithmetic.Set(R.Slice(num_words), Q.Slice(num_words), num_words);
        }

        /// <summary>
        /// ECC Point multiplication by scalar
        /// </summary>
        /// <param name="result"></param>
        /// <param name="point"></param>
        /// <param name="scalar"></param>
        public static void PointMul(Span<ulong> result, ReadOnlySpan<ulong> point, ReadOnlySpan<ulong> scalar)
        {
            Span<ulong> tmp1 = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            Span<ulong> tmp2 = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            VLI_Common.Picker<ulong> p2 = new(tmp1, tmp2);
            ulong carry = ECCUtil.regularize_k(scalar, tmp1, tmp2);
            PointMul(result, point, p2[Convert.ToUInt64(!Convert.ToBoolean(carry))], Constants.NUM_N_BITS + 1);
        }

        /// <summary>
        /// ECC Point multiplication by scalar
        /// </summary>
        /// <param name="result"></param>
        /// <param name="point"></param>
        /// <param name="scalar"></param>
        /// <param name="initial_Z"></param>
        /// <param name="num_bits"></param>
        public static void PointMul(Span<ulong> result, ReadOnlySpan<ulong> point, ReadOnlySpan<ulong> scalar, ReadOnlySpan<ulong> initial_Z, int num_bits)
        {
            // R0 and R1
            VLI_Common.Picker<ulong> Rx = new(stackalloc ulong[VLI_Common.ECC_MAX_WORDS], stackalloc ulong[VLI_Common.ECC_MAX_WORDS]);
            VLI_Common.Picker<ulong> Ry = new(stackalloc ulong[VLI_Common.ECC_MAX_WORDS], stackalloc ulong[VLI_Common.ECC_MAX_WORDS]);
            Span<ulong> z = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];

            const int num_words = Constants.NUM_WORDS;
            int i;
            ulong nb;

            VLI_Arithmetic.Set(Rx[1], point, num_words);
            VLI_Arithmetic.Set(Ry[1], point.Slice(num_words), num_words);

            ECCUtil.XYcZ_initial_double(Rx[1], Ry[1], Rx[0], Ry[0], initial_Z);

            for (i = num_bits - 2; i > 0; --i)
            {
                nb = Convert.ToUInt64(!VLI_Logic.TestBit(scalar, i));
                ECCUtil.XYcZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);
                ECCUtil.XYcZ_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);
            }

            nb = Convert.ToUInt64(!VLI_Logic.TestBit(scalar, 0));
            ECCUtil.XYcZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);

            // Find final 1/Z value.
            VLI_Arithmetic.ModSub(z, Rx[1], Rx[0], Constants.p, num_words); // X1 - X0
            ECCUtil.modMult_fast(z, z, Ry[1 - nb]);               // Yb * (X1 - X0)
            ECCUtil.modMult_fast(z, z, point);                    // xP * Yb * (X1 - X0)
            VLI_Arithmetic.ModInv(z, z, Constants.p, num_words);            // 1 / (xP * Yb * (X1 - X0))
            // yP / (xP * Yb * (X1 - X0))
            ECCUtil.modMult_fast(z, z, point.Slice(num_words));
            ECCUtil.modMult_fast(z, z, Rx[1 - nb]); // Xb * yP / (xP * Yb * (X1 - X0))
            /* End 1/Z calculation */

            ECCUtil.XYcZ_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);
            ECCUtil.apply_z(Rx[0], Ry[0], z);

            VLI_Arithmetic.Set(result, Rx[0], num_words);
            VLI_Arithmetic.Set(result.Slice(num_words), Ry[0], num_words);
        }

        /// <summary>
        /// ECC Point multiplication by scalar
        /// </summary>
        /// <param name="result"></param>
        /// <param name="point"></param>
        /// <param name="scalar"></param>
        /// <param name="initial_Z"></param>
        /// <param name="num_bits"></param>
        public static void PointMul(Span<ulong> result, ReadOnlySpan<ulong> point, ReadOnlySpan<ulong> scalar, int num_bits)
        {
            // R0 and R1
            VLI_Common.Picker<ulong> Rx = new(stackalloc ulong[VLI_Common.ECC_MAX_WORDS], stackalloc ulong[VLI_Common.ECC_MAX_WORDS]);
            VLI_Common.Picker<ulong> Ry = new(stackalloc ulong[VLI_Common.ECC_MAX_WORDS], stackalloc ulong[VLI_Common.ECC_MAX_WORDS]);
            Span<ulong> z = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];

            const int num_words = Constants.NUM_WORDS;

            int i;
            ulong nb;

            VLI_Arithmetic.Set(Rx[1], point, num_words);
            VLI_Arithmetic.Set(Ry[1], point.Slice(num_words), num_words);

            ECCUtil.XYcZ_double(Rx[1], Ry[1], Rx[0], Ry[0]);

            for (i = num_bits - 2; i > 0; --i)
            {
                nb = Convert.ToUInt64(!VLI_Logic.TestBit(scalar, i));
                ECCUtil.XYcZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);
                ECCUtil.XYcZ_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);
            }

            nb = Convert.ToUInt64(!VLI_Logic.TestBit(scalar, 0));
            ECCUtil.XYcZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);

            // Find final 1/Z value.
            VLI_Arithmetic.ModSub(z, Rx[1], Rx[0], Constants.p, num_words); // X1 - X0
            ECCUtil.modMult_fast(z, z, Ry[1 - nb]);               // Yb * (X1 - X0)
            ECCUtil.modMult_fast(z, z, point);                    // xP * Yb * (X1 - X0)
            VLI_Arithmetic.ModInv(z, z, Constants.p, num_words);            // 1 / (xP * Yb * (X1 - X0))
            // yP / (xP * Yb * (X1 - X0))
            ECCUtil.modMult_fast(z, z, point.Slice(num_words));
            ECCUtil.modMult_fast(z, z, Rx[1 - nb]); // Xb * yP / (xP * Yb * (X1 - X0))
            /* End 1/Z calculation */

            ECCUtil.XYcZ_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);
            ECCUtil.apply_z(Rx[0], Ry[0], z);

            VLI_Arithmetic.Set(result, Rx[0], num_words);
            VLI_Arithmetic.Set(result.Slice(num_words), Ry[0], num_words);
        }

        /// <summary>
        /// Compute the corresponding public key for a private key.
        /// </summary>
        /// <param name="result">Will be filled in with the corresponding public key</param>
        /// <param name="private_key"> The private key to compute the public key for</param>
        /// <returns>True if the key was computed successfully, False if an error occurred.</returns>
        public static bool ComputePublicPoint(Span<ulong> result, ReadOnlySpan<ulong> private_key)
        {
            Span<ulong> tmp1 = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            Span<ulong> tmp2 = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            VLI_Common.Picker<ulong> p2 = new(tmp1, tmp2);

            ulong carry;

            // Regularize the bitcount for the private key so that attackers cannot use a side channel
            //  attack to learn the number of leading zeros.
            carry = ECCUtil.regularize_k(private_key, tmp1, tmp2);

            PointMul(result, Constants.G, p2[Convert.ToUInt64(!Convert.ToBoolean(carry))], Constants.NUM_N_BITS + 1);

            // Final validation of computed value
            return !IsZero(result);
        }

    }
}
