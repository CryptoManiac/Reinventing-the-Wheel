using System;
using System.Drawing;
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
        public static bool IsValid(ReadOnlySpan<ulong> point) {

            const int num_words = Constants.NUM_WORDS;
            Span<ulong> tmp1 = stackalloc ulong[num_words];
            Span<ulong> tmp2 = stackalloc ulong[num_words];

            // The point at infinity is invalid.
            if (IsZero(point)) {
                return false;
            }

            // x and y must be smaller than p.
            if (VLI_Logic.CmpUnsafe(Constants.p, point, num_words) != 1 || VLI_Logic.CmpUnsafe(Constants.p, point.Slice(num_words), num_words) != 1) {
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
        public static void PointAdd(Span<ulong> R, Span<ulong> input_P, ReadOnlySpan<ulong> input_Q) {
            const int num_words = Constants.NUM_WORDS;
            Span<ulong> P = stackalloc ulong[num_words];
            Span<ulong> Q = stackalloc ulong[num_words];
            Span<ulong> z = stackalloc ulong[num_words];

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
        public static void PointMul(Span<ulong> result, ReadOnlySpan<ulong> point, ReadOnlySpan<ulong> scalar) {
            const int num_words = Constants.NUM_WORDS;
            Span<ulong> tmp1 = stackalloc ulong[num_words];
            Span<ulong> tmp2 = stackalloc ulong[num_words];
            VLI_Common.Picker<ulong> p2 = new(tmp1, tmp2);
            ulong carry = ECCUtil.regularize_k(scalar, tmp1, tmp2);
            PointMul(result, point, p2[VLI_Logic.ZeroIfNotZero(carry)], Constants.NUM_N_BITS + 1);
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
            const int num_words = Constants.NUM_WORDS;

            // R0 and R1
            VLI_Common.Picker<ulong> Rx = new(stackalloc ulong[num_words], stackalloc ulong[num_words]);
            VLI_Common.Picker<ulong> Ry = new(stackalloc ulong[num_words], stackalloc ulong[num_words]);
            Span<ulong> z = stackalloc ulong[num_words];

            int i;
            ulong nb;

            VLI_Arithmetic.Set(Rx[1], point, num_words);
            VLI_Arithmetic.Set(Ry[1], point.Slice(num_words), num_words);

            ECCUtil.XYcZ_initial_double(Rx[1], Ry[1], Rx[0], Ry[0], initial_Z);

            for (i = num_bits - 2; i > 0; --i)
            {
                nb = VLI_Logic.OneIfFalse(VLI_Logic.TestBit(scalar, i));
                ECCUtil.XYcZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);
                ECCUtil.XYcZ_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);
            }

            nb = VLI_Logic.OneIfFalse(VLI_Logic.TestBit(scalar, 0));
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
            const int num_words = Constants.NUM_WORDS;

            // R0 and R1
            VLI_Common.Picker<ulong> Rx = new(stackalloc ulong[num_words], stackalloc ulong[num_words]);
            VLI_Common.Picker<ulong> Ry = new(stackalloc ulong[num_words], stackalloc ulong[num_words]);
            Span<ulong> z = stackalloc ulong[num_words];

            int i;
            ulong nb;

            VLI_Arithmetic.Set(Rx[1], point, num_words);
            VLI_Arithmetic.Set(Ry[1], point.Slice(num_words), num_words);

            ECCUtil.XYcZ_double(Rx[1], Ry[1], Rx[0], Ry[0]);

            for (i = num_bits - 2; i > 0; --i)
            {
                nb = VLI_Logic.OneIfFalse(VLI_Logic.TestBit(scalar, i));
                ECCUtil.XYcZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);
                ECCUtil.XYcZ_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);
            }

            nb = VLI_Logic.OneIfFalse(VLI_Logic.TestBit(scalar, 0));
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
    }
}
