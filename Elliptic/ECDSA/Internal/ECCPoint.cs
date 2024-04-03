using System.Drawing;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Channels;
using Wheel.Crypto.Elliptic.EllipticCommon;
using Wheel.Crypto.Elliptic.EllipticCommon.VeryLongInt;

namespace Wheel.Crypto.Elliptic.ECDSA
{
    /// <summary>
    /// Elliptic Curve point operations
    /// </summary>
    public readonly partial struct ECCurve
    {
        /// <summary>
        /// Returns 1 if 'point' is the point at infinity, 0 otherwise.
        /// </summary>
        /// <param name="point"></param>
        /// <returns></returns>
        internal bool IsZeroPoint(ReadOnlySpan<ulong> point)
        {
            return VLI.IsZero(point, 2 * NUM_WORDS);
        }

        /// <summary>
        /// Check that point is not an infinity and that it actually exists
        /// </summary>
        /// <param name="point"></param>
        /// <returns></returns>
        [SkipLocalsInit]
        internal bool IsValidPoint(ReadOnlySpan<ulong> point)
        {
            Span<ulong> tmp1 = stackalloc ulong[NUM_WORDS];
            Span<ulong> tmp2 = stackalloc ulong[NUM_WORDS];

            // The point at infinity is invalid.
            if (IsZeroPoint(point))
            {
                return false;
            }

            // x and y must be smaller than p.
            if (VLI.VarTimeCmp(P, point, NUM_WORDS) != 1 || VLI.VarTimeCmp(P, point.Slice(NUM_WORDS), NUM_WORDS) != 1)
            {
                return false;
            }

            ModSquare(tmp1, point.Slice(NUM_WORDS));
            XSide(tmp2, point); // tmp2 = x^3 + ax + b

            // Make sure that y^2 == x^3 + ax + b
            return VLI.Equal(tmp1, tmp2, NUM_WORDS);
        }

        /// <summary>
        /// ECC Point Addition R = P + Q
        /// </summary>
        /// <param name="R"></param>
        /// <param name="input_P"></param>
        /// <param name="input_Q"></param>
        [SkipLocalsInit]
        internal void PointAdd(Span<ulong> R, Span<ulong> input_P, ReadOnlySpan<ulong> input_Q)
        {
            Span<ulong> P = stackalloc ulong[NUM_WORDS * 2];
            Span<ulong> Q = stackalloc ulong[NUM_WORDS * 2];
            Span<ulong> z = stackalloc ulong[NUM_WORDS];

            VLI.Set(P, input_P, NUM_WORDS);
            VLI.Set(P.Slice(NUM_WORDS), input_P.Slice(NUM_WORDS), NUM_WORDS);
            VLI.Set(Q, input_Q, NUM_WORDS);
            VLI.Set(Q.Slice(NUM_WORDS), input_Q.Slice(NUM_WORDS), NUM_WORDS);

            XYcZ_Add(P, P.Slice(NUM_WORDS), Q, Q.Slice(NUM_WORDS));

            // Find final 1/Z value.
            ModMult(z, input_P, P.Slice(NUM_WORDS));
            VLI.ModInv(z, z, P, NUM_WORDS);
            ModMult(z, z, P);
            ModMult(z, z, input_P.Slice(NUM_WORDS));

            // End 1/Z calculation

            ApplyZ(Q, Q.Slice(NUM_WORDS), z);

            VLI.Set(R, Q, NUM_WORDS);
            VLI.Set(R.Slice(NUM_WORDS), Q.Slice(NUM_WORDS), NUM_WORDS);
        }

        /// <summary>
        /// ECC Point multiplication by scalar
        /// </summary>
        /// <param name="result"></param>
        /// <param name="point"></param>
        /// <param name="scalar"></param>
        /// <param name="initial_Z"></param>
        /// <param name="num_bits"></param>
        [SkipLocalsInit]
        internal void PointMul(Span<ulong> result, ReadOnlySpan<ulong> point, ReadOnlySpan<ulong> scalar, ReadOnlySpan<ulong> initial_Z, int num_bits)
        {
            // R0 and R1
            VLI.Picker Rx = new(stackalloc ulong[NUM_WORDS], stackalloc ulong[NUM_WORDS]);
            VLI.Picker Ry = new(stackalloc ulong[NUM_WORDS], stackalloc ulong[NUM_WORDS]);
            Span<ulong> z = stackalloc ulong[NUM_WORDS];

            ulong nb;

            VLI.Set(Rx[1], point, NUM_WORDS);
            VLI.Set(Ry[1], point.Slice(NUM_WORDS), NUM_WORDS);

            XYcZ_Initial_Double(Rx[1], Ry[1], Rx[0], Ry[0], initial_Z);

            for (int i = num_bits - 2; i > 0; --i)
            {
                nb = Convert.ToUInt64(!VLI.TestBit(scalar, i));
                XYcZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);
                XYcZ_Add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);
            }

            nb = Convert.ToUInt64(!VLI.TestBit(scalar, 0));
            XYcZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);

            // Find final 1/Z value.
            VLI.ModSub(z, Rx[1], Rx[0], P, NUM_WORDS); // X1 - X0
            ModMult(z, z, Ry[1 - nb]);               // Yb * (X1 - X0)
            ModMult(z, z, point);                    // xP * Yb * (X1 - X0)

            VLI.ModInv(z, z, P, NUM_WORDS);            // 1 / (xP * Yb * (X1 - X0))
                                                             // yP / (xP * Yb * (X1 - X0))
            ModMult(z, z, point.Slice(NUM_WORDS));
            ModMult(z, z, Rx[1 - nb]); // Xb * yP / (xP * Yb * (X1 - X0))

            // End 1/Z calculation
            XYcZ_Add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);
            ApplyZ(Rx[0], Ry[0], z);

            VLI.Set(result, Rx[0], NUM_WORDS);
            VLI.Set(result.Slice(NUM_WORDS), Ry[0], NUM_WORDS);
        }

        /// <summary>
        /// Compute the corresponding public key for a private key.
        /// </summary>
        /// <param name="result">Will be filled in with the corresponding public key</param>
        /// <param name="private_key"> The private key to compute the public key for</param>
        /// <returns>True if the key was computed successfully, False if an error occurred.</returns>
        [SkipLocalsInit]
        internal bool ComputePublicPoint(Span<ulong> result, ReadOnlySpan<ulong> private_key)
        {
            Span<ulong> tmp1 = stackalloc ulong[NUM_WORDS];
            Span<ulong> tmp2 = stackalloc ulong[NUM_WORDS];
            VLI.Picker p2 = new(tmp1, tmp2);

            ulong carry;

            // Regularize the bitcount for the private key so that attackers cannot use a side channel
            //  attack to learn the number of leading zeros.
            carry = RegularizeK(private_key, tmp1, tmp2);

            // Get a random initial Z value to improve
            //  protection against side channel attacks.
            GenerateRandomSecret(p2[carry], MemoryMarshal.Cast<ulong, byte>(private_key));

            PointMul(result, G, p2[!Convert.ToBoolean(carry)], p2[carry], NUM_N_BITS + 1);

            // Final validation of computed value
            return !IsZeroPoint(result);
        }

    }
}
