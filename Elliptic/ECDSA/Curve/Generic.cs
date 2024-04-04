using System.Runtime.CompilerServices;
using Wheel.Crypto.Elliptic.ECDSA.Internal;

namespace Wheel.Crypto.Elliptic.ECDSA;

/// <summary>
/// Generic curve arithmetic (shared among some implementations).
/// NOTE: These methods are declared static on purpose, it allows us to use their addresses in the curve constructor functions.
/// </summary>
public readonly partial struct ECCurve
{
    /// <summary>
    /// Double in place
    /// </summary>
    /// <param name="X1"></param>
    /// <param name="Y1"></param>
    /// <param name="Z1"></param>
    [SkipLocalsInit]
    private static void DoubleJacobian_Generic(in ECCurve curve, Span<ulong> X1, Span<ulong> Y1, Span<ulong> Z1)
    {
        // t1 = X, t2 = Y, t3 = Z
        Span<ulong> t4 = stackalloc ulong[curve.NUM_WORDS];
        Span<ulong> t5 = stackalloc ulong[curve.NUM_WORDS];

        if (VLI.IsZero(Z1, curve.NUM_WORDS))
        {
            return;
        }

        curve.ModSquare(t4, Y1);   // t4 = y1^2
        curve.ModMult(t5, X1, t4); // t5 = x1*y1^2 = A
        curve.ModSquare(t4, t4);   // t4 = y1^4 */
        curve.ModMult(Y1, Y1, Z1); // t2 = y1*z1 = z3
        curve.ModSquare(Z1, Z1);   // t3 = z1^2

        VLI.ModAdd(X1, X1, Z1, curve.P, curve.NUM_WORDS); // t1 = x1 + z1^2
        VLI.ModAdd(Z1, Z1, Z1, curve.P, curve.NUM_WORDS); // t3 = 2*z1^2
        VLI.ModSub(Z1, X1, Z1, curve.P, curve.NUM_WORDS); // t3 = x1 - z1^2
        curve.ModMult(X1, X1, Z1);                // t1 = x1^2 - z1^4

        VLI.ModAdd(Z1, X1, X1, curve.P, curve.NUM_WORDS); // t3 = 2*(x1^2 - z1^4)
        VLI.ModAdd(X1, X1, Z1, curve.P, curve.NUM_WORDS); // t1 = 3*(x1^2 - z1^4)
        if (VLI.TestBit(X1, 0))
        {
            ulong l_carry = VLI.Add(X1, X1, curve.P, curve.NUM_WORDS);
            VLI.RShift1(X1, curve.NUM_WORDS);
            X1[curve.NUM_WORDS - 1] |= l_carry << (VLI.WORD_BITS - 1);
        }
        else
        {
            VLI.RShift1(X1, curve.NUM_WORDS);
        }
        // t1 = 3/2*(x1^2 - z1^4) = B

        curve.ModSquare(Z1, X1);                  // t3 = B^2
        VLI.ModSub(Z1, Z1, t5, curve.P, curve.NUM_WORDS); // t3 = B^2 - A
        VLI.ModSub(Z1, Z1, t5, curve.P, curve.NUM_WORDS); // t3 = B^2 - 2A = x3
        VLI.ModSub(t5, t5, Z1, curve.P, curve.NUM_WORDS); // t5 = A - x3
        curve.ModMult(X1, X1, t5);         // t1 = B * (A - x3)
        VLI.ModSub(t4, X1, t4, curve.P, curve.NUM_WORDS); // t4 = B * (A - x3) - y1^4 = y3

        VLI.Set(X1, Z1, curve.NUM_WORDS);
        VLI.Set(Z1, Y1, curve.NUM_WORDS);
        VLI.Set(Y1, t4, curve.NUM_WORDS);
    }

    /// <summary>
    /// Compute a = sqrt(a) (mod curve_p)
    /// </summary>
    /// <param name="a"></param>
    [SkipLocalsInit]
    private static void ModSQRT_Generic(in ECCurve curve, Span<ulong> a)
    {
        Span<ulong> p1 = stackalloc ulong[curve.NUM_WORDS];
        Span<ulong> result = stackalloc ulong[curve.NUM_WORDS];

        VLI.Set(p1, 1, curve.NUM_WORDS);
        VLI.Set(result, 1, curve.NUM_WORDS);

        // When curve.P == 3 (mod 4), we can compute
        //   sqrt(a) = a^((curve.P + 1) / 4) (mod curve.P).

        VLI.Add(p1, curve.P, p1, curve.NUM_WORDS); // p1 = curve.P + 1
        for (int i = VLI.NumBits_VT(p1, curve.NUM_WORDS) - 1; i > 1; --i)
        {
            curve.ModSquare(result, result);
            if (VLI.TestBit(p1, i))
            {
                curve.ModMult(result, result, a);
            }
        }
        VLI.Set(a, result, curve.NUM_WORDS);
    }

    /// <summary>
    /// Computes result = x^3 + b. Result must not overlap x.
    /// </summary>
    /// <param name="result"></param>
    /// <param name="x"></param>
    [SkipLocalsInit]
    private static void XSide_Generic(in ECCurve curve, Span<ulong> result, ReadOnlySpan<ulong> x)
    {
        Span<ulong> _3 = stackalloc ulong[curve.NUM_WORDS];
        VLI.Set(_3, 3, curve.NUM_WORDS); // -a = 3
        curve.ModSquare(result, x);                             // r = x^2
        VLI.ModSub(result, result, _3, curve.P, curve.NUM_WORDS);       // r = x^2 - 3
        curve.ModMult(result, result, x);                     // r = x^3 - 3x
        VLI.ModAdd(result, result, curve.B, curve.P, curve.NUM_WORDS); // r = x^3 - 3x + b
    }
}

