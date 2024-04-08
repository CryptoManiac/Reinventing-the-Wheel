using System;
using System.Runtime.CompilerServices;
using Wheel.Crypto.Elliptic.EllipticCommon;

namespace Wheel.Crypto.Elliptic.EdDSA.Internal.GroupElement;

internal static class GEMath
{
    #region Scalarmults

    private const int S1_SWINDOWSIZE = 5;
    private const int S1_TABLE_SIZE = (1 << (S1_SWINDOWSIZE - 2));
    private const int S2_SWINDOWSIZE = 7;
    private const int S2_TABLE_SIZE = (1 << (S2_SWINDOWSIZE - 2));

    /* computes [s1]p1 + [s2]basepoint */
    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ge25519_double_scalarmult_vartime(ref GE25519 r, in GE25519 p1, ReadOnlySpan<ulong> s1, ReadOnlySpan<ulong> s2)
    {

        Span<sbyte> slide1 = stackalloc sbyte[256];
        Span<sbyte> slide2 = stackalloc sbyte[256];

        Span<GE25519_PNIELS> pre1 = stackalloc GE25519_PNIELS[S1_TABLE_SIZE];

        GE25519 d1;
        GE25519_P1P1 t;

        int i;

        ModM.contract256_slidingwindow(slide1, s1, S1_SWINDOWSIZE);
        ModM.contract256_slidingwindow(slide2, s2, S2_SWINDOWSIZE);

        d1.ge25519_double(p1);
        pre1[0].ge25519_full_to_pniels(p1);
        for (i = 0; i < S1_TABLE_SIZE - 1; i++)
        {
            pre1[i + 1].ge25519_pnielsadd(d1, pre1[i]);
        }

        // set neutral
        r.ge25519_set_neutral();

        i = 255;
        while ((i >= 0) && !Convert.ToBoolean(slide1[i] | slide2[i]))
        {
            i--;
        }

        for (; i >= 0; i--)
        {
            t.ge25519_double_p1p1(r);

            if (Convert.ToBoolean(slide1[i]))
            {
                r.ge25519_p1p1_to_full(t);
                t.ge25519_pnielsadd_p1p1(r, pre1[Math.Abs(slide1[i]) / 2], (byte)slide1[i] >> 7);
            }

            if (Convert.ToBoolean(slide2[i]))
            {
                r.ge25519_p1p1_to_full(t);
                t.ge25519_nielsadd2_p1p1(r, Curve25519.tables.NIELS_Sliding_Multiples[Math.Abs(slide2[i]) / 2], (byte)slide2[i] >> 7);
            }

            r.ge25519_p1p1_to_partial(t);
        }
    }

    /// <summary>
    /// computes [s1]p1
    /// WARNING: This function IS NOT timing-secure
    /// </summary>
    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ge25519_scalarmult_vartime(ref GE25519 r, in GE25519 p1, ReadOnlySpan<ulong> s1)
    {

        Span<sbyte> slide1 = stackalloc sbyte[256];
        Span<GE25519_PNIELS> pre1 = stackalloc GE25519_PNIELS[S1_TABLE_SIZE];
        GE25519 d1;
        GE25519_P1P1 t;
        int i;

        ModM.contract256_slidingwindow(slide1, s1, S1_SWINDOWSIZE);

        d1.ge25519_double(p1);
        pre1[0].ge25519_full_to_pniels(p1);

        for (i = 0; i < S1_TABLE_SIZE - 1; i++)
        {
            pre1[i + 1].ge25519_pnielsadd(d1, pre1[i]);
        }

        // set neutral
        r.ge25519_set_neutral();

        i = 255;
        while ((i >= 0) && !Convert.ToBoolean(slide1[i]))
        {
            i--;
        }

        for (; i >= 0; i--)
        {
            t.ge25519_double_p1p1(r);

            if (Convert.ToBoolean(slide1[i]))
            {
                r.ge25519_p1p1_to_full(t);
                t.ge25519_pnielsadd_p1p1(r, pre1[Math.Abs(slide1[i]) / 2], (byte)slide1[i] >> 7);
            }

            r.ge25519_p1p1_to_partial(t);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint ge25519_windowb_equal(uint b, uint c)
    {
        return ((b ^ c) - 1) >> 31;
    }

    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ge25519_scalarmult_base_choose_niels(ref GE25519_NIELS t, ReadOnlySpan<GE25519_NIELS_Packed> table, int pos, int b)
    {

        Span<ulong> neg = stackalloc ulong[ModM.ModM_WORDS];

        uint sign = (uint)((byte)b >> 7);
        uint mask = ~(sign - 1);
        uint u = (uint)((b + mask) ^ mask);

        GE25519_NIELS_Packed packed;

        // Init to zero
        packed.ALL.Clear();

        /* initialize to ysubx = 1, xaddy = 1, t2d = 0 */
        packed.YsubX[0] = 1;
        packed.XaddY[0] = 1;

        for (int i = 0; i < 8; i++)
        {
            Curve25519.Move_conditional_bytes(packed.ALL, table[(pos * 8) + i].ALL, ge25519_windowb_equal(u, (uint)i + 1));
        }

        /* expand in to t */
        Curve25519.Expand(t.YsubX, packed.YsubX);
        Curve25519.Expand(t.XaddY, packed.XaddY);
        Curve25519.Expand(t.T2D, packed.T2D);

        /* adjust for sign */
        Curve25519.Swap_conditional(t.YsubX, t.XaddY, sign);
        Curve25519.Neg(neg, t.T2D);
        Curve25519.Swap_conditional(t.T2D, neg, sign);
    }

    /* computes [s]basepoint */
    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ge25519_scalarmult_base_niels(ref GE25519 r, ReadOnlySpan<GE25519_NIELS_Packed> basepoint_table, ReadOnlySpan<ulong> s)
    {

        Span<sbyte> b = stackalloc sbyte[64];

        GE25519_NIELS t;
        ModM.contract256_window4(b, s);

        ge25519_scalarmult_base_choose_niels(ref t, basepoint_table, 0, b[1]);
        Curve25519.Sub_reduce(r.X, t.XaddY, t.YsubX);
        Curve25519.Add_reduce(r.Y, t.XaddY, t.YsubX);
        r.Z.Clear();
        Curve25519.Copy(r.T, t.T2D);
        r.Z[0] = 2;

        for (int i = 3; i < 64; i += 2)
        {
            ge25519_scalarmult_base_choose_niels(ref t, basepoint_table, i / 2, b[i]);
            r.ge25519_nielsadd2(t);
        }

        r.ge25519_double_partial(r);
        r.ge25519_double_partial(r);
        r.ge25519_double_partial(r);
        r.ge25519_double(r);
        ge25519_scalarmult_base_choose_niels(ref t, basepoint_table, 0, b[0]);
        Curve25519.Mul(t.T2D, t.T2D, Curve25519.tables.ECD);
        r.ge25519_nielsadd2(t);
        for (int i = 2; i < 64; i += 2)
        {
            ge25519_scalarmult_base_choose_niels(ref t, basepoint_table, i / 2, b[i]);
            r.ge25519_nielsadd2(t);
        }
    }

    #endregion
}

