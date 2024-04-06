using System;
using Wheel.Crypto.Elliptic.EdDSA.Internal.Curve25519;
using Wheel.Crypto.Elliptic.EllipticCommon;

namespace Wheel.Crypto.Elliptic.EdDSA.Internal.GroupElement;

internal static class GEMath
{
    public static Tables tables = Tables.Get_Tables();

    #region Conversions
    public static void ge25519_p1p1_to_partial(ref GE25519 r, in GE25519 p)
    {

        EdMath.curve25519_mul(r.X, p.X, p.T);
        EdMath.curve25519_mul(r.Y, p.Y, p.Z);
        EdMath.curve25519_mul(r.Z, p.Z, p.T);
    }

    public static void ge25519_p1p1_to_full(ref GE25519 r, in GE25519 p)
    {
        EdMath.curve25519_mul(r.X, p.X, p.T);
        EdMath.curve25519_mul(r.Y, p.Y, p.Z);
        EdMath.curve25519_mul(r.Z, p.Z, p.T);
        EdMath.curve25519_mul(r.T, p.X, p.Y);
    }

    public static void ge25519_full_to_pniels(ref GE25519_PNIELS p, in GE25519 r)
    {
        EdMath.curve25519_sub(p.YsubX, r.Y, r.X);
        EdMath.curve25519_add(p.XaddY, r.Y, r.X);
        EdMath.curve25519_copy(p.Z, r.Z);
        EdMath.curve25519_mul(p.T2D, r.T, tables.EC2D);
    }
    #endregion

    #region Adding and doubling

    public static void ge25519_add_p1p1(ref GE25519 r, in GE25519 p, in GE25519 q)
    {
        Span<ulong> a = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> b = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> c = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> d = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> t = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> u = stackalloc ulong[ModM.ModM_WORDS];


        EdMath.curve25519_sub(a, p.Y, p.X);
        EdMath.curve25519_add(b, p.Y, p.X);
        EdMath.curve25519_sub(t, q.Y, q.X);
        EdMath.curve25519_add(u, q.Y, q.X);
        EdMath.curve25519_mul(a, a, t);
        EdMath.curve25519_mul(b, b, u);
        EdMath.curve25519_mul(c, p.T, q.T);
        EdMath.curve25519_mul(c, c, tables.EC2D);
        EdMath.curve25519_mul(d, p.Z, q.Z);
        EdMath.curve25519_add(d, d, d);
        EdMath.curve25519_sub(r.X, b, a);
        EdMath.curve25519_add(r.Y, b, a);
        EdMath.curve25519_add_after_basic(r.Z, d, c);
        EdMath.curve25519_sub_after_basic(r.T, d, c);
    }


    public static void ge25519_double_p1p1(ref GE25519 r, in GE25519 p)
    {
        Span<ulong> a = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> b = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> c = stackalloc ulong[ModM.ModM_WORDS];

        EdMath.curve25519_square(a, p.X);
        EdMath.curve25519_square(b, p.Y);
        EdMath.curve25519_square(c, p.Z);
        EdMath.curve25519_add_reduce(c, c, c);
        EdMath.curve25519_add(r.X, p.X, p.Y);
        EdMath.curve25519_square(r.X, r.X);
        EdMath.curve25519_add(r.Y, b, a);
        EdMath.curve25519_sub(r.Z, b, a);
        EdMath.curve25519_sub_after_basic(r.X, r.X, r.Y);
        EdMath.curve25519_sub_after_basic(r.T, c, r.Z);
    }

    public static void ge25519_nielsadd2_p1p1(ref GE25519 r, in GE25519 p, in GE25519_NIELS q, int signbit)
    {
        Picker rb = new(r.Z, r.T);
        ReadOnlyPicker qb = new(q.YsubX, q.XaddY);

        Span<ulong> a = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> b = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> c = stackalloc ulong[ModM.ModM_WORDS];

        EdMath.curve25519_sub(a, p.Y, p.X);
        EdMath.curve25519_add(b, p.Y, p.X);
        EdMath.curve25519_mul(a, a, qb[signbit]); /* x for +, y for - */
        EdMath.curve25519_mul(r.X, b, qb[signbit ^ 1]); /* y for +, x for - */
        EdMath.curve25519_add(r.Y, r.X, a);
        EdMath.curve25519_sub(r.X, r.X, a);
        EdMath.curve25519_mul(c, p.T, q.T2D);
        EdMath.curve25519_add_reduce(r.T, p.Z, p.Z);
        EdMath.curve25519_copy(r.Z, r.T);
        EdMath.curve25519_add(rb[signbit], rb[signbit], c); /* z for +, t for - */
        EdMath.curve25519_sub(rb[signbit ^ 1], rb[signbit ^ 1], c); /* t for +, z for - */
    }

    public static void ge25519_pnielsadd_p1p1(ref GE25519 r, in GE25519 p, in GE25519_PNIELS q, int signbit)
    {
        Picker rb = new(r.Z, r.T);
        ReadOnlyPicker qb = new(q.YsubX, q.XaddY);

        Span<ulong> a = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> b = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> c = stackalloc ulong[ModM.ModM_WORDS];

        EdMath.curve25519_sub(a, p.Y, p.X);
        EdMath.curve25519_add(b, p.Y, p.X);
        EdMath.curve25519_mul(a, a, qb[signbit]); /* ysubx for +, xaddy for - */
        EdMath.curve25519_mul(r.X, b, qb[signbit ^ 1]); /* xaddy for +, ysubx for - */
        EdMath.curve25519_add(r.Y, r.X, a);
        EdMath.curve25519_sub(r.X, r.X, a);
        EdMath.curve25519_mul(c, p.T, q.T2D);
        EdMath.curve25519_mul(r.T, p.Z, q.Z);
        EdMath.curve25519_add_reduce(r.T, r.T, r.T);
        EdMath.curve25519_copy(r.Z, r.T);
        EdMath.curve25519_add(rb[signbit], rb[signbit], c); /* z for +, t for - */
        EdMath.curve25519_sub(rb[signbit ^ 1], rb[signbit ^ 1], c); /* t for +, z for - */
    }

    public static void ge25519_double_partial(ref GE25519 r, in GE25519 p)
    {
        GE25519 t;
        ge25519_double_p1p1(ref t, p);
        ge25519_p1p1_to_partial(ref r, t);
    }

    public static void ge25519_double(ref GE25519 r, in GE25519 p)
    {
        GE25519 t;
        ge25519_double_p1p1(ref t, p);
        ge25519_p1p1_to_full(ref r, t);
    }

    public static void ge25519_add(ref GE25519 r, in GE25519 p, in GE25519 q)
    {
        GE25519 t;
        ge25519_add_p1p1(ref t, p, q);
        ge25519_p1p1_to_full(ref r, t);
    }

    public static void ge25519_nielsadd2(ref GE25519 r, in GE25519_NIELS q)
    {
        Span<ulong> a = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> b = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> c = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> e = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> f = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> g = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> h = stackalloc ulong[ModM.ModM_WORDS];

        EdMath.curve25519_sub(a, r.Y, r.X);
        EdMath.curve25519_add(b, r.Y, r.X);
        EdMath.curve25519_mul(a, a, q.YsubX);
        EdMath.curve25519_mul(e, b, q.XaddY);
        EdMath.curve25519_add(h, e, a);
        EdMath.curve25519_sub(e, e, a);
        EdMath.curve25519_mul(c, r.T, q.T2D);
        EdMath.curve25519_add(f, r.Z, r.Z);
        EdMath.curve25519_add_after_basic(g, f, c);
        EdMath.curve25519_sub_after_basic(f, f, c);
        EdMath.curve25519_mul(r.X, e, f);
        EdMath.curve25519_mul(r.Y, h, g);
        EdMath.curve25519_mul(r.Z, g, f);
        EdMath.curve25519_mul(r.T, e, h);
    }

    public static void ge25519_pnielsadd(ref GE25519_PNIELS r, in GE25519 p, in GE25519_PNIELS q)
    {
        Span<ulong> a = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> b = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> c = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> x = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> y = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> z = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> t = stackalloc ulong[ModM.ModM_WORDS];

        EdMath.curve25519_sub(a, p.Y, p.X);
        EdMath.curve25519_add(b, p.Y, p.X);
        EdMath.curve25519_mul(a, a, q.YsubX);
        EdMath.curve25519_mul(x, b, q.XaddY);
        EdMath.curve25519_add(y, x, a);
        EdMath.curve25519_sub(x, x, a);
        EdMath.curve25519_mul(c, p.T, q.T2D);
        EdMath.curve25519_mul(t, p.Z, q.Z);
        EdMath.curve25519_add(t, t, t);
        EdMath.curve25519_add_after_basic(z, t, c);
        EdMath.curve25519_sub_after_basic(t, t, c);
        EdMath.curve25519_mul(r.XaddY, x, t);
        EdMath.curve25519_mul(r.YsubX, y, z);
        EdMath.curve25519_mul(r.Z, z, t);
        EdMath.curve25519_mul(r.T2D, x, y);
        EdMath.curve25519_copy(y, r.YsubX);
        EdMath.curve25519_sub(r.YsubX, r.YsubX, r.XaddY);
        EdMath.curve25519_add(r.XaddY, r.XaddY, y);
        EdMath.curve25519_mul(r.T2D, r.T2D, tables.EC2D);
    }

    #endregion

    #region pack & unpack

    public static void ge25519_pack(Span<byte> r, in GE25519 p)
    {
        Span<byte> parity = stackalloc byte[32];
        Span<ulong> tx = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> ty = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> zi = stackalloc ulong[ModM.ModM_WORDS];

        EdMath.curve25519_recip(zi, p.Z);
        EdMath.curve25519_mul(tx, p.X, zi);
        EdMath.curve25519_mul(ty, p.Y, zi);
        EdMath.curve25519_contract(r, ty);
        EdMath.curve25519_contract(parity, tx);
        r[31] ^= (byte)((parity[0] & 1) << 7);
    }

    public static bool ge25519_unpack_negative_vartime(ref GE25519 r, ReadOnlySpan<byte> p)
    {

        Span<byte> zero = stackalloc byte[32];
        zero.Clear();

        Span<ulong> one = stackalloc ulong[ModM.ModM_WORDS] { 1, 0, 0, 0, 0 };

        Span<byte> check = stackalloc byte[32];
        byte parity = (byte)(p[31] >> 7);

        Span<ulong> t = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> root = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> num = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> den = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> d3 = stackalloc ulong[ModM.ModM_WORDS];

        EdMath.curve25519_expand(r.Y, p);
        EdMath.curve25519_copy(r.Z, one);
        EdMath.curve25519_square(num, r.Y); /* x = y^2 */
        EdMath.curve25519_mul(den, num, tables.ECD); /* den = dy^2 */
        EdMath.curve25519_sub_reduce(num, num, r.Z); /* x = y^1 - 1 */
        EdMath.curve25519_add(den, den, r.Z); /* den = dy^2 + 1 */

        /* Computation of sqrt(num/den) */
        /* 1.: computation of num^((p-5)/8)*den^((7p-35)/8) = (num*den^7)^((p-5)/8) */
        EdMath.curve25519_square(t, den);
        EdMath.curve25519_mul(d3, t, den);
        EdMath.curve25519_square(r.X, d3);
        EdMath.curve25519_mul(r.X, r.X, den);
        EdMath.curve25519_mul(r.X, r.X, num);
        EdMath.curve25519_pow_two252m3(r.X, r.X);

        /* 2. computation of r.X = num * den^3 * (num*den^7)^((p-5)/8) */
        EdMath.curve25519_mul(r.X, r.X, d3);
        EdMath.curve25519_mul(r.X, r.X, num);

        /* 3. Check if either of the roots works: */
        EdMath.curve25519_square(t, r.X);
        EdMath.curve25519_mul(t, t, den);
        EdMath.curve25519_sub_reduce(root, t, num);
        EdMath.curve25519_contract(check, root);
        if (!Logic.ed25519_verify(check, zero, 32))
        {
            EdMath.curve25519_add_reduce(t, t, num);
            EdMath.curve25519_contract(check, t);
            if (!Logic.ed25519_verify(check, zero, 32))
            {
                return false;
            }
            EdMath.curve25519_mul(r.X, r.X, tables.SqrtNeg1);
        }

        EdMath.curve25519_contract(check, r.X);
        if ((check[0] & 1) == parity)
        {
            EdMath.curve25519_copy(t, r.X);
            EdMath.curve25519_neg(r.X, t);
        }
        EdMath.curve25519_mul(r.T, r.X, r.Y);
        return true;
    }

    #endregion

    #region Helpers

    private static void ge25519_set_neutral(ref GE25519 r)
    {
        r.ALL.Clear();
        r.Y[0] = 1;
        r.Z[0] = 1;
    }

    #endregion

    #region Scalarmults

    private const int S1_SWINDOWSIZE = 5;
    private const int S1_TABLE_SIZE = (1 << (S1_SWINDOWSIZE - 2));
    private const int S2_SWINDOWSIZE = 7;
    private const int S2_TABLE_SIZE = (1 << (S2_SWINDOWSIZE - 2));

    /* computes [s1]p1 + [s2]basepoint */
    public static void ge25519_double_scalarmult_vartime(ref GE25519 r, in GE25519 p1, ReadOnlySpan<ulong> s1, ReadOnlySpan<ulong> s2)
    {

        Span<sbyte> slide1 = stackalloc sbyte[256];
        Span<sbyte> slide2 = stackalloc sbyte[256];

        Span<GE25519_PNIELS> pre1 = stackalloc GE25519_PNIELS[S1_TABLE_SIZE];

        GE25519 d1;
        GE25519 t;

        int i;

        ModM.contract256_slidingwindow(slide1, s1, S1_SWINDOWSIZE);
        ModM.contract256_slidingwindow(slide2, s2, S2_SWINDOWSIZE);

        ge25519_double(ref d1, p1);
        ge25519_full_to_pniels(ref pre1[0], p1);
        for (i = 0; i < S1_TABLE_SIZE - 1; i++)
        {
            ge25519_pnielsadd(ref pre1[i + 1], d1, pre1[i]);
        }

        // set neutral
        ge25519_set_neutral(ref r);

        i = 255;
        while ((i >= 0) && !Convert.ToBoolean(slide1[i] | slide2[i]))
        {
            i--;
        }

        for (; i >= 0; i--)
        {
            ge25519_double_p1p1(ref t, r);

            if (Convert.ToBoolean(slide1[i]))
            {
                ge25519_p1p1_to_full(ref r, t);
                ge25519_pnielsadd_p1p1(ref t, r, pre1[Math.Abs(slide1[i]) / 2], (byte)slide1[i] >> 7);
            }

            if (Convert.ToBoolean(slide2[i]))
            {
                ge25519_p1p1_to_full(ref r, t);
                ge25519_nielsadd2_p1p1(ref t, r, tables.NIELS_Sliding_Multiples[Math.Abs(slide2[i]) / 2], (byte)slide2[i] >> 7);
            }

            ge25519_p1p1_to_partial(ref r, t);
        }
    }

    /// <summary>
    /// computes [s1]p1
    /// </summary>
    public static void ge25519_scalarmult_vartime(ref GE25519 r, in GE25519 p1, ReadOnlySpan<ulong> s1)
    {

        Span<sbyte> slide1 = stackalloc sbyte[256];
        Span<GE25519_PNIELS> pre1 = stackalloc GE25519_PNIELS[S1_TABLE_SIZE];
        GE25519 d1;
        GE25519 t;
        int i;

        ModM.contract256_slidingwindow(slide1, s1, S1_SWINDOWSIZE);

        ge25519_double(ref d1, p1);
        ge25519_full_to_pniels(ref pre1[0], p1);
        for (i = 0; i < S1_TABLE_SIZE - 1; i++)
            ge25519_pnielsadd(ref pre1[i + 1], d1, pre1[i]);

        // set neutral
        ge25519_set_neutral(ref r);

        i = 255;
        while ((i >= 0) && !Convert.ToBoolean(slide1[i]))
        {
            i--;
        }

        for (; i >= 0; i--)
        {
            ge25519_double_p1p1(ref t, r);

            if (Convert.ToBoolean(slide1[i]))
            {
                ge25519_p1p1_to_full(ref r, t);
                ge25519_pnielsadd_p1p1(ref t, r, pre1[Math.Abs(slide1[i]) / 2], (byte)slide1[i] >> 7);
            }

            ge25519_p1p1_to_partial(ref r, t);
        }
    }

    private static uint ge25519_windowb_equal(uint b, uint c)
    {
        return ((b ^ c) - 1) >> 31;
    }

    public static void ge25519_scalarmult_base_choose_niels(ref GE25519_NIELS t, ReadOnlySpan<ReadOnlyGE25519_NIELS_Packed> table, int pos, int b)
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
            EdMath.curve25519_move_conditional_bytes(packed.ALL, table[(pos * 8) + i], ge25519_windowb_equal(u, (uint)i + 1));
        }

        /* expand in to t */
        EdMath.curve25519_expand(t.YsubX, packed.YsubX);
        EdMath.curve25519_expand(t.XaddY, packed.XaddY);
        EdMath.curve25519_expand(t.T2D, packed.T2D);

        /* adjust for sign */
        EdMath.curve25519_swap_conditional(t.YsubX, t.XaddY, sign);
        EdMath.curve25519_neg(neg, t.T2D);
        EdMath.curve25519_swap_conditional(t.T2D, neg, sign);
    }

    /* computes [s]basepoint */
    public static void ge25519_scalarmult_base_niels(ref GE25519 r, ReadOnlySpan<ReadOnlyGE25519_NIELS_Packed> basepoint_table, ReadOnlySpan<ulong> s)
    {

        Span<sbyte> b = stackalloc sbyte[64];

        GE25519_NIELS t;
        ModM.contract256_window4(b, s);

        ge25519_scalarmult_base_choose_niels(ref t, basepoint_table, 0, b[1]);
        EdMath.curve25519_sub_reduce(r.X, t.XaddY, t.YsubX);
        EdMath.curve25519_add_reduce(r.Y, t.XaddY, t.YsubX);
        r.Z.Clear();
        EdMath.curve25519_copy(r.T, t.T2D);
        r.Z[0] = 2;

        for (int i = 3; i < 64; i += 2)
        {
            ge25519_scalarmult_base_choose_niels(ref t, basepoint_table, i / 2, b[i]);
            ge25519_nielsadd2(ref r, t);
        }

        ge25519_double_partial(ref r, r);
        ge25519_double_partial(ref r, r);
        ge25519_double_partial(ref r, r);
        ge25519_double(ref r, r);
        ge25519_scalarmult_base_choose_niels(ref t, basepoint_table, 0, b[0]);
        EdMath.curve25519_mul(t.T2D, t.T2D, tables.ECD);
        ge25519_nielsadd2(ref r, t);
        for (int i = 2; i < 64; i += 2)
        {
            ge25519_scalarmult_base_choose_niels(ref t, basepoint_table, i / 2, b[i]);
            ge25519_nielsadd2(ref r, t);
        }
    }

    #endregion
}

