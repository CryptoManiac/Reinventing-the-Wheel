using EdDSA.Internal.Curve25519;
using Wheel.Crypto.Elliptic.EllipticCommon;

namespace EdDSA.Internal.GroupElement;

internal static class GEMath
{
    private static Tables tables = Tables.Get_Tables();

    #region Conversions
    public static void ge25519_p1p1_to_partial(ref GE25519 r, in ReadOnlyGE25519 p)
    {

        EdMath.curve25519_mul(r.X, p.X, p.T);
        EdMath.curve25519_mul(r.Y, p.Y, p.Z);
        EdMath.curve25519_mul(r.Z, p.Z, p.T);
    }

    public static void ge25519_p1p1_to_full(ref GE25519 r, in ReadOnlyGE25519 p)
    {
        EdMath.curve25519_mul(r.X, p.X, p.T);
        EdMath.curve25519_mul(r.Y, p.Y, p.Z);
        EdMath.curve25519_mul(r.Z, p.Z, p.T);
        EdMath.curve25519_mul(r.T, p.X, p.Y);
    }

    public static void ge25519_full_to_pniels(ref GE25519_PNIELS p, in ReadOnlyGE25519 r)
    {
        EdMath.curve25519_sub(p.YsubX, r.Y, r.X);
        EdMath.curve25519_add(p.XaddY, r.Y, r.X);
        EdMath.curve25519_copy(p.Z, r.Z);
        EdMath.curve25519_mul(p.T2D, r.T, tables.EC2D);
    }
    #endregion

    #region Adding and doubling

    public static void ge25519_add_p1p1(ref GE25519 r, in ReadOnlyGE25519 p, in ReadOnlyGE25519 q) {

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


    public static void ge25519_double_p1p1(ref GE25519 r, in ReadOnlyGE25519 p)
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

    public static void ge25519_nielsadd2_p1p1(ref GE25519 r, in ReadOnlyGE25519 p, in ReadOnlyGE25519_NIELS q, byte signbit)
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

    public static void ge25519_pnielsadd_p1p1(ref GE25519 r, in ReadOnlyGE25519 p, in ReadOnlyGE25519_PNIELS q, byte signbit)
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

    public static void ge25519_double_partial(ref GE25519 r, in ReadOnlyGE25519 p)
    {
        GE25519 t;
        ge25519_double_p1p1(ref t, p);
        ge25519_p1p1_to_partial(ref r, t.readOnly);
    }

    public static void ge25519_double(ref GE25519 r, in ReadOnlyGE25519 p)
    {
        GE25519 t;
        ge25519_double_p1p1(ref t, p);
        ge25519_p1p1_to_full(ref r, t.readOnly);
    }

    public static void ge25519_add(ref GE25519 r, in ReadOnlyGE25519 p, in ReadOnlyGE25519 q)
    {
        GE25519 t;
        ge25519_add_p1p1(ref t, p, q);
        ge25519_p1p1_to_full(ref r, t.readOnly);
    }

    public static void ge25519_nielsadd2(ref GE25519 r, in ReadOnlyGE25519_NIELS q)
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

    public static void ge25519_pnielsadd(ref GE25519_PNIELS r, in ReadOnlyGE25519 p, in ReadOnlyGE25519_PNIELS q)
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
}

