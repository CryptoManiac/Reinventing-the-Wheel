using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Wheel.Crypto.Elliptic.EdDSA.Internal.GroupElement;

/// <summary>
/// GE stands for Group Element
/// Memory-safe wrapper over fixed-length number arrays
/// TODO: Implement read-only version
/// </summary>
[StructLayout(LayoutKind.Explicit)]
internal struct GE25519
{
    [FieldOffset(0 * ModM.ModM_WORDS * sizeof(ulong))]
    private unsafe fixed ulong _X[ModM.ModM_WORDS];
    [FieldOffset(1 * ModM.ModM_WORDS * sizeof(ulong))]
    private unsafe fixed ulong _Y[ModM.ModM_WORDS];
    [FieldOffset(2 * ModM.ModM_WORDS * sizeof(ulong))]
    private unsafe fixed ulong _Z[ModM.ModM_WORDS];
    [FieldOffset(3 * ModM.ModM_WORDS * sizeof(ulong))]
    private unsafe fixed ulong _T[ModM.ModM_WORDS];

    /// <summary>
    /// All integers at once, used by constructor
    /// </summary>
    [FieldOffset(0)]
    private unsafe fixed ulong _ALL[TypeUlongSz];

    public const int TypeUlongSz = 4 * ModM.ModM_WORDS;

    public GE25519() {
        throw new InvalidOperationException("Constructor shouldn't be called");
    }

    #region Precalculated data
    private static readonly Ed25519Tables tables = Ed25519Tables.Get_Tables();
    #endregion

    #region Helpers

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void ge25519_set_neutral()
    {
        ALL.Clear();
        Y[0] = 1;
        Z[0] = 1;
    }

    #endregion

    #region Adding and doubling


    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void ge25519_double_partial(in GE25519 p)
    {
        GE25519_P1P1 t;
        t.ge25519_double_p1p1(p);
        ge25519_p1p1_to_partial(t);
    }

    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void ge25519_double(in GE25519 p)
    {
        GE25519_P1P1 t;
        t.ge25519_double_p1p1(p);
        ge25519_p1p1_to_full(t);
    }

    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void ge25519_add(in GE25519 p, in GE25519 q)
    {
        GE25519_P1P1 t;
        t.ge25519_add_p1p1(p, q);
        ge25519_p1p1_to_full(t);
    }

    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void ge25519_nielsadd2(in GE25519_NIELS q)
    {
        Span<ulong> a = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> b = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> c = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> e = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> f = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> g = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> h = stackalloc ulong[ModM.ModM_WORDS];

        Curve25519.Sub(a, Y, X);
        Curve25519.Add(b, Y, X);
        Curve25519.Mul(a, a, q.YsubX);
        Curve25519.Mul(e, b, q.XaddY);
        Curve25519.Add(h, e, a);
        Curve25519.Sub(e, e, a);
        Curve25519.Mul(c, T, q.T2D);
        Curve25519.Add(f, Z, Z);
        Curve25519.Add_after_basic(g, f, c);
        Curve25519.Sub_after_basic(f, f, c);
        Curve25519.Mul(X, e, f);
        Curve25519.Mul(Y, h, g);
        Curve25519.Mul(Z, g, f);
        Curve25519.Mul(T, e, h);
    }

    #endregion

    #region Conversions
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void ge25519_p1p1_to_partial(in GE25519_P1P1 p)
    {

        Curve25519.Mul(X, p.X, p.T);
        Curve25519.Mul(Y, p.Y, p.Z);
        Curve25519.Mul(Z, p.Z, p.T);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void ge25519_p1p1_to_full(in GE25519_P1P1 p)
    {
        Curve25519.Mul(X, p.X, p.T);
        Curve25519.Mul(Y, p.Y, p.Z);
        Curve25519.Mul(Z, p.Z, p.T);
        Curve25519.Mul(T, p.X, p.Y);
    }
    #endregion

    #region pack & unpack

    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void ge25519_pack(Span<byte> r)
    {
        Span<byte> parity = stackalloc byte[32];
        Span<ulong> tx = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> ty = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> zi = stackalloc ulong[ModM.ModM_WORDS];

        Curve25519.Recip(zi, Z);
        Curve25519.Mul(tx, X, zi);
        Curve25519.Mul(ty, Y, zi);
        Curve25519.Contract(r, ty);
        Curve25519.Contract(parity, tx);
        r[31] ^= (byte)((parity[0] & 1) << 7);
    }

    [SkipLocalsInit]
    public bool ge25519_unpack_negative_vartime(ReadOnlySpan<byte> p)
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

        Curve25519.Expand(Y, p);
        Curve25519.Copy(Z, one);
        Curve25519.Square(num, Y); /* x = y^2 */
        Curve25519.Mul(den, num, tables.ECD); /* den = dy^2 */
        Curve25519.Sub_reduce(num, num, Z); /* x = y^1 - 1 */
        Curve25519.Add(den, den, Z); /* den = dy^2 + 1 */

        /* Computation of sqrt(num/den) */
        /* 1.: computation of num^((p-5)/8)*den^((7p-35)/8) = (num*den^7)^((p-5)/8) */
        Curve25519.Square(t, den);
        Curve25519.Mul(d3, t, den);
        Curve25519.Square(X, d3);
        Curve25519.Mul(X, X, den);
        Curve25519.Mul(X, X, num);
        Curve25519.Pow_two252m3(X, X);

        /* 2. computation of X = num * den^3 * (num*den^7)^((p-5)/8) */
        Curve25519.Mul(X, X, d3);
        Curve25519.Mul(X, X, num);

        /* 3. Check if either of the roots works: */
        Curve25519.Square(t, X);
        Curve25519.Mul(t, t, den);
        Curve25519.Sub_reduce(root, t, num);
        Curve25519.Contract(check, root);
        if (!Curve25519.Equals(check, zero, 32))
        {
            Curve25519.Add_reduce(t, t, num);
            Curve25519.Contract(check, t);
            if (!Curve25519.Equals(check, zero, 32))
            {
                return false;
            }
            Curve25519.Mul(X, X, tables.SqrtNeg1);
        }

        Curve25519.Contract(check, X);
        if ((check[0] & 1) == parity)
        {
            Curve25519.Copy(t, X);
            Curve25519.Neg(X, t);
        }
        Curve25519.Mul(T, X, Y);
        return true;
    }

    #endregion

    #region Scalarmults
    private const int S1_SWINDOWSIZE = 5;
    private const int S1_TABLE_SIZE = (1 << (S1_SWINDOWSIZE - 2));
    private const int S2_SWINDOWSIZE = 7;
    private const int S2_TABLE_SIZE = (1 << (S2_SWINDOWSIZE - 2));

    /* computes [s]basepoint */
    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void ge25519_scalarmult_base_niels(ReadOnlySpan<ulong> s)
    {

        Span<sbyte> b = stackalloc sbyte[64];

        GE25519_NIELS t;
        ModM.contract256_window4(b, s);

        t.ge25519_scalarmult_base_choose_niels(tables.NIELS_Base_Multiples, 0, b[1]);
        Curve25519.Sub_reduce(X, t.XaddY, t.YsubX);
        Curve25519.Add_reduce(Y, t.XaddY, t.YsubX);
        Z.Clear();
        Curve25519.Copy(T, t.T2D);
        Z[0] = 2;

        for (int i = 3; i < 64; i += 2)
        {
            t.ge25519_scalarmult_base_choose_niels(tables.NIELS_Base_Multiples, i / 2, b[i]);
            ge25519_nielsadd2(t);
        }

        ge25519_double_partial(this);
        ge25519_double_partial(this);
        ge25519_double_partial(this);
        ge25519_double(this);
        t.ge25519_scalarmult_base_choose_niels(tables.NIELS_Base_Multiples, 0, b[0]);
        Curve25519.Mul(t.T2D, t.T2D, tables.ECD);
        ge25519_nielsadd2(t);
        for (int i = 2; i < 64; i += 2)
        {
            t.ge25519_scalarmult_base_choose_niels(tables.NIELS_Base_Multiples, i / 2, b[i]);
            ge25519_nielsadd2(t);
        }
    }

    /// <summary>
    /// computes [s1]p1
    /// WARNING: This function IS NOT timing-secure
    /// </summary>
    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void ge25519_scalarmult_vartime(in GE25519 p1, ReadOnlySpan<ulong> s1)
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
        ge25519_set_neutral();

        i = 255;
        while ((i >= 0) && !Convert.ToBoolean(slide1[i]))
        {
            i--;
        }

        for (; i >= 0; i--)
        {
            t.ge25519_double_p1p1(this);

            if (Convert.ToBoolean(slide1[i]))
            {
                ge25519_p1p1_to_full(t);
                t.ge25519_pnielsadd_p1p1(this, pre1[Math.Abs(slide1[i]) / 2], (byte)slide1[i] >> 7);
            }

            ge25519_p1p1_to_partial(t);
        }
    }

    /* computes [s1]p1 + [s2]basepoint */
    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void ge25519_double_scalarmult_vartime(in GE25519 p1, ReadOnlySpan<ulong> s1, ReadOnlySpan<ulong> s2)
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
        ge25519_set_neutral();

        i = 255;
        while ((i >= 0) && !Convert.ToBoolean(slide1[i] | slide2[i]))
        {
            i--;
        }

        for (; i >= 0; i--)
        {
            t.ge25519_double_p1p1(this);

            if (Convert.ToBoolean(slide1[i]))
            {
                ge25519_p1p1_to_full(t);
                t.ge25519_pnielsadd_p1p1(this, pre1[Math.Abs(slide1[i]) / 2], (byte)slide1[i] >> 7);
            }

            if (Convert.ToBoolean(slide2[i]))
            {
                ge25519_p1p1_to_full(t);
                t.ge25519_nielsadd2_p1p1(this, tables.NIELS_Sliding_Multiples[Math.Abs(slide2[i]) / 2], (byte)slide2[i] >> 7);
            }

            ge25519_p1p1_to_partial(t);
        }
    }
    #endregion

    #region Data accessors
    public readonly unsafe Span<ulong> X
    {
        get {
            fixed (ulong* ptr = &_X[0])
            {
                return new(ptr, ModM.ModM_WORDS);
            }
        }
    }

    public readonly unsafe Span<ulong> Y
    {
        get
        {
            fixed (ulong* ptr = &_Y[0])
            {
                return new(ptr, ModM.ModM_WORDS);
            }
        }
    }

    public readonly unsafe Span<ulong> Z
    {
        get
        {
            fixed(ulong* ptr = &_Z[0])
            {
                return new(ptr, ModM.ModM_WORDS);
            }
        }
    }

    public readonly unsafe Span<ulong> T
    {
        get
        {
            fixed (ulong* ptr = &_T[0])
            {
                return new(ptr, ModM.ModM_WORDS);
            }
        }
    }

    public readonly unsafe Span<ulong> ALL
    {
        get
        {
            fixed (ulong* ptr = &_ALL[0])
            {
                return new(ptr, TypeUlongSz);
            }
        }
    }
    #endregion
}
