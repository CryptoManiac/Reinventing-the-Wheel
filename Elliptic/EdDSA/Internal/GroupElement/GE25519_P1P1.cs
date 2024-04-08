using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Crypto.Elliptic.EllipticCommon;

namespace Wheel.Crypto.Elliptic.EdDSA.Internal.GroupElement;

/// <summary>
/// GE stands for Group Element
/// Memory-safe wrapper over fixed-length number arrays
/// TODO: Implement read-only version
/// </summary>
[StructLayout(LayoutKind.Explicit)]
internal struct GE25519_P1P1
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

    public GE25519_P1P1() {
        throw new InvalidOperationException("Constructor shouldn't be called");
    }

    #region Precalculated data
    private static readonly Curve25519Tables tables = Curve25519Tables.Get_Tables();
    #endregion

    #region Adding and doubling
    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void ge25519_add_p1p1(in GE25519 p, in GE25519 q)
    {
        Span<ulong> a = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> b = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> c = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> d = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> t = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> u = stackalloc ulong[ModM.ModM_WORDS];


        Curve25519.Sub(a, p.Y, p.X);
        Curve25519.Add(b, p.Y, p.X);
        Curve25519.Sub(t, q.Y, q.X);
        Curve25519.Add(u, q.Y, q.X);
        Curve25519.Mul(a, a, t);
        Curve25519.Mul(b, b, u);
        Curve25519.Mul(c, p.T, q.T);
        Curve25519.Mul(c, c, tables.EC2D);
        Curve25519.Mul(d, p.Z, q.Z);
        Curve25519.Add(d, d, d);
        Curve25519.Sub(X, b, a);
        Curve25519.Add(Y, b, a);
        Curve25519.Add_after_basic(Z, d, c);
        Curve25519.Sub_after_basic(T, d, c);
    }


    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void ge25519_double_p1p1(in GE25519 p)
    {
        Span<ulong> a = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> b = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> c = stackalloc ulong[ModM.ModM_WORDS];

        Curve25519.Square(a, p.X);
        Curve25519.Square(b, p.Y);
        Curve25519.Square(c, p.Z);
        Curve25519.Add_reduce(c, c, c);
        Curve25519.Add(X, p.X, p.Y);
        Curve25519.Square(X, X);
        Curve25519.Add(Y, b, a);
        Curve25519.Sub(Z, b, a);
        Curve25519.Sub_after_basic(X, X, Y);
        Curve25519.Sub_after_basic(T, c, Z);
    }

    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void ge25519_nielsadd2_p1p1(in GE25519 p, in GE25519_NIELS q, int signbit)
    {
        Picker rb = new(Z, T);
        ReadOnlyPicker qb = new(q.YsubX, q.XaddY);

        Span<ulong> a = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> b = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> c = stackalloc ulong[ModM.ModM_WORDS];

        Curve25519.Sub(a, p.Y, p.X);
        Curve25519.Add(b, p.Y, p.X);
        Curve25519.Mul(a, a, qb[signbit]); /* x for +, y for - */
        Curve25519.Mul(X, b, qb[signbit ^ 1]); /* y for +, x for - */
        Curve25519.Add(Y, X, a);
        Curve25519.Sub(X, X, a);
        Curve25519.Mul(c, p.T, q.T2D);
        Curve25519.Add_reduce(T, p.Z, p.Z);
        Curve25519.Copy(Z, T);
        Curve25519.Add(rb[signbit], rb[signbit], c); /* z for +, t for - */
        Curve25519.Sub(rb[signbit ^ 1], rb[signbit ^ 1], c); /* t for +, z for - */
    }

    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void ge25519_pnielsadd_p1p1(in GE25519 p, in GE25519_PNIELS q, int signbit)
    {
        Picker rb = new(Z, T);
        ReadOnlyPicker qb = new(q.YsubX, q.XaddY);

        Span<ulong> a = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> b = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> c = stackalloc ulong[ModM.ModM_WORDS];

        Curve25519.Sub(a, p.Y, p.X);
        Curve25519.Add(b, p.Y, p.X);
        Curve25519.Mul(a, a, qb[signbit]); /* ysubx for +, xaddy for - */
        Curve25519.Mul(X, b, qb[signbit ^ 1]); /* xaddy for +, ysubx for - */
        Curve25519.Add(Y, X, a);
        Curve25519.Sub(X, X, a);
        Curve25519.Mul(c, p.T, q.T2D);
        Curve25519.Mul(T, p.Z, q.Z);
        Curve25519.Add_reduce(T, T, T);
        Curve25519.Copy(Z, T);
        Curve25519.Add(rb[signbit], rb[signbit], c); /* z for +, t for - */
        Curve25519.Sub(rb[signbit ^ 1], rb[signbit ^ 1], c); /* t for +, z for - */
    }
    #endregion

    #region Coordinate accessors
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
