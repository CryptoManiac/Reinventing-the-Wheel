using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Wheel.Crypto.Elliptic.EdDSA.Internal.GroupElement;

/// <summary>
/// GE stands for Group Element
/// Memory-safe wrapper over fixed-length number arrays
/// </summary>
[StructLayout(LayoutKind.Explicit)]
internal struct GE25519_PNIELS
{
    [FieldOffset(0 * ModM.ModM_WORDS * sizeof(ulong))]
    private unsafe fixed ulong _YsubX[ModM.ModM_WORDS];
    [FieldOffset(1 * ModM.ModM_WORDS * sizeof(ulong))]
    private unsafe fixed ulong _XaddY[ModM.ModM_WORDS];
    [FieldOffset(2 * ModM.ModM_WORDS * sizeof(ulong))]
    private unsafe fixed ulong _Z[ModM.ModM_WORDS];
    [FieldOffset(3 * ModM.ModM_WORDS * sizeof(ulong))]
    private unsafe fixed ulong _T2D[ModM.ModM_WORDS];

    #region Precalculated data
    private static readonly Ed25519Tables tables = Ed25519Tables.Get_Tables();
    #endregion

    #region Conversions
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void ge25519_full_to_pniels(in GE25519 r)
    {
        Curve25519.Sub(YsubX, r.Y, r.X);
        Curve25519.Add(XaddY, r.Y, r.X);
        Curve25519.Copy(Z, r.Z);
        Curve25519.Mul(T2D, r.T, tables.EC2D);
    }
    #endregion


    #region Adding and doubling
    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void ge25519_pnielsadd(in GE25519 p, in GE25519_PNIELS q)
    {
        Span<ulong> a = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> b = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> c = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> x = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> y = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> z = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> t = stackalloc ulong[ModM.ModM_WORDS];

        Curve25519.Sub(a, p.Y, p.X);
        Curve25519.Add(b, p.Y, p.X);
        Curve25519.Mul(a, a, q.YsubX);
        Curve25519.Mul(x, b, q.XaddY);
        Curve25519.Add(y, x, a);
        Curve25519.Sub(x, x, a);
        Curve25519.Mul(c, p.T, q.T2D);
        Curve25519.Mul(t, p.Z, q.Z);
        Curve25519.Add(t, t, t);
        Curve25519.Add_after_basic(z, t, c);
        Curve25519.Sub_after_basic(t, t, c);
        Curve25519.Mul(XaddY, x, t);
        Curve25519.Mul(YsubX, y, z);
        Curve25519.Mul(Z, z, t);
        Curve25519.Mul(T2D, x, y);
        Curve25519.Copy(y, YsubX);
        Curve25519.Sub(YsubX, YsubX, XaddY);
        Curve25519.Add(XaddY, XaddY, y);
        Curve25519.Mul(T2D, T2D, tables.EC2D);
    }
    #endregion

    #region Data accessors
    /// <summary>
    /// All integers at once, used by constructor
    /// </summary>
    [FieldOffset(0)]
    private unsafe fixed ulong _ALL[TypeUlongSz];

    public const int TypeUlongSz = 3 * ModM.ModM_WORDS;

    public GE25519_PNIELS()
    {
        throw new InvalidOperationException("Constructor shouldn't be called");
    }

    public readonly unsafe Span<ulong> YsubX
    {
        get
        {
            fixed (ulong* ptr = &_YsubX[0])
            {
                return new(ptr, ModM.ModM_WORDS);
            }
        }
    }

    public readonly unsafe Span<ulong> XaddY
    {
        get
        {
            fixed (ulong* ptr = &_XaddY[0])
            {
                return new(ptr, ModM.ModM_WORDS);
            }
        }
    }

    public readonly unsafe Span<ulong> Z
    {
        get
        {
            fixed (ulong* ptr = &_Z[0])
            {
                return new(ptr, ModM.ModM_WORDS);
            }
        }
    }

    public readonly unsafe Span<ulong> T2D
    {
        get
        {
            fixed (ulong* ptr = &_T2D[0])
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
