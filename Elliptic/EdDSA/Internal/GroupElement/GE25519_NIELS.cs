using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Wheel.Crypto.Elliptic.EdDSA.Internal.GroupElement;

/// <summary>
/// GE stands for Group Element
/// Memory-safe wrapper over fixed-length number arrays
/// </summary>
[StructLayout(LayoutKind.Explicit)]
internal struct GE25519_NIELS
{
    [FieldOffset(0 * ModM.ModM_WORDS * sizeof(ulong))]
    private unsafe fixed ulong _YsubX[ModM.ModM_WORDS];
    [FieldOffset(1 * ModM.ModM_WORDS * sizeof(ulong))]
    private unsafe fixed ulong _XaddY[ModM.ModM_WORDS];
    [FieldOffset(2 * ModM.ModM_WORDS * sizeof(ulong))]
    private unsafe fixed ulong _T2D[ModM.ModM_WORDS];

    /// <summary>
    /// All integers at once, used by constructor
    /// </summary>
    [FieldOffset(0)]
    private unsafe fixed ulong _ALL[TypeUlongSz];

    public const int TypeUlongSz = 3 * ModM.ModM_WORDS;

    public GE25519_NIELS()
    {
        throw new InvalidOperationException("Constructor shouldn't be called");
    }

    #region Scalarmults

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint ge25519_windowb_equal(uint b, uint c)
    {
        return ((b ^ c) - 1) >> 31;
    }

    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void ge25519_scalarmult_base_choose_niels(ReadOnlySpan<GE25519_NIELS_Packed> table, int pos, int b)
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
        Curve25519.Expand(YsubX, packed.YsubX);
        Curve25519.Expand(XaddY, packed.XaddY);
        Curve25519.Expand(T2D, packed.T2D);

        /* adjust for sign */
        Curve25519.Swap_conditional(YsubX, XaddY, sign);
        Curve25519.Neg(neg, T2D);
        Curve25519.Swap_conditional(T2D, neg, sign);
    }

    #endregion

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
}

