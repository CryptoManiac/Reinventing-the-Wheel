using System.Runtime.InteropServices;

namespace EdDSA.Internal.GroupElement;

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

    public GE25519_NIELS(ReadOnlySpan<ulong> values)
    {
        // Will throw on insufficient length
        values[..TypeUlongSz].CopyTo(ALL);
    }

    public GE25519_NIELS(in ReadOnlyGE25519_NIELS ge)
    {
        ge.ALL.CopyTo(ALL);
    }

    public static implicit operator GE25519_NIELS(ReadOnlyGE25519_NIELS ge)
    {
        return new(ge);
    }

    /// <summary>
    /// Read-only version
    /// </summary>
    public unsafe readonly ReadOnlyGE25519_NIELS readOnly
    {
        get
        {
            fixed (void* ptr = &this)
            {
                return new Span<ReadOnlyGE25519_NIELS>(ptr, 1)[0];
            }
        }
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

/// <summary>
/// GE stands for Group Element
/// Memory-safe wrapper over fixed-length number arrays
/// </summary>
[StructLayout(LayoutKind.Explicit)]
internal struct ReadOnlyGE25519_NIELS
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

    public ReadOnlyGE25519_NIELS(ReadOnlySpan<ulong> values)
    {
        // Will throw on insufficient length
        values[..TypeUlongSz].CopyTo(_ALL_);
    }

    public ReadOnlyGE25519_NIELS(in GE25519_NIELS ge)
    {
        ge.ALL.CopyTo(_ALL_);
    }

    public readonly unsafe ReadOnlySpan<ulong> YsubX
    {
        get
        {
            fixed (ulong* ptr = &_YsubX[0])
            {
                return new(ptr, ModM.ModM_WORDS);
            }
        }
    }

    public readonly unsafe ReadOnlySpan<ulong> XaddY
    {
        get
        {
            fixed (ulong* ptr = &_XaddY[0])
            {
                return new(ptr, ModM.ModM_WORDS);
            }
        }
    }

    public readonly unsafe ReadOnlySpan<ulong> T2D
    {
        get
        {
            fixed (ulong* ptr = &_T2D[0])
            {
                return new(ptr, ModM.ModM_WORDS);
            }
        }
    }

    public readonly unsafe ReadOnlySpan<ulong> ALL => _ALL_;

    private readonly unsafe Span<ulong> _ALL_
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

