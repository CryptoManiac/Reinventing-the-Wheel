using System.Runtime.InteropServices;

namespace EdDSA_Mehdi.Internal.BaseTypes;

[StructLayout(LayoutKind.Explicit)]
public struct M64_U32
{
    private static readonly int LO = Convert.ToInt32(!BitConverter.IsLittleEndian);
    private static readonly int HI = 1 - LO;

    [FieldOffset(0)]
    private unsafe fixed U32 _words[2];

    public unsafe U32 lo
    {
        readonly get => _words[LO];
        set => _words[LO] = value;
    }
    public unsafe U32 hi
    {
        readonly get => _words[HI];
        set => _words[HI] = value;
    }
}

[StructLayout(LayoutKind.Explicit)]
public struct M64_S32
{
    private static readonly int LO = Convert.ToInt32(!BitConverter.IsLittleEndian);
    private static readonly int HI = 1 - LO;

    [FieldOffset(0)]
    private unsafe fixed U32 _words[2];

    public unsafe U32 lo
    {
        readonly get => _words[LO];
        set => _words[LO] = value;
    }
    public unsafe S32 hi
    {
        readonly get => (S32)_words[HI];
        set => _words[HI] = (U32)value;
    }
}


[StructLayout(LayoutKind.Explicit)]
public struct M64_M32
{
    private static readonly int LO = Convert.ToInt32(!BitConverter.IsLittleEndian);
    private static readonly int HI = 1 - LO;

    [FieldOffset(0)]
    private unsafe fixed U32 _words[2];

    public unsafe M32 lo
    {
        readonly get
        {
            fixed (U32* ptr = &_words[LO])
            {
                return *(M32*)ptr;
            }
        }
        set
        {
            fixed (U32* ptr = &_words[LO])
            {
                *(M32*)ptr = value;
            }
        }
    }
    public unsafe M32 hi
    {
        readonly get
        {
            fixed (U32* ptr = &_words[HI])
            {
                return *(M32*)ptr;
            }
        }
        set
        {
            fixed (U32* ptr = &_words[HI])
            {
                *(M32*)ptr = value;
            }
        }
    }
}

[StructLayout(LayoutKind.Explicit)]
public struct M64_U16
{
    private static readonly int IDX_MUL = Convert.ToInt32(!BitConverter.IsLittleEndian);
    private static readonly int ZERO = 4 - 4 * IDX_MUL;
    private static readonly int ONE = 4 - 3 * IDX_MUL;
    private static readonly int TWO = 4 - 2 * IDX_MUL;
    private static readonly int THREE = 4 - 1 * IDX_MUL;

    [FieldOffset(0)]
    private unsafe fixed U16 words[4];

    public unsafe U16 w0
    {
        readonly get => words[ZERO];
        set => words[ZERO] = value;
    }
    public unsafe U16 w1
    {
        readonly get => words[ONE];
        set => words[ONE] = value;
    }

    public unsafe U16 w2
    {
        readonly get => words[TWO];
        set => words[TWO] = value;
    }
    public unsafe U16 w3
    {
        readonly get => words[THREE];
        set => words[THREE] = value;
    }
}

[StructLayout(LayoutKind.Explicit)]
public struct M64_U8
{
    private static readonly int IDX_MUL = Convert.ToInt32(!BitConverter.IsLittleEndian);

    private static readonly int ZERO = 8 - 8 * IDX_MUL;
    private static readonly int ONE = 8 - 7 * IDX_MUL;
    private static readonly int TWO = 8 - 6 * IDX_MUL;
    private static readonly int THREE = 8 - 5 * IDX_MUL;
    private static readonly int FOUR = 8 - 4 * IDX_MUL;
    private static readonly int FIVE = 8 - 3 * IDX_MUL;
    private static readonly int SIX = 8 - 2 * IDX_MUL;
    private static readonly int SEVEN = 8 - 1 * IDX_MUL;

    [FieldOffset(0)]
    private unsafe fixed U8 bytes[8];

    public unsafe U8 b0
    {
        readonly get => bytes[ZERO];
        set => bytes[ZERO] = value;
    }
    public unsafe U8 b1
    {
        readonly get => bytes[ONE];
        set => bytes[ONE] = value;
    }

    public unsafe U8 b2
    {
        readonly get => bytes[TWO];
        set => bytes[TWO] = value;
    }
    public unsafe U8 b3
    {
        readonly get => bytes[THREE];
        set => bytes[THREE] = value;
    }

    public unsafe U8 b4
    {
        readonly get => bytes[FOUR];
        set => bytes[FOUR] = value;
    }
    public unsafe U8 b5
    {
        readonly get => bytes[FIVE];
        set => bytes[FIVE] = value;
    }

    public unsafe U8 b6
    {
        readonly get => bytes[SIX];
        set => bytes[SIX] = value;
    }
    public unsafe U8 b7
    {
        readonly get => bytes[SEVEN];
        set => bytes[SEVEN] = value;
    }
}

/// <summary>
/// Eight-byte value (ulong aka uint64_t)
/// </summary>
[StructLayout(LayoutKind.Explicit)]
public struct M64
{
    [FieldOffset(0)]
    public U64 u64;
    [FieldOffset(0)]
    public S64 s64;

    [FieldOffset(0)]
    private unsafe fixed U8 _bytes[8];
    public readonly unsafe Span<U8> bytes
    {
        get
        {
            fixed (U8* ptr = &_bytes[0])
            {
                return new Span<U8>(ptr, 8);
            }
        }
    }

    [FieldOffset(0)]
    public M64_U32 u32;

    [FieldOffset(0)]
    public M64_S32 s32;

    [FieldOffset(0)]
    public M64_U16 u16;

    [FieldOffset(0)]
    public M64_U8 u8;

    [FieldOffset(0)]
    public M64_M32 m32;
}

