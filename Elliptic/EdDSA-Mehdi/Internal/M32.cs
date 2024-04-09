using System;
using System.Runtime.InteropServices;
using Wheel.Crypto.Elliptic.Curve25519.Internal;

namespace EdDSA_Mehdi.Internal;

[StructLayout(LayoutKind.Explicit)]
public struct M32_U16
{
    private static readonly int LO = Convert.ToInt32(!BitConverter.IsLittleEndian);
    private static readonly int HI = Convert.ToInt32(BitConverter.IsLittleEndian);

    [FieldOffset(0)]
    private unsafe fixed U16 _words[2];

    public unsafe U16 w0
    {
        readonly get => _words[LO];
        set => _words[LO] = value;
    }
    public unsafe U16 w1
    {
        readonly get => _words[HI];
        set => _words[HI] = value;
    }
}

[StructLayout(LayoutKind.Explicit)]
public struct M32_S16
{
    private static readonly int LO = Convert.ToInt32(!BitConverter.IsLittleEndian);
    private static readonly int HI = Convert.ToInt32(BitConverter.IsLittleEndian);

    [FieldOffset(0)]
    private unsafe fixed U16 _words[2];

    public unsafe U16 w0
    {
        readonly get => _words[LO];
        set => _words[LO] = value;
    }
    public unsafe S16 w1
    {
        readonly get => (S16) _words[HI];
        set => _words[HI] = (U16) value;
    }
}

[StructLayout(LayoutKind.Explicit)]
public struct M32_M16
{
    private static readonly int LO = Convert.ToInt32(!BitConverter.IsLittleEndian);
    private static readonly int HI = Convert.ToInt32(BitConverter.IsLittleEndian);

    [FieldOffset(0)]
    private unsafe fixed U16 _words[2];

    public unsafe M16 lo
    {
        readonly get
        {
            fixed(U16* ptr = &_words[LO])
            {
                return *(M16*)ptr;
            }
        }
        set
        {
            fixed (U16* ptr = &_words[LO])
            {
                *(M16*)ptr = value;
            }
        }
    }
    public unsafe M16 hi
    {
        readonly get
        {
            fixed (U16* ptr = &_words[HI])
            {
                return *(M16*)ptr;
            }
        }
        set
        {
            fixed (U16* ptr = &_words[HI])
            {
                *(M16*)ptr = value;
            }
        }
    }
}

[StructLayout(LayoutKind.Explicit)]
public struct M32_U8
{
    private static readonly int IDX_MUL = Convert.ToInt32(!BitConverter.IsLittleEndian);
    private static readonly int ZERO = 4 - 4 * IDX_MUL;
    private static readonly int ONE = 4 - 3 * IDX_MUL;
    private static readonly int TWO = 4 - 2 * IDX_MUL;
    private static readonly int THREE = 4 - 1 * IDX_MUL;

    [FieldOffset(0)]
    private unsafe fixed U8 bytes[4];

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
}

[StructLayout(LayoutKind.Explicit)]
public struct M32
{
    [FieldOffset(0)]
    U32 u32;
    [FieldOffset(0)]
    S32 s32;

    [FieldOffset(0)]
    private unsafe fixed U8 _bytes[4];
    public readonly unsafe Span<U8> bytes
    {
        get
        {
            fixed (U8* ptr = &_bytes[0])
            {
                return new Span<U8>(ptr, 4);
            }
        }
    }

    [FieldOffset(0)]
    public M32_U16 u16;

    [FieldOffset(0)]
    public M32_S16 s16;

    [FieldOffset(0)]
    public M32_M16 m16;
}
