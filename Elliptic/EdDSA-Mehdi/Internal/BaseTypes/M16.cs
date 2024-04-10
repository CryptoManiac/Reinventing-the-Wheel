using System.Runtime.InteropServices;

namespace EdDSA_Mehdi.Internal.BaseTypes;

[StructLayout(LayoutKind.Explicit)]
public struct M16_U8
{
    private static readonly int LO = Convert.ToInt32(!BitConverter.IsLittleEndian);
    private static readonly int HI = 1 - LO;

    [FieldOffset(0)]
    private unsafe fixed U8 bytes[2];
    public unsafe U8 b0
    {
        get => bytes[LO];
        set => bytes[LO] = value;
    }
    public unsafe U8 b1 {
        get => bytes[HI];
        set => bytes[HI] = value;
    }
}

[StructLayout(LayoutKind.Explicit)]
public struct M16_S8
{
    private static readonly int LO = Convert.ToInt32(!BitConverter.IsLittleEndian);
    private static readonly int HI = 1 - LO;

    [FieldOffset(0)] private unsafe fixed U8 bytes[2];

    public unsafe U8 b0
    {
        readonly get => bytes[LO];
        set => bytes[LO] = value;
    }

    public unsafe S8 b1
    {
        readonly get => (S8)bytes[LO];
        set => bytes[LO] = (U8)value;
    }
}

/// <summary>
/// Two-byte value (ushort aka uint16_t)
/// </summary>
[StructLayout(LayoutKind.Explicit)]
public struct M16
{
    [FieldOffset(0)]
    public U16 u16;
    [FieldOffset(0)]
    public S16 s16;

    [FieldOffset(0)]
    private unsafe fixed U8 _bytes[2];
    
    public readonly unsafe Span<U8> bytes
    {
        get
        {
            fixed(U8* ptr = &_bytes[0])
            {
                return new Span<U8>(ptr, 2);
            }
        }
    }

    [FieldOffset(0)]
    public M16_U8 u8;

    [FieldOffset(0)]
    public M16_S8 s8;
}
