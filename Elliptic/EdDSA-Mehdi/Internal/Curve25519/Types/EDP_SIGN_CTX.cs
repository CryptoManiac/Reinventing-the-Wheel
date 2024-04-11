using System.Runtime.InteropServices;

namespace EdDSA_Mehdi.Internal.Curve25519.Types;

[StructLayout(LayoutKind.Explicit)]
public unsafe struct EDP_SIGN_CTX
{
    [FieldOffset(0)]
    private unsafe fixed U8 _sk[32];

    [FieldOffset(32)]
    private unsafe fixed U8 _pk[32];

    /// <summary>
    /// Public key
    /// </summary>
    public Span<U8> pk
    {
        get
        {
            fixed (U8* ptr = &_pk[0])
            {
                return new(ptr, 32);
            }
        }
    }

    /// <summary>
    /// Secret key
    /// </summary>
    public Span<U8> sk
    {
        get
        {
            fixed (U8* ptr = &_sk[0])
            {
                return new(ptr, 32);
            }
        }
    }
}
