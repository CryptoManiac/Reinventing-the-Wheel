using System.Runtime.InteropServices;

namespace EdDSA_Mehdi.Internal.Curve25519.Types;


/// <summary>
/// Signature verification context
/// </summary>
[StructLayout(LayoutKind.Explicit)]
public unsafe struct EDP_SIGV_CTX{

    #region MyRegion
    [FieldOffset(0)]
    private unsafe fixed U8 _pk[32];
    [FieldOffset(32)] 
    private unsafe fixed U8 _q_table[16 * PE_POINT.TypeByteSz];

    /// <summary>
    /// Type size in bytes
    /// </summary>
    public const int TypeByteSz = 32 + 16 * PE_POINT.TypeByteSz;

    #endregion

    public unsafe Span<U8> pk
    {
        get
        {
            fixed (U8* ptr = &_pk[0])
            {
                return new(ptr, 32);
            }
        }
    }

    public unsafe Span<PE_POINT> q_table
    {
        get
        {
            fixed (U8* ptr = &_q_table[0])
            {
                return new(ptr, 16);
            }
        }
    }
}

