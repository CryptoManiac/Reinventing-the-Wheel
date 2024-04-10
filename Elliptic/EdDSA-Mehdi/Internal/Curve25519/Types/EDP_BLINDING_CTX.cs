using System.Runtime.InteropServices;

namespace EdDSA_Mehdi.Internal.Curve25519.Types;

/// <summary>
/// Scalar blinding context
/// </summary>
[StructLayout(LayoutKind.Explicit)]
public struct EDP_BLINDING_CTX
{
    #region Safe access wrappers
    public readonly unsafe Span<U_WORD> bl
    {
        get
        {
            fixed(U_WORD* ptr = &_bl[0])
            {
                return new Span<U_WORD>(ptr, Const.K_WORDS);
            }
        }
    }
    
    public readonly unsafe Span<U_WORD> zr
    {
        get
        {
            fixed(U_WORD* ptr = &_zr[0])
            {
                return new Span<U_WORD>(ptr, Const.K_WORDS);
            }
        }
    }
    #endregion
    
    #region Fixed buffers
    [FieldOffset(0 * Const.K_WORDS * sizeof(U_WORD))]
    private unsafe fixed U_WORD _bl[Const.K_WORDS];
    [FieldOffset(1 * Const.K_WORDS * sizeof(U_WORD))]
    private unsafe fixed U_WORD _zr[Const.K_WORDS];
    #endregion

    /// <summary>
    /// Blinding point coordinates
    /// </summary>
    [FieldOffset(2 * Const.K_WORDS * sizeof(U_WORD))]
    PE_POINT BP;
}
