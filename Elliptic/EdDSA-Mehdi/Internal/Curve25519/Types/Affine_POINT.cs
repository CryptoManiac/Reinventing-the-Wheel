using System.Runtime.InteropServices;

namespace EdDSA_Mehdi.Internal.Curve25519.Types;

/// <summary>
/// Affine coordinates
/// </summary>
[StructLayout(LayoutKind.Explicit)]
public struct Affine_POINT
{
    #region Safe access wrappers
    public readonly unsafe Span<U_WORD> x
    {
        get
        {
            fixed(U_WORD* ptr = &_x[0])
            {
                return new Span<U_WORD>(ptr, Const.K_WORDS);
            }
        }
    }
    
    public readonly unsafe Span<U_WORD> y
    {
        get
        {
            fixed(U_WORD* ptr = &_y[0])
            {
                return new Span<U_WORD>(ptr, Const.K_WORDS);
            }
        }
    }
    #endregion

    #region Fixed buffers
    [FieldOffset(0 * Const.K_WORDS * sizeof(U_WORD))]
    private unsafe fixed U_WORD _x[Const.K_WORDS];
    [FieldOffset(1 * Const.K_WORDS * sizeof(U_WORD))]
    private unsafe fixed U_WORD _y[Const.K_WORDS];
    /// <summary>
    /// Size of structure in bytes
    /// </summary>
    public const int TypeByteSz = 2 * Const.K_WORDS * sizeof(U_WORD);
    #endregion
}
