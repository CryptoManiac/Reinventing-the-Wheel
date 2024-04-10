using System.Runtime.InteropServices;

namespace EdDSA_Mehdi.Internal.Curve25519.Types;

/// <summary>
/// Projective coordinates
/// </summary>
[StructLayout(LayoutKind.Explicit)]
public struct Ext_POINT
{
    #region Safe access wrappers
    /// <summary>
    /// x/z
    /// </summary>
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
    
    /// <summary>
    /// y/z
    /// </summary>
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
    
    public readonly unsafe Span<U_WORD> z
    {
        get
        {
            fixed(U_WORD* ptr = &_z[0])
            {
                return new Span<U_WORD>(ptr, Const.K_WORDS);
            }
        }
    }
    
    /// <summary>
    /// xy/z
    /// </summary>
    public readonly unsafe Span<U_WORD> t
    {
        get
        {
            fixed(U_WORD* ptr = &_t[0])
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
    [FieldOffset(2 * Const.K_WORDS * sizeof(U_WORD))]
    private unsafe fixed U_WORD _z[Const.K_WORDS];
    [FieldOffset(3 * Const.K_WORDS * sizeof(U_WORD))]
    private unsafe fixed U_WORD _t[Const.K_WORDS];
    #endregion
}
