using System.Runtime.InteropServices;
using EdDSA_Mehdi.Internal.BaseTypes;

namespace EdDSA_Mehdi.Internal.Curve25519.Types;

/// <summary>
/// Pre-computed, extended point
/// </summary>
[StructLayout(LayoutKind.Explicit)]
public struct PE_POINT
{
    #region Safe access wrappers
    /// <summary>
    /// Y+X
    /// </summary>
    public readonly unsafe Span<U_WORD> YpX
    {
        get
        {
            fixed(U_WORD* ptr = &_YpX[0])
            {
                return new Span<U_WORD>(ptr, Const.K_WORDS);
            }
        }
    }
    
    /// <summary>
    /// Y-X
    /// </summary>
    public readonly unsafe Span<U_WORD> YmX
    {
        get
        {
            fixed(U_WORD* ptr = &_YmX[0])
            {
                return new Span<U_WORD>(ptr, Const.K_WORDS);
            }
        }
    }
    
    /// <summary>
    /// 2d*T
    /// </summary>
    public readonly unsafe Span<U_WORD> T2d
    {
        get
        {
            fixed(U_WORD* ptr = &_T2d[0])
            {
                return new Span<U_WORD>(ptr, Const.K_WORDS);
            }
        }
    }
    
    /// <summary>
    /// 2*Z
    /// </summary>
    public readonly unsafe Span<U_WORD> Z2
    {
        get
        {
            fixed(U_WORD* ptr = &_Z2[0])
            {
                return new Span<U_WORD>(ptr, Const.K_WORDS);
            }
        }
    }
    #endregion

    #region Fixed buffers
    [FieldOffset(0 * Const.K_WORDS * sizeof(U_WORD))]
    private unsafe fixed U_WORD _YpX[Const.K_WORDS];  
    [FieldOffset(1 * Const.K_WORDS * sizeof(U_WORD))]
    private unsafe fixed U_WORD _YmX[Const.K_WORDS];       
    [FieldOffset(2 * Const.K_WORDS * sizeof(U_WORD))]
    private unsafe fixed U_WORD _T2d[Const.K_WORDS]; 
    [FieldOffset(3 * Const.K_WORDS * sizeof(U_WORD))]
    private unsafe fixed U_WORD _Z2[Const.K_WORDS];
    /// <summary>
    /// Size of structure in bytes
    /// </summary>
    public const int TypeByteSz = 4 * Const.K_WORDS * sizeof(U_WORD);
    #endregion
    
    public PE_POINT(in M256 YpX, in M256 YmX, in M256 T2d, in M256 Z2)
    {
        YpX.words.CopyTo(this.YpX);
        YmX.words.CopyTo(this.YmX);
        T2d.words.CopyTo(this.T2d);
        Z2.words.CopyTo(this.Z2);
    }
}
