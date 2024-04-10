using System.Runtime.InteropServices;

namespace EdDSA_Mehdi.Internal.Curve25519.Types;

/// <summary>
/// The curve used is y2 = x^3 + 486662x^2 + x, a Montgomery curve, over 
/// the prime field defined by the prime number 2^255 - 19, and it uses the 
/// base point x = 9. 
///     Protocol uses compressed elliptic point (only X coordinates), so it 
/// allows for efficient use of the Montgomery ladder for ECDH, using only 
///     XZ coordinates.
/// 
///     The curve is birationally equivalent to Ed25519 (Twisted Edwards curve).
/// 
/// b = 256
/// p = 2**255 - 19
/// l = 2**252 + 27742317777372353535851937790883648493
/// </summary>
[StructLayout(LayoutKind.Explicit)]
public struct XZ_POINT
{
    #region Safe access wrappers
    /// <summary>
    /// x/z
    /// </summary>
    public readonly unsafe Span<U_WORD> X
    {
        get
        {
            fixed(U_WORD* ptr = &_X[0])
            {
                return new Span<U_WORD>(ptr, Const.K_WORDS);
            }
        }
    }
    
    public readonly unsafe Span<U_WORD> Z
    {
        get
        {
            fixed(U_WORD* ptr = &_Z[0])
            {
                return new Span<U_WORD>(ptr, Const.K_WORDS);
            }
        }
    }
    
    #endregion
    #region Fixed buffers
    [FieldOffset(0 * Const.K_WORDS * sizeof(U_WORD))]
    private unsafe fixed U_WORD _X[Const.K_WORDS];
    [FieldOffset(1 * Const.K_WORDS * sizeof(U_WORD))]
    private unsafe fixed U_WORD _Z[Const.K_WORDS];
    /// <summary>
    /// Size of structure in bytes
    /// </summary>
    public const int TypeByteSz = 2 * Const.K_WORDS * sizeof(U_WORD);
    #endregion
}