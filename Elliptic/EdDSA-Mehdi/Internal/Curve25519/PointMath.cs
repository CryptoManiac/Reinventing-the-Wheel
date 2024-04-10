using EdDSA_Mehdi.Internal.BaseTypes;
using EdDSA_Mehdi.Internal.Curve25519.Types;

namespace EdDSA_Mehdi.Internal.Curve25519;

/// <summary>
/// Point arithmetics
/// </summary>
public static partial class ECP
{
    /// <summary>
    /// X coordinate of base point
    /// </summary>
    public static M256V_U8 ecp_BasePoint = new ([
        9,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0
    ]);
    
    /// <summary>
    /// Y = X + X 
    /// </summary>
    /// <param name="Y"></param>
    /// <param name="???"></param>
    public static void ecp_MontDouble(ref XZ_POINT Y, in XZ_POINT X)
    {
        Span<U_WORD> A = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> B = stackalloc U_WORD[Const.K_WORDS];
        
        /*  x2 = (x+z)^2 * (x-z)^2 */
        /*  z2 = ((x+z)^2 - (x-z)^2)*((x+z)^2 + ((A-2)/4)((x+z)^2 - (x-z)^2)) */
        ecp_AddReduce(A, X.X, X.Z);       /* A = (x+z) */
        ecp_SubReduce(B, X.X, X.Z);       /* B = (x-z) */
        ecp_SqrReduce(A, A);                /* A = (x+z)^2 */
        ecp_SqrReduce(B, B);                /* B = (x-z)^2 */
        ecp_MulReduce(Y.X, A, B);          /* x2 = (x+z)^2 * (x-z)^2 */
        ecp_SubReduce(B, A, B);             /* B = (x+z)^2 - (x-z)^2 */
        /* (486662-2)/4 = 121665 */
        ecp_WordMulAddReduce(A, A, 121665, B);
        ecp_MulReduce(Y.Z, A, B);          /* z2 = (B)*((x+z)^2 + ((A-2)/4)(B)) */
    }
    
    /// <summary>
    /// P = P + Q, Q = 2Q
    /// </summary>
    /// <param name="P"></param>
    /// <param name="Q"></param>
    /// <param name="Base"></param>
    public static void ecp_Mont(ref XZ_POINT P, ref XZ_POINT Q, ReadOnlySpan<U_WORD> Base)
    {
        Span<U_WORD> A = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> B = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> C = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> D = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> E = stackalloc U_WORD[Const.K_WORDS];
        
        /* x3 = ((x1-z1)(x2+z2) + (x1+z1)(x2-z2))^2*zb     zb=1 */
        /* z3 = ((x1-z1)(x2+z2) - (x1+z1)(x2-z2))^2*xb     xb=Base */
        ecp_SubReduce(A, P.X, P.Z);   /* A = x1-z1 */
        ecp_AddReduce(B, P.X, P.Z);   /* B = x1+z1 */
        ecp_SubReduce(C, Q.X, Q.Z);   /* C = x2-z2 */
        ecp_AddReduce(D, Q.X, Q.Z);   /* D = x2+z2 */
        ecp_MulReduce(A, A, D);         /* A = (x1-z1)(x2+z2) */
        ecp_MulReduce(B, B, C);         /* B = (x1+z1)(x2-z2) */
        ecp_AddReduce(E, A, B);         /* E = (x1-z1)(x2+z2) + (x1+z1)(x2-z2) */
        ecp_SubReduce(B, A, B);         /* B = (x1-z1)(x2+z2) - (x1+z1)(x2-z2) */
        ecp_SqrReduce(P.X, E);         /* x3 = ((x1-z1)(x2+z2) + (x1+z1)(x2-z2))^2 */
        ecp_SqrReduce(A, B);            /* A = ((x1-z1)(x2+z2) - (x1+z1)(x2-z2))^2 */
        ecp_MulReduce(P.Z, A, Base);   /* z3 = ((x1-z1)(x2+z2) - (x1+z1)(x2-z2))^2*Base */

        /* x4 = (x2+z2)^2 * (x2-z2)^2 */
        /* z4 = ((x2+z2)^2 - (x2-z2)^2)*((x2+z2)^2 + 121665((x2+z2)^2 - (x2-z2)^2)) */
        /* C = (x2-z2) */
        /* D = (x2+z2) */
        ecp_SqrReduce(A, D);            /* A = (x2+z2)^2 */
        ecp_SqrReduce(B, C);            /* B = (x2-z2)^2 */
        ecp_MulReduce(Q.X, A, B);      /* x4 = (x2+z2)^2 * (x2-z2)^2 */
        ecp_SubReduce(B, A, B);         /* B = (x2+z2)^2 - (x2-z2)^2 */
        ecp_WordMulAddReduce(A, A, 121665, B);
        ecp_MulReduce(Q.Z, A, B);      /* z4 = B*((x2+z2)^2 + 121665*B) */
    }
}
