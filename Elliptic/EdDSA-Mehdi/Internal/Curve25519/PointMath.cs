using EdDSA_Mehdi.Internal.BaseTypes;
using EdDSA_Mehdi.Internal.Curve25519.Types;

namespace EdDSA_Mehdi.Internal.Curve25519;

/*
 * Arithmetic on twisted Edwards curve y^2 - x^2 = 1 + dx^2y^2
 * with d = -(121665/121666) mod p
 *      d = 0x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3
 *      p = 2**255 - 19
 *      p = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED
 * Base point: y=4/5 mod p
 *      x = 0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A
 *      y = 0x6666666666666666666666666666666666666666666666666666666666666658
 * Base point order:
 *      l = 2**252 + 27742317777372353535851937790883648493
 *      l = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
 */
public static partial class ECP
{
    /// <summary>
    /// X coordinate of base point
    /// </summary>
    public static M256V_U8 ecp_BasePoint = new (
        9,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0
    );
    
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
    
    private static unsafe void ECP_MONT(int n, int k, ref int j, ReadOnlySpan<nuint> PP, ReadOnlySpan<nuint> QP, ReadOnlySpan<U_WORD> X)
    {
        j = (k >> n) & 1;
        XZ_POINT* P = (XZ_POINT*) PP[j].ToPointer();
        XZ_POINT* Q = (XZ_POINT*) QP[j].ToPointer();
        ecp_Mont(ref *P, ref *Q, X);
    }
    
    public static void ecp_PointMultiply(Span<U8> PublicKey, ReadOnlySpan<U8> BasePoint, ReadOnlySpan<U8> SecretKey, int len)
    {
        int i, j = 0, k;
        XZ_POINT P, Q;
        Span<U_WORD> X = stackalloc U_WORD[Const.K_WORDS];
        Span<nuint> PP = stackalloc nuint[2];
        Span<nuint> QP = stackalloc nuint[2];

        ecp_BytesToWords(X, BasePoint);

        /* 1: P = (2k+1)G, Q = (2k+2)G */
        /* 0: Q = (2k+1)G, P = (2k)G */

        /* Find first non-zero bit */
        while (len-- > 0)
        {
            k = SecretKey[len];
            for (i = 0; i < 8; i++, k <<= 1)
            {
                /* P = kG, Q = (k+1)G */
                if (Convert.ToBoolean(k & 0x80))
                {
                    /* We have first non-zero bit
                    // This is always bit 254 for keys created according to the spec.
                    // Start with randomized base point
                    */

                    ecp_Add(P.Z, X, edp_custom_blinding.zr);    /* P.Z = random */
                    ecp_MulReduce(P.X, X, P.Z);
                    ecp_MontDouble(ref Q,  P);

                    //PP[1] = &P; PP[0] = &Q;
                    //QP[1] = &Q; QP[0] = &P;

                    unsafe
                    {
                        PP[1] = new nuint(&P); PP[0] = new nuint(&Q);
                        PP[1] = new nuint(&Q); PP[0] = new nuint(&P);
                    }
                    
                    /* Everything we reference in the below loop are on the stack
                    // and already touched (cached)
                    */

                    while (++i < 8)
                    {
                        k <<= 1; 
                        ECP_MONT(7, k, ref j, PP, QP, X);
                    }
                    while (len > 0)
                    {
                        k = SecretKey[--len];
                        ECP_MONT(7, k, ref j, PP, QP, X);
                        ECP_MONT(6, k, ref j, PP, QP, X);
                        ECP_MONT(5, k, ref j, PP, QP, X);
                        ECP_MONT(4, k, ref j, PP, QP, X);
                        ECP_MONT(3, k, ref j, PP, QP, X);
                        ECP_MONT(2, k, ref j, PP, QP, X);
                        ECP_MONT(1, k, ref j, PP, QP, X);
                        ECP_MONT(0, k, ref j, PP, QP, X);
                    }

                    ecp_Inverse(Q.Z, P.Z);
                    ecp_MulMod(X, P.X, Q.Z);
                    ecp_WordsToBytes(PublicKey, X);
                    return;
                }
            }
        }
        /* K is 0 */
        PublicKey.Clear();
    }
}
