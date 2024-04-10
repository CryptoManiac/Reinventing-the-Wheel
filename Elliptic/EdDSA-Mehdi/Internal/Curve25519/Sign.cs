using EdDSA_Mehdi.Internal.BaseTypes;
using EdDSA_Mehdi.Internal.Curve25519.Types;

namespace EdDSA_Mehdi.Internal.Curve25519;

/// <summary>
/// Signing functions and related point arithmetic
/// </summary>
public static partial class ECP
{
    /// <summary>
    /// 2*d
    /// </summary>
    private static readonly M256 _w_2d = new(0x26B2F159,0xEBD69B94,0x8283B156,0x00E0149A,0xEEF3D130,0x198E80F2,0x56DFFCE7,0x2406D9DC);
    
    /// <summary>
    /// 1/d
    /// </summary>
    private static readonly M256 _w_di = new(0xCDC9F843,0x25E0F276,0x4279542E,0x0B5DD698,0xCDB9CF66,0x2B162114,0x14D5CE43,0x40907ED2);
    
    /// <summary>
    /// Reference: http://eprint.iacr.org/2008/522
    /// Cost: 7M + 7add
    /// Return: R = P + BasePoint
    /// </summary>
    /// <param name="p"></param>
    public static void edp_AddBasePoint(ref Ext_POINT p)
    {
        Span<U_WORD> a = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> b = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> c = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> d = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> e = stackalloc U_WORD[Const.K_WORDS];
        
        ecp_SubReduce(a, p.y, p.x);           /* A = (Y1-X1)*(Y2-X2) */
        ecp_MulReduce(a, a, _w_base_folding8[1].YmX);
        ecp_AddReduce(b, p.y, p.x);           /* B = (Y1+X1)*(Y2+X2) */
        ecp_MulReduce(b, b, _w_base_folding8[1].YpX);
        ecp_MulReduce(c, p.t, _w_base_folding8[1].T2d); /* C = T1*2d*T2 */
        ecp_AddReduce(d, p.z, p.z);           /* D = 2*Z1 */
        ecp_SubReduce(e, b, a);                 /* E = B-A */
        ecp_AddReduce(b, b, a);                 /* H = B+A */
        ecp_SubReduce(a, d, c);                 /* F = D-C */
        ecp_AddReduce(d, d, c);                 /* G = D+C */

        ecp_MulReduce(p.x, e, a);              /* E*F */
        ecp_MulReduce(p.y, b, d);              /* H*G */
        ecp_MulReduce(p.t, e, b);              /* E*H */
        ecp_MulReduce(p.z, d, a);              /* G*F */
    }
    
    /// <summary>
    /// Assumptions: pre-computed q, q.Z=1
    /// Cost: 7M + 7add
    /// Return: P = P + Q
    /// </summary>
    /// <param name="p"></param>
    /// <param name="q"></param>
    public static void edp_AddAffinePoint(ref Ext_POINT p, in PA_POINT q)
    {
        Span<U_WORD> a = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> b = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> c = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> d = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> e = stackalloc U_WORD[Const.K_WORDS];

        ecp_SubReduce(a, p.y, p.x);           /* A = (Y1-X1)*(Y2-X2) */
        ecp_MulReduce(a, a, q.YmX);
        ecp_AddReduce(b, p.y, p.x);           /* B = (Y1+X1)*(Y2+X2) */
        ecp_MulReduce(b, b, q.YpX);
        ecp_MulReduce(c, p.t, q.T2d);         /* C = T1*2d*T2 */
        ecp_AddReduce(d, p.z, p.z);           /* D = Z1*2*Z2 (Z2=1)*/
        ecp_SubReduce(e, b, a);                 /* E = B-A */
        ecp_AddReduce(b, b, a);                 /* H = B+A */
        ecp_SubReduce(a, d, c);                 /* F = D-C */
        ecp_AddReduce(d, d, c);                 /* G = D+C */

        ecp_MulReduce(p.x, e, a);              /* E*F */
        ecp_MulReduce(p.y, b, d);              /* H*G */
        ecp_MulReduce(p.t, e, b);              /* E*H */
        ecp_MulReduce(p.z, d, a);              /* G*F */
    }
    
    /// <summary>
    /// Reference: http://eprint.iacr.org/2008/522
    /// Cost: 4M + 4S + 7add
    /// Return: P = 2*P
    /// </summary>
    /// <param name="p"></param>
    public static void edp_DoublePoint(ref Ext_POINT p)
    {
        Span<U_WORD> a = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> b = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> c = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> d = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> e = stackalloc U_WORD[Const.K_WORDS];

        ecp_SqrReduce(a, p.x);         /* A = X1^2 */
        ecp_SqrReduce(b, p.y);         /* B = Y1^2 */
        ecp_SqrReduce(c, p.z);         /* C = 2*Z1^2 */
        ecp_AddReduce(c, c, c);
        ecp_SubReduce(d, _w_maxP.words, a);   /* D = -A */

        ecp_SubReduce(a, d, b);         /* H = D-B */
        ecp_AddReduce(d, d, b);         /* G = D+B */
        ecp_SubReduce(b, d, c);         /* F = G-C */
        ecp_AddReduce(e, p.x, p.y);   /* E = (X1+Y1)^2-A-B = (X1+Y1)^2+H */
        ecp_SqrReduce(e, e);
        ecp_AddReduce(e, e, a);

        ecp_MulReduce(p.x, e, b);      /* E*F */
        ecp_MulReduce(p.y, a, d);      /* H*G */
        ecp_MulReduce(p.z, d, b);      /* G*F */
        ecp_MulReduce(p.t, e, a);      /* E*H */
    }
    
    //---- -- FOLDING ------------------------------------------------------------
    //
    //    The performance boost is achieved by a process that I call it FOLDING.
    //    Folding can be viewed as an extension of Shamir's trick but it is based
    //    on break down of the scalar multiplier of a*P into a polynomial of the
    //    form:
    //
    //        a*P = SUM(a_i*2^(i*w))*P    for i = 0,1,2,...n-1
    //
    //        a*P = SUM(a_i*P_i)
    //
    //        where P_i = (2^(i*w))*P
    //              n = number of folds
    //              w = bit-length of a_i
    //
    //    For folding of 8, 256-bit multiplier 'a' is chopped into 8 limbs of
    //    32-bits each (a_0, a_1,...a_7). P_0 - P_7 can be pre-calculated and
    //    their 256-different permutations can be cached or hard-coded
    //    directly into the code.
    //    This arrangement combined with double-and-add approach reduces the
    //    number of EC point calculations by a factor of 8. We only need 31
    //    double & add operations.
    //
    //       +---+---+---+---+---+---+- .... -+---+---+---+---+---+---+
    //  a = (|255|254|253|252|251|250|        | 5 | 4 | 3 | 2 | 1 | 0 |)
    //       +---+---+---+---+---+---+- .... -+---+---+---+---+---+---+
    //
    //                     a_i                       P_i
    //       +---+---+---+ .... -+---+---+---+    ----------
    // a7 = (|255|254|253|       |226|225|224|) * (2**224)*P
    //       +---+---+---+ .... -+---+---+---+
    // a6 = (|225|224|223|       |194|193|192|) * (2**192)*P
    //       +---+---+---+ .... -+---+---+---+
    // a5 = (|191|190|189|       |162|161|160|) * (2**160)*P
    //       +---+---+---+ .... -+---+---+---+
    // a4 = (|159|158|157|       |130|129|128|) * (2**128)*P
    //       +---+---+---+ .... -+---+---+---+
    // a3 = (|127|126|125|       | 98| 97| 96|) * (2**96)*P
    //       +---+---+---+ .... -+---+---+---+
    // a2 = (| 95| 94| 93|       | 66| 65| 64|) * (2**64)*P
    //       +---+---+---+ .... -+---+---+---+
    // a1 = (| 63| 62| 61|       | 34| 33| 32|) * (2**32)*P
    //       +---+---+---+ .... -+---+---+---+
    // a0 = (| 31| 30| 29|       | 2 | 1 | 0 |) * (2**0)*P
    //       +---+---+---+ .... -+---+---+---+
    //         |   |                   |   |
    //         |   +--+                |   +--+
    //         |      |                |      |
    //         V      V     slices     V      V
    //       +---+  +---+    ....    +---+  +---+
    //       |255|  |254|            |225|  |224|   P7
    //       +---+  +---+    ....    +---+  +---+
    //       |225|  |224|            |193|  |192|   P6
    //       +---+  +---+    ....    +---+  +---+
    //       |191|  |190|            |161|  |160|   P5
    //       +---+  +---+    ....    +---+  +---+
    //       |159|  |158|            |129|  |128|   P4
    //       +---+  +---+    ....    +---+  +---+
    //       |127|  |126|            | 97|  | 96|   P3
    //       +---+  +---+    ....    +---+  +---+
    //       | 95|  | 94|            | 65|  | 64|   P2
    //       +---+  +---+    ....    +---+  +---+
    //       | 63|  | 62|            | 33|  | 32|   P1
    //       +---+  +---+    ....    +---+  +---+
    //       | 31|  | 30|            | 1 |  | 0 |   P0
    //       +---+  +---+    ....    +---+  +---+
    // cut[]:  0      1      ....      30     31
    // --------------------------------------------------------------------------
    // Return S = a*P where P is ed25519 base point and R is random

    /// <summary>
    /// S = a*P where P is ed25519 base point and R is random
    /// </summary>
    /// <param name="S"></param>
    /// <param name="sk"></param>
    /// <param name="R"></param>
    public static void edp_BasePointMult(ref Ext_POINT S, ReadOnlySpan<U_WORD> sk, ReadOnlySpan<U_WORD> R)
    {
        int i = 1;
        Span<U8> cut = stackalloc U8[32];

        ecp_8Folds(cut, sk);

        ref PA_POINT p0 = ref _w_base_folding8[cut[0]];

        ecp_SubReduce(S.x, p0.YpX, p0.YmX);  /* 2x */
        ecp_AddReduce(S.y, p0.YpX, p0.YmX);  /* 2y */
        ecp_MulReduce(S.t, p0.T2d, _w_di.words);    /* 2xy */

        /* Randomize starting point */

        ecp_AddReduce(S.z, R, R);              /* Z = 2R */
        ecp_MulReduce(S.x, S.x, R);           /* X = 2xR */
        ecp_MulReduce(S.t, S.t, R);           /* T = 2xyR */
        ecp_MulReduce(S.y, S.y, R);           /* Y = 2yR */

        do 
        {
            edp_DoublePoint(ref S);
            edp_AddAffinePoint(ref S, _w_base_folding8[cut[i]]);
        } while (i++ < 31);
    }

    public static void edp_BasePointMultiply(ref Affine_POINT R, ReadOnlySpan<U_WORD> sk)
    {
        Ext_POINT S;
        edp_BasePointMult(ref S, sk, edp_custom_blinding.zr);
        ecp_Inverse(S.z, S.z);
        ecp_MulMod(R.x, S.x, S.z);
        ecp_MulMod(R.y, S.y, S.z);
    }

    public static void edp_BasePointMultiply(ref Affine_POINT R, ReadOnlySpan<U_WORD> sk, in EDP_BLINDING_CTX blinding)
    {
        Ext_POINT S;
        Span<U_WORD> t = stackalloc U_WORD[Const.K_WORDS];

        eco_AddReduce(t, sk, blinding.bl);
        edp_BasePointMult(ref S, t, blinding.zr);
        edp_AddPoint(ref S, S, blinding.BP);

        ecp_Inverse(S.z, S.z);
        ecp_MulMod(R.x, S.x, S.z);
        ecp_MulMod(R.y, S.y, S.z);
    }

    public static void edp_ExtPoint2PE(ref PE_POINT r, in Ext_POINT p)
    {
        ecp_AddReduce(r.YpX, p.y, p.x);
        ecp_SubReduce(r.YmX, p.y, p.x);
        ecp_MulReduce(r.T2d, p.t, _w_2d.words);
        ecp_AddReduce(r.Z2, p.z, p.z);
    }
}
