using EdDSA_Mehdi.Internal.BaseTypes;
using EdDSA_Mehdi.Internal.Curve25519.Types;
using Hashing.Hashing.HMAC;
using Wheel.Hashing.SHA.SHA512;
using Wheel.Hashing.SHA3;

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
        ecp_MulReduce(a, a, Const._w_base_folding8[1].YmX);
        ecp_AddReduce(b, p.y, p.x);           /* B = (Y1+X1)*(Y2+X2) */
        ecp_MulReduce(b, b, Const._w_base_folding8[1].YpX);
        ecp_MulReduce(c, p.t, Const._w_base_folding8[1].T2d); /* C = T1*2d*T2 */
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
        ecp_SubReduce(d, Const._w_maxP.words, a);   /* D = -A */

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

        ref PA_POINT p0 = ref Const._w_base_folding8[cut[0]];

        ecp_SubReduce(S.x, p0.YpX, p0.YmX);  /* 2x */
        ecp_AddReduce(S.y, p0.YpX, p0.YmX);  /* 2y */
        ecp_MulReduce(S.t, p0.T2d, Const._w_di.words);    /* 2xy */

        /* Randomize starting point */

        ecp_AddReduce(S.z, R, R);              /* Z = 2R */
        ecp_MulReduce(S.x, S.x, R);           /* X = 2xR */
        ecp_MulReduce(S.t, S.t, R);           /* T = 2xyR */
        ecp_MulReduce(S.y, S.y, R);           /* Y = 2yR */

        do 
        {
            edp_DoublePoint(ref S);
            edp_AddAffinePoint(ref S, Const._w_base_folding8[cut[i]]);
        } while (i++ < 31);
    }

    public static void edp_BasePointMultiply(ref Affine_POINT R, ReadOnlySpan<U_WORD> sk)
    {
        Ext_POINT S;
        edp_BasePointMult(ref S, sk, EDP_BLINDING_CTX.edp_custom_blinding.zr);
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
        ecp_MulReduce(r.T2d, p.t, Const._w_2d.words);
        ecp_AddReduce(r.Z2, p.z, p.z);
    }
    
    /// <summary>
    /// Generate public key associated with the secret key
    /// </summary>
    /// <param name="pubKey">OUT: [32 bytes] public key</param>
    /// <param name="privKey">IN/OUT: [32 bytes] private key</param>
    /// <param name="blinding">blinding context</param>
    public static void ed25519_CalculatePublicKey(Span<U8> pubKey, Span<U8> privKey, in EDP_BLINDING_CTX blinding)
    {
        ecp_TrimSecretKey(privKey[0 .. 32]);
        Span<U_WORD> t = stackalloc U_WORD[Const.K_WORDS];
        Affine_POINT Q;
        ecp_BytesToWords(t, privKey);
        edp_BasePointMultiply(ref Q, t, blinding);
        ed25519_PackPoint(pubKey[..32], Q.y, Q.x[0]);
    }
    
    /*
    /// <summary>
    /// Calculate signature nonce HMAC_sk(m) mod BPO
    /// </summary>
    /// <param name="nonce">OUT: Secret nonce</param>
    /// <param name="sk">IN: [32 bytes] Secret key</param>
    /// <param name="m">IN: [32 bytes] Message</param>
    public static void HNONCE_SHA2(Span<U_WORD> nonce, ReadOnlySpan<U8> sk, ReadOnlySpan<U8> m)
    {
        HMAC<SHA512> ctx = new();
        Span<U8> md = stackalloc U8[ctx.HashSz];
        ctx.Init(sk);
        ctx.Update(m);

        ctx.Digest(md);
        eco_DigestToWords(nonce, md);
        eco_Mod(nonce); // nonce mod BPO
        ctx.Dispose();
    }

    /// <summary>
    /// Calculate signature nonce HMAC_sk(m) mod BPO
    /// </summary>
    /// <param name="nonce">OUT: Secret nonce</param>
    /// <param name="sk">IN: [32 bytes] Secret key</param>
    /// <param name="m">IN: [32 bytes] Message</param>
    public static void HNONCE_SHA3(Span<U_WORD> nonce, ReadOnlySpan<U8> sk, ReadOnlySpan<U8> m)
    {
        HMAC<SHA3_512> ctx = new();
        Span<U8> md = stackalloc U8[ctx.HashSz];
        ctx.Init(sk);
        ctx.Update(m);

        ctx.Digest(md);
        eco_DigestToWords(nonce, md);
        eco_Mod(nonce); // nonce mod BPO
        ctx.Dispose();
    }

    /// <summary>
    /// Calculate signature nonce HMAC_sk(m) mod BPO
    /// </summary>
    /// <param name="nonce">OUT: Secret nonce</param>
    /// <param name="sk">IN: [32 bytes] Secret key</param>
    /// <param name="m">IN: [32 bytes] Message</param>
    public static void HNONCE_KECCAK(Span<U_WORD> nonce, ReadOnlySpan<U8> sk, ReadOnlySpan<U8> m)
    {
        HMAC<Keccak_512> ctx = new();
        Span<U8> md = stackalloc U8[ctx.HashSz];
        ctx.Init(sk);
        ctx.Update(m);

        ctx.Digest(md);
        eco_DigestToWords(nonce, md);
        eco_Mod(nonce); // nonce mod BPO
        ctx.Dispose();
    }*/
}
