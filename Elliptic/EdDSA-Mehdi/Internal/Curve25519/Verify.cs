using System.Runtime.InteropServices;
using EdDSA_Mehdi.Internal.BaseTypes;
using EdDSA_Mehdi.Internal.Curve25519.Types;
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
    public static void ed25519_PackPoint(Span<U8> buff, ReadOnlySpan<uint> Y, uint parity)
    {
        ecp_EncodeInt(buff, Y, (U8)(parity & 1));
    }

    /// <summary>
    /// Assumptions: pre-computed q
    /// Cost: 8M + 6add
    /// Return: P = P + Q
    /// </summary>
    /// <param name="r"></param>
    /// <param name="p"></param>
    /// <param name="q"></param>
    public static void edp_AddPoint(ref Ext_POINT r, in Ext_POINT p, in PE_POINT q)
    {
        Span<U_WORD> a = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> b = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> c = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> d = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> e = stackalloc U_WORD[Const.K_WORDS];

        ecp_SubReduce(a, p.y, p.x); /* A = (Y1-X1)*(Y2-X2) */
        ecp_MulReduce(a, a, q.YmX);
        ecp_AddReduce(b, p.y, p.x); /* B = (Y1+X1)*(Y2+X2) */
        ecp_MulReduce(b, b, q.YpX);
        ecp_MulReduce(c, p.t, q.T2d); /* C = T1*2d*T2 */
        ecp_MulReduce(d, p.z, q.Z2); /* D = Z1*2*Z2 */
        ecp_SubReduce(e, b, a); /* E = B-A */
        ecp_AddReduce(b, b, a); /* H = B+A */
        ecp_SubReduce(a, d, c); /* F = D-C */
        ecp_AddReduce(d, d, c); /* G = D+C */

        ecp_MulReduce(r.x, e, a); /* E*F */
        ecp_MulReduce(r.y, b, d); /* H*G */
        ecp_MulReduce(r.t, e, b); /* E*H */
        ecp_MulReduce(r.z, d, a); /* G*F */
    }

    public static void ecp_ModExp2523(Span<U_WORD> Y, ReadOnlySpan<U_WORD> X)
    {
        Span<U_WORD> x2 = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> x5 = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> x9 = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> x10 = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> x11 = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> x20 = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> x50 = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> x100 = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> t = stackalloc U_WORD[Const.K_WORDS];

        ecp_SqrReduce(x2, X); /* 2 */
        ecp_SrqMulReduce(x9, x2, 2, X); /* 9 */
        ecp_MulReduce(x11, x9, x2); /* 11 */
        ecp_SqrReduce(t, x11); /* 22 */
        ecp_MulReduce(x5, t, x9); /* 31 = 2^5 - 2^0 */
        ecp_SrqMulReduce(x10, x5, 5, x5); /* 2^10 - 2^0 */
        ecp_SrqMulReduce(x20, x10, 10, x10); /* 2^20 - 2^0 */
        ecp_SrqMulReduce(t, x20, 20, x20); /* 2^40 - 2^0 */
        ecp_SrqMulReduce(x50, t, 10, x10); /* 2^50 - 2^0 */
        ecp_SrqMulReduce(x100, x50, 50, x50); /* 2^100 - 2^0 */
        ecp_SrqMulReduce(t, x100, 100, x100); /* 2^200 - 2^0 */
        ecp_SrqMulReduce(t, t, 50, x50); /* 2^250 - 2^0 */
        ecp_SqrReduce(t, t);
        ecp_SqrReduce(t, t); /* 2^252 - 2^2 */
        ecp_MulReduce(Y, t, X); /* 2^252 - 3 */
    }

    public static void ed25519_CalculateX(Span<U_WORD> X, ReadOnlySpan<U_WORD> Y, U_WORD parity)
    {
        Span<U_WORD> u = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> v = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> a = stackalloc U_WORD[Const.K_WORDS];
        Span<U_WORD> b = stackalloc U_WORD[Const.K_WORDS];

        /* Calculate sqrt((y^2 - 1)/(d*y^2 + 1)) */

        ecp_SqrReduce(u, Y); /* u = y^2 */
        ecp_MulReduce(v, u, Const._w_d.words); /* v = dy^2 */
        ecp_SubReduce(u, u, Const._w_One); /* u = y^2-1 */
        ecp_AddReduce(v, v, Const._w_One); /* v = dy^2+1 */

        /* Calculate:  sqrt(u/v) = u*v^3 * (u*v^7)^((p-5)/8) */

        ecp_SqrReduce(b, v);
        ecp_MulReduce(a, u, b);
        ecp_MulReduce(a, a, v); /* a = u*v^3 */
        ecp_SqrReduce(b, b); /* b = v^4 */
        ecp_MulReduce(b, a, b); /* b = u*v^7 */
        ecp_ModExp2523(b, b);
        ecp_MulReduce(X, b, a);

        /* Check if we have correct sqrt, else, multiply by sqrt(-1) */

        ecp_SqrReduce(b, X);
        ecp_MulReduce(b, b, v);
        ecp_SubReduce(b, b, u);
        ecp_Mod(b);

        if (0 != ecp_CmpNE(b, Const._w_Zero))
        {
            ecp_MulReduce(X, X, Const._w_I.words);
        }

        while (ecp_CmpLT(X, Const._w_P.words) == 0) ecp_Sub(X, X, Const._w_P.words);

        /* match parity */
        if (((X[0] ^ parity) & 1) != 0)
        {
            ecp_Sub(X, Const._w_P.words, X);
        }
    }

    public static void ecp_SrqMulReduce(Span<U_WORD> Z, ReadOnlySpan<U_WORD> X, int n, ReadOnlySpan<U_WORD> Y)
    {
        Span<U_WORD> t = stackalloc U_WORD[Const.K_WORDS];
        ecp_SqrReduce(t, X);
        while (n-- > 1)
        {
            ecp_SqrReduce(t, t);
        }

        ecp_MulReduce(Z, t, Y);
    }

    public static void ed25519_UnpackPoint(ref Affine_POINT r, ReadOnlySpan<U8> p)
    {
        U8 parity = ecp_DecodeInt(r.y, p);
        ed25519_CalculateX(r.x, r.y, parity);
    }

    public static void edp_PolyPointMultiply(ref Affine_POINT r, ReadOnlySpan<U_WORD> a, ReadOnlySpan<U_WORD> b, ReadOnlySpan<PE_POINT> qtable)
    {
        int i = 1;
        Ext_POINT S;

        Span<U8> u = stackalloc U8[32];
        Span<U8> v = stackalloc U8[64];

        ecp_8Folds(u, a);
        ecp_4Folds(v, b);

        /* Set initial value of S */
        PE_POINT q0 = qtable[v[0]];
        ecp_SubReduce(S.x, q0.YpX, q0.YmX); /* 2x */
        ecp_AddReduce(S.y, q0.YpX, q0.YmX); /* 2y */
        ecp_MulReduce(S.t, q0.T2d, Const._w_di.words); /* 2xy */
        ecp_Copy(S.z, q0.Z2); /* 2z */

        do
        {
            /* 31D + 31A */
            edp_DoublePoint(ref S);
            edp_AddPoint(ref S, S, qtable[v[i]]);
        } while (++i < 32);

        do
        {
            /* 32D + 64A */
            edp_DoublePoint(ref S);
            edp_AddAffinePoint(ref S, Const._w_base_folding8[u[i - 32]]);
            edp_AddPoint(ref S, S, qtable[v[i]]);
        } while (++i < 64);

        ecp_Inverse(S.z, S.z);
        ecp_MulMod(r.x, S.x, S.z);
        ecp_MulMod(r.y, S.y, S.z);
    }

    /*
    /// <summary>
    /// Calculate signature challenge H(enc(R) + pk + m)
    /// </summary>
    /// <param name="hram"></param>
    /// <param name="R"></param>
    /// <param name="A"></param>
    /// <param name="m"></param>
    public static void HRAM_SHA2(Span<U8> hram, ReadOnlySpan<U8> R, ReadOnlySpan<U8> A, ReadOnlySpan<U8> m)
    {
        SHA512 ctx = new();
        ctx.Update(R);
        ctx.Update(A);
        ctx.Update(m);
        ctx.Digest(hram);
    }

    /// <summary>
    /// Calculate signature challenge H(enc(R) + pk + m)
    /// </summary>
    /// <param name="hram"></param>
    /// <param name="R"></param>
    /// <param name="A"></param>
    /// <param name="m"></param>
    public static void HRAM_SHA3(Span<U8> hram, ReadOnlySpan<U8> R, ReadOnlySpan<U8> A, ReadOnlySpan<U8> m)
    {
        SHA3_512 ctx = new();
        ctx.Update(R);
        ctx.Update(A);
        ctx.Update(m);
        ctx.Digest(hram);
    }

    /// <summary>
    /// Calculate signature challenge H(enc(R) + pk + m)
    /// </summary>
    /// <param name="hram"></param>
    /// <param name="R"></param>
    /// <param name="A"></param>
    /// <param name="m"></param>
    public static void HRAM_KECCAK(Span<U8> hram, ReadOnlySpan<U8> R, ReadOnlySpan<U8> A, ReadOnlySpan<U8> m)
    {
        Keccak_512 ctx = new();
        ctx.Update(R);
        ctx.Update(A);
        ctx.Update(m);
        ctx.Digest(hram);
    }*/

    /// <summary>
    /// Constant-time comparison
    /// </summary>
    /// <param name="x"></param>
    /// <param name="y"></param>
    /// <param name="len"></param>
    /// <returns></returns>
    public static bool Equals(ReadOnlySpan<U8> x, ReadOnlySpan<U8> y, int len)
    {
        int diff = 0;
        for (int i = 0; i != len; ++i)
        {
            diff |= x[i] ^ y[i];
        }
        return !Convert.ToBoolean(diff);
    }
}
