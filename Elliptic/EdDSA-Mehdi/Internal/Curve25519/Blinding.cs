using System.Runtime.InteropServices;
using EdDSA_Mehdi.Internal.Curve25519.Types;
using Wheel.Hashing.SHA.SHA512;

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
    /// Blinding is a measure to protect against side channel attacks.
    /// Blinding randomizes the scalar multiplier.
    ///
    /// Instead of calculating a*P, calculate (a+b mod BPO)*P + B
    /// Where b = random blinding and B = -b*P
    /// </summary>
    /// <param name="context">blinding context</param>
    /// <param name="seed">random blinding seed</param>
    public static void ed25519_Blinding_Init(ref EDP_BLINDING_CTX ctx, Span<U8> seed)
    {
        SHA512 H = new();

        Ext_POINT T;
        Span<U_WORD> t = stackalloc U_WORD[Const.K_WORDS];
        Span<U8> digest = stackalloc U8[H.HashSz];

        /* Use edp_custom_blinding to protect generation of the new blinder */

        H.Update(MemoryMarshal.Cast<U_WORD, U8>(edp_custom_blinding.zr));
        H.Update(seed);
        H.Digest(digest);

        ecp_BytesToWords(ctx.zr, digest[32..]);
        ecp_BytesToWords(t, digest);
        eco_Mod(t);
        ecp_Sub(ctx.bl, _w_BPO, t);

        eco_AddReduce(t, t, edp_custom_blinding.bl);
        edp_BasePointMult(ref T, t, edp_custom_blinding.zr);
        edp_AddPoint(ref T, T, edp_custom_blinding.BP);

        edp_ExtPoint2PE(ref ctx.BP, T);

        /* clear potentially sensitive data */
        t.Clear();
        digest.Clear();
    }
}
