using System.Runtime.InteropServices;
using EdDSA_Mehdi.Internal.BaseTypes;
using Wheel.Crypto.Elliptic.EllipticCommon;
using Wheel.Hashing.SHA.SHA512;

namespace EdDSA_Mehdi.Internal.Curve25519.Types;

/// <summary>
/// Blinding is a measure to protect against side channel attacks.
/// Blinding randomizes the scalar multiplier.
///
/// Instead of calculating a*P, calculate (a+b mod BPO)*P + B
/// Where b = random blinding and B = -b*P
/// </summary>
[StructLayout(LayoutKind.Explicit)]
public struct EDP_BLINDING_CTX
{
    #region Preconfigured blinding context
    public readonly static EDP_BLINDING_CTX edp_custom_blinding = new(
    new(0xD3BDA75F, 0x2104B751, 0x93294683, 0x673355BD, 0x0D730DE4, 0x512E2FB3, 0x4F879DE4, 0x098B4071),
    new(0x9F026A7F, 0xEF60AAC3, 0x788B32C2, 0xC452E263, 0x9EAF4281, 0xC57630C2, 0x66274C37, 0x9899945C),
    new(
        new(0xEAF3D972, 0x98224406, 0x14A60F11, 0x3511B9B5, 0x41932314, 0x666BF84C, 0xF9F5C216, 0xD364D819),
        new(0xFAB824FE, 0x0F3E7C52, 0x381C2D0F, 0x75FA75B5, 0xE835CD75, 0xEA65EE4C, 0x54C29198, 0xD1F07420),
        new(0xDB4B3B6A, 0x6E7BDC9C, 0x930BF754, 0x292D7D2B, 0xB360E07C, 0x32F9D0E1, 0x54D4FAC4, 0x7B700942),
        new(0x576E1548, 0x73AC6A00, 0xE00DF285, 0x2B269255, 0xD2A64215, 0xF8202335, 0xAFEBAAC5, 0xF408857A)
        )
    );
    #endregion

    #region Safe access wrappers
    public readonly unsafe Span<U_WORD> bl
    {
        get
        {
            fixed(U_WORD* ptr = &_bl[0])
            {
                return new Span<U_WORD>(ptr, Const.K_WORDS);
            }
        }
    }
    
    public readonly unsafe Span<U_WORD> zr
    {
        get
        {
            fixed(U_WORD* ptr = &_zr[0])
            {
                return new Span<U_WORD>(ptr, Const.K_WORDS);
            }
        }
    }
    #endregion
    
    #region Fixed buffers
    [FieldOffset(0 * Const.K_WORDS * sizeof(U_WORD))]
    private unsafe fixed U_WORD _bl[Const.K_WORDS];
    [FieldOffset(1 * Const.K_WORDS * sizeof(U_WORD))]
    private unsafe fixed U_WORD _zr[Const.K_WORDS];
    /// <summary>
    /// Size of structure in bytes
    /// </summary>
    public const int TypeByteSz = 2 * Const.K_WORDS * sizeof(U_WORD);
    #endregion

    /// <summary>
    /// Blinding point coordinates
    /// </summary>
    [FieldOffset(2 * Const.K_WORDS * sizeof(U_WORD))]
    public PE_POINT BP;

    /// <summary>
    /// Initialize a configured context
    /// </summary>
    /// <param name="bl"></param>
    /// <param name="zr"></param>
    /// <param name="BP"></param>
    public EDP_BLINDING_CTX(in M256 bl, in M256 zr, in PE_POINT BP)
    {
        bl.words.CopyTo(this.bl);
        zr.words.CopyTo(this.zr);
        this.BP = BP;
    }

    /// <summary>
    /// Initialize a random context
    /// </summary>
    public EDP_BLINDING_CTX()
    {
        // New random blinding seed
        Span<U8> random_seed = stackalloc U8[64];
        RNG.Fill(random_seed);

        /* Use edp_custom_blinding to protect generation of the new blinder */

        SHA512 ctx = new();
        ctx.Update(MemoryMarshal.Cast<U_WORD, U8>(edp_custom_blinding.zr));
        ctx.Update(random_seed);
        Span<U8> digest = stackalloc U8[ctx.HashSz];
        ctx.Digest(digest);

        ECP.ecp_BytesToWords(zr, digest[32..]);

        Span<U_WORD> t = stackalloc U_WORD[Const.K_WORDS];
        ECP.ecp_BytesToWords(t, digest);
        ECP.eco_Mod(t);
        ECP.ecp_Sub(bl, Const._w_BPO, t);

        ECP.eco_AddReduce(t, t, edp_custom_blinding.bl);

        Ext_POINT T;
        ECP.edp_BasePointMult(ref T, t, edp_custom_blinding.zr);
        ECP.edp_AddPoint(ref T, T, edp_custom_blinding.BP);

        ECP.edp_ExtPoint2PE(ref BP, T);

        /* clear potentially sensitive data */
        t.Clear();
        digest.Clear();
    }
}
