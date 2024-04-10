using EdDSA_Mehdi.Internal.BaseTypes;

namespace EdDSA_Mehdi.Internal.Curve25519;

/// <summary>
/// This part provides support for mod BPO (Base Point Order) operations
/// BPO = 2**252 + 27742317777372353535851937790883648493
/// BPO = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
///
/// If you keep adding points together, the result repeats every BPO times.
///     Based on this, you may use:
///
/// public_key = (private_key mod BPO)*BasePoint
///     Split key example:
/// k1 = random()
/// k2 = 1/k1 mod BPO   --> k1*k2 = 1 mod BPO
/// P1 = k1*P0 --> P2 = k2*P1 = k2*k1*P0 = P0
/// See selftest code for some examples of BPO usage
///
///     This library is used for implementation of EdDSA sign/verify.
/// </summary>
public static partial class ECP
{
    /// <summary>
    /// n * BPO
    /// </summary>
    private static readonly M256[] _w_NxBPO = new M256[16]
    {
        new(0, 0, 0, 0, 0, 0, 0, 0),
        new(0x5CF5D3ED, 0x5812631A, 0xA2F79CD6, 0x14DEF9DE, 0, 0, 0, 0x10000000),
        new(0xB9EBA7DA, 0xB024C634, 0x45EF39AC, 0x29BDF3BD, 0, 0, 0, 0x20000000),
        new(0x16E17BC7, 0x0837294F, 0xE8E6D683, 0x3E9CED9B, 0, 0, 0, 0x30000000),
        new(0x73D74FB4, 0x60498C69, 0x8BDE7359, 0x537BE77A, 0, 0, 0, 0x40000000),
        new(0xD0CD23A1, 0xB85BEF83, 0x2ED6102F, 0x685AE159, 0, 0, 0, 0x50000000),
        new(0x2DC2F78E, 0x106E529E, 0xD1CDAD06, 0x7D39DB37, 0, 0, 0, 0x60000000),
        new(0x8AB8CB7B, 0x6880B5B8, 0x74C549DC, 0x9218D516, 0, 0, 0, 0x70000000),
        new(0xE7AE9F68, 0xC09318D2, 0x17BCE6B2, 0xA6F7CEF5, 0, 0, 0, 0x80000000),
        new(0x44A47355, 0x18A57BED, 0xBAB48389, 0xBBD6C8D3, 0, 0, 0, 0x90000000),
        new(0xA19A4742, 0x70B7DF07, 0x5DAC205F, 0xD0B5C2B2, 0, 0, 0, 0xA0000000),
        new(0xFE901B2F, 0xC8CA4221, 0x00A3BD35, 0xE594BC91, 0, 0, 0, 0xB0000000),
        new(0x5B85EF1C, 0x20DCA53C, 0xA39B5A0C, 0xFA73B66F, 0, 0, 0, 0xC0000000),
        new(0xB87BC309, 0x78EF0856, 0x4692F6E2, 0x0F52B04E, 1, 0, 0, 0xD0000000),
        new(0x157196F6, 0xD1016B71, 0xE98A93B8, 0x2431AA2C, 1, 0, 0, 0xE0000000),
        new(0x72676AE3, 0x2913CE8B, 0x8C82308F, 0x3910A40B, 1, 0, 0, 0xF0000000)
    };

    private const U32 minusR_0 = 0xCF5D3ED0;
    private const U32 minusR_1 = 0x812631A5;
    private const U32 minusR_2 = 0x2F79CD65;
    private const U32 minusR_3 = 0x4DEF9DEA;
    private const U32 minusR_4 = 1;
    private const U32 minusR_5 = 0;
    private const U32 minusR_6 = 0;
    private const U32 minusR_7 = 0;

    /// <summary>
    /// Calculate: Y = [b:X] mod BPO
    /// For R = 2^256, we calculate Y = b*R + X mod BPO
    /// Since -R mod BPO is only 129-bits, it reduces number of multiplications if
    /// we calculate: Y = X - b*(-R) mod BPO instead
    /// Note that b*(-R) is 161-bits at most and does not need reduction.
    /// </summary>
    /// <param name="Y"></param>
    /// <param name="b"></param>
    /// <param name="X"></param>
    public static void eco_ReduceHiWord(Span<U32> Y, U32 b, ReadOnlySpan<U32> X)
    {
        M64 c;
        Span<U32> T = stackalloc U32[16];

        /* Set T = b*(-R) */

        c.u64 = (U64)b * minusR_0;
        T[0] = c.u32.lo;
        c.u64 = (U64)b * minusR_1 + c.u32.hi;
        T[1] = c.u32.lo;
        c.u64 = (U64)b * minusR_2 + c.u32.hi;
        T[2] = c.u32.lo;
        c.u64 = (U64)b * minusR_3 + c.u32.hi;
        T[3] = c.u32.lo;
        c.u64 = (U64)b + c.u32.hi;
        T[4] = c.u32.lo;
        T[5] = c.u32.hi;
        T[6] = 0;
        T[7] = 0;

        /* Y = X - T */
        c.s32.hi = ecp_Sub(Y, X, T);

        /* Add BPO if there is a borrow */

        ecp_Add(Y, Y, _w_NxBPO[c.s32.hi & 1].words);
    }

    /// <summary>
    /// Z = X*Y mod BPO
    /// </summary>
    /// <param name="Z"></param>
    /// <param name="X"></param>
    /// <param name="Y"></param>
    public static void eco_MulReduce(Span<U32> Z, ReadOnlySpan<U32> X, ReadOnlySpan<U32> Y)
    {
        Span<U32> T = stackalloc U32[16];
        ecp_Mul(T, X, Y); /* T = X*Y */
        eco_ReduceHiWord(T[7..], T[15], T[7..]);
        eco_ReduceHiWord(T[6..], T[14], T[6..]);
        eco_ReduceHiWord(T[5..], T[13], T[5..]);
        eco_ReduceHiWord(T[4..], T[12], T[4..]);
        eco_ReduceHiWord(T[3..], T[11], T[3..]);
        eco_ReduceHiWord(T[2..], T[10], T[2..]);
        eco_ReduceHiWord(T[1..], T[9], T[1..]);
        eco_ReduceHiWord(Z, T[8], T[0..]);
    }

    /// <summary>
    /// X mod BPO
    /// </summary>
    /// <param name="X"></param>
    public static void eco_Mod(Span<U32> X)
    {
        S32 c = ecp_Sub(X, X, _w_NxBPO[X[7] >> 28].words);
        ecp_Add(X, X, _w_NxBPO[c & 1].words);
    }

    /// <summary>
    /// Z = X + Y mod BPO
    /// </summary>
    /// <param name="Z"></param>
    /// <param name="X"></param>
    /// <param name="Y"></param>
    public static void eco_AddReduce(Span<U32> Z, ReadOnlySpan<U32> X, ReadOnlySpan<U32> Y)
    {
        U32 c = ecp_Add(Z, X, Y);
        eco_ReduceHiWord(Z, c, Z);
    }

    /// <summary>
    /// Return Y = D mod BPO where D is 512-bit message digest (i.e SHA512 digest)
    /// </summary>
    /// <param name="Y"></param>
    /// <param name="md"></param>
    public static void eco_DigestToWords(Span<U32> Y, ReadOnlySpan<U8> md)
    {
        Span<U32> T = stackalloc U32[16];

        /* We use digest value as little-endian byte array. */
        ecp_BytesToWords(T, md);
        ecp_BytesToWords(T[8..], md[32..]);

        eco_ReduceHiWord(T[7..], T[15], T[7..]);
        eco_ReduceHiWord(T[6..], T[14], T[6..]);
        eco_ReduceHiWord(T[5..], T[13], T[5..]);
        eco_ReduceHiWord(T[4..], T[12], T[4..]);
        eco_ReduceHiWord(T[3..], T[11], T[3..]);
        eco_ReduceHiWord(T[2..], T[10], T[2..]);
        eco_ReduceHiWord(T[1..], T[9], T[1..]);
        eco_ReduceHiWord(Y, T[8], T[0..]);
    }
}
