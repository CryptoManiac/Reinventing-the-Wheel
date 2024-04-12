using EdDSA_Mehdi.Internal.BaseTypes;

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

        ecp_Add(Y, Y, Const._w_NxBPO[c.s32.hi & 1].words);
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
        S32 c = ecp_Sub(X, X, Const._w_NxBPO[X[7] >> 28].words);
        ecp_Add(X, X, Const._w_NxBPO[c & 1].words);
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
