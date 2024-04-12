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
    public static void ecp_SetValue(Span<U32> X, U32 value)
    {
        X[0] = value;
        X[1] = X[2] = X[3] = X[4] = X[5] = X[6] = X[7] = 0;
    }

    /// <summary>
    /// Y = X
    /// </summary>
    /// <param name="Y"></param>
    /// <param name="???"></param>
    public static void ecp_Copy(Span<U32> Y, ReadOnlySpan<U32> X)
    {
        X.CopyTo(Y);
    }

    public static uint ecp_CmpNE(ReadOnlySpan<U32> X, ReadOnlySpan<U32> Y)
    {
        return ((X[0] ^ Y[0]) | (X[1] ^ Y[1]) | (X[2] ^ Y[2]) | (X[3] ^ Y[3]) |
                (X[4] ^ Y[4]) | (X[5] ^ Y[5]) | (X[6] ^ Y[6]) | (X[7] ^ Y[7]));
    }

    public static int ecp_CmpLT(ReadOnlySpan<U32> X, ReadOnlySpan<U32> Y)
    {
        Span<U32> T = stackalloc U32[8];
        return ecp_Sub(T, X, Y);
    }

    private static void ECP_ADD_C0(ref M64 c, ref U32 Y, U32 X, U32 V)
    {
        c.u64 = (U64)(X) + (V);
        Y = c.u32.lo;
    }

    private static void ECP_ADD_C1(ref M64 c, ref U32 Y, U32 X)
    {
        c.u64 = (U64)(X) + c.u32.hi;
        Y = c.u32.lo;
    }

    private static void ECP_SUB_C0(ref M64 c, ref U32 Y, U32 X, U32 V)
    {
        //c.s64 = (U64)(X) - (V);
        c.s64 = X;
        c.s64 -= V;
        Y = c.u32.lo;
    }

    private static void ECP_SUB_C1(ref M64 c, ref U32 Y, U32 X)
    {
        //c.s64 = (U64)(X) + (S64)c.s32.hi;
        c.s64 = X + c.s32.hi;
        Y = c.u32.lo;
    }

    private static void ECP_MULSET_W0(ref M64 c, ref U32 Y, U32 b, U32 X)
    {
        c.u64 = (U64)(b) * (X);
        Y = c.u32.lo;
    }

    private static void ECP_MULSET_W1(ref M64 c, ref U32 Y, U32 b, U32 X)
    {
        c.u64 = (U64)(b) * (X) + c.u32.hi;
        Y = c.u32.lo;
    }

    private static void ECP_MULADD_W0(ref M64 c, ref U32 Z, U32 Y, U32 b, U32 X)
    {
        c.u64 = (U64)(b) * (X) + (Y);
        Z = c.u32.lo;
    }

    private static void ECP_MULADD_W1(ref M64 c, ref U32 Z, U32 Y, U32 b, U32 X)
    {
        c.u64 = (U64)(b) * (X) + (U64)(Y) + c.u32.hi;
        Z = c.u32.lo;
    }

    private static void ECP_ADD32(ref M64 c, ref U32 Z, U32 X, U32 Y)
    {
        c.u64 = (U64)(X) + (Y);
        Z = c.u32.lo;
    }

    private static void ECP_ADC32(ref M64 c, ref U32 Z, U32 X, U32 Y)
    {
        c.u64 = (U64)(X) + (U64)(Y) + c.u32.hi;
        Z = c.u32.lo;
    }

    private static void ECP_SUB32(ref M64 c, ref U32 Z, U32 X, U32 Y)
    {
        c.s64 = (S64)(X) - (Y);
        Z = c.s32.lo;
    }

    private static void ECP_SBC32(ref M64 b, ref U32 Z, U32 X, U32 Y)
    {
        //b.s64 = (S64)(X) - (U64)(Y) + b.s32.hi;
        b.s64 = X;
        b.s64 -= Y;
        b.s64 += b.s32.hi;
        Z = b.s32.lo;
    }

    /* Computes Z = X+Y */
    public static U32 ecp_Add(Span<U32> Z, ReadOnlySpan<U32> X, ReadOnlySpan<U32> Y)
    {
        M64 c = new();

        ECP_ADD32(ref c, ref Z[0], X[0], Y[0]);
        ECP_ADC32(ref c, ref Z[1], X[1], Y[1]);
        ECP_ADC32(ref c, ref Z[2], X[2], Y[2]);
        ECP_ADC32(ref c, ref Z[3], X[3], Y[3]);
        ECP_ADC32(ref c, ref Z[4], X[4], Y[4]);
        ECP_ADC32(ref c, ref Z[5], X[5], Y[5]);
        ECP_ADC32(ref c, ref Z[6], X[6], Y[6]);
        ECP_ADC32(ref c, ref Z[7], X[7], Y[7]);
        return c.u32.hi;
    }

    /* Computes Z = X-Y */
    public static S32 ecp_Sub(Span<U32> Z, ReadOnlySpan<U32> X, ReadOnlySpan<U32> Y)
    {
        M64 b = new();
        ECP_SUB32(ref b, ref Z[0], X[0], Y[0]);
        ECP_SBC32(ref b, ref Z[1], X[1], Y[1]);
        ECP_SBC32(ref b, ref Z[2], X[2], Y[2]);
        ECP_SBC32(ref b, ref Z[3], X[3], Y[3]);
        ECP_SBC32(ref b, ref Z[4], X[4], Y[4]);
        ECP_SBC32(ref b, ref Z[5], X[5], Y[5]);
        ECP_SBC32(ref b, ref Z[6], X[6], Y[6]);
        ECP_SBC32(ref b, ref Z[7], X[7], Y[7]);
        return b.s32.hi;
    }

    /* Computes Z = X+Y mod P */
    public static void ecp_AddReduce(Span<U32> Z, ReadOnlySpan<U32> X, ReadOnlySpan<U32> Y)
    {
        M64 c = new();
        c.u32.hi = ecp_Add(Z, X, Y) * 38;

        /* Z += c.u32.hi * 38 */
        ECP_ADD_C0(ref c, ref Z[0], Z[0], c.u32.hi);
        ECP_ADD_C1(ref c, ref Z[1], Z[1]);
        ECP_ADD_C1(ref c, ref Z[2], Z[2]);
        ECP_ADD_C1(ref c, ref Z[3], Z[3]);
        ECP_ADD_C1(ref c, ref Z[4], Z[4]);
        ECP_ADD_C1(ref c, ref Z[5], Z[5]);
        ECP_ADD_C1(ref c, ref Z[6], Z[6]);
        ECP_ADD_C1(ref c, ref Z[7], Z[7]);

        /* One more carry at most */
        ECP_ADD_C0(ref c, ref Z[0], Z[0], c.u32.hi * 38);
        ECP_ADD_C1(ref c, ref Z[1], Z[1]);
        ECP_ADD_C1(ref c, ref Z[2], Z[2]);
        ECP_ADD_C1(ref c, ref Z[3], Z[3]);
        ECP_ADD_C1(ref c, ref Z[4], Z[4]);
        ECP_ADD_C1(ref c, ref Z[5], Z[5]);
        ECP_ADD_C1(ref c, ref Z[6], Z[6]);
        ECP_ADD_C1(ref c, ref Z[7], Z[7]);
    }

    /* Computes Z = X-Y mod P */
    public static void ecp_SubReduce(Span<U32> Z, ReadOnlySpan<U32> X, ReadOnlySpan<U32> Y)
    {
        M64 c = new();
        //c.u32.hi = ecp_Sub(Z, X, Y) & 38;
        c.s32.hi = ecp_Sub(Z, X, Y) & 38;

        ECP_SUB_C0(ref c, ref Z[0], Z[0], c.u32.hi);
        ECP_SUB_C1(ref c, ref Z[1], Z[1]);
        ECP_SUB_C1(ref c, ref Z[2], Z[2]);
        ECP_SUB_C1(ref c, ref Z[3], Z[3]);
        ECP_SUB_C1(ref c, ref Z[4], Z[4]);
        ECP_SUB_C1(ref c, ref Z[5], Z[5]);
        ECP_SUB_C1(ref c, ref Z[6], Z[6]);
        ECP_SUB_C1(ref c, ref Z[7], Z[7]);

        ECP_SUB_C0(ref c, ref Z[0], Z[0], c.u32.hi & 38);
        ECP_SUB_C1(ref c, ref Z[1], Z[1]);
        ECP_SUB_C1(ref c, ref Z[2], Z[2]);
        ECP_SUB_C1(ref c, ref Z[3], Z[3]);
        ECP_SUB_C1(ref c, ref Z[4], Z[4]);
        ECP_SUB_C1(ref c, ref Z[5], Z[5]);
        ECP_SUB_C1(ref c, ref Z[6], Z[6]);
        ECP_SUB_C1(ref c, ref Z[7], Z[7]);
    }

    public static void ecp_Mod(Span<U32> X)
    {
        Span<U32> T = stackalloc U32[8];
        U32 c = (U32)ecp_Sub(X, X, Const._w_P.words);

        /* set T = 0 if c=0, else T = P */

        T[0] = c & 0xFFFFFFED;
        T[1] = T[2] = T[3] = T[4] = T[5] = T[6] = c;
        T[7] = c >> 1;

        ecp_Add(X, X, T); /* X += 0 or P */

        /* In case there is another P there */

        c = (U32)ecp_Sub(X, X, Const._w_P.words);

        /* set T = 0 if c=0, else T = P */

        T[0] = c & 0xFFFFFFED;
        T[1] = T[2] = T[3] = T[4] = T[5] = T[6] = c;
        T[7] = c >> 1;

        ecp_Add(X, X, T); /* X += 0 or P */
    }

    /* Computes Y = b*X */
    public static void ecp_mul_set(Span<U32> Y, U32 b, ReadOnlySpan<U32> X)
    {
        M64 c = new();
        ECP_MULSET_W0(ref c, ref Y[0], b, X[0]);
        ECP_MULSET_W1(ref c, ref Y[1], b, X[1]);
        ECP_MULSET_W1(ref c, ref Y[2], b, X[2]);
        ECP_MULSET_W1(ref c, ref Y[3], b, X[3]);
        ECP_MULSET_W1(ref c, ref Y[4], b, X[4]);
        ECP_MULSET_W1(ref c, ref Y[5], b, X[5]);
        ECP_MULSET_W1(ref c, ref Y[6], b, X[6]);
        ECP_MULSET_W1(ref c, ref Y[7], b, X[7]);
        Y[8] = c.u32.hi;
    }

    /* Computes Y += b*X */
    /* Addition is performed on lower 8-words of Y */
    public static void ecp_mul_add(Span<U32> Y, U32 b, ReadOnlySpan<U32> X)
    {
        M64 c = new();
        ECP_MULADD_W0(ref c, ref Y[0], Y[0], b, X[0]);
        ECP_MULADD_W1(ref c, ref Y[1], Y[1], b, X[1]);
        ECP_MULADD_W1(ref c, ref Y[2], Y[2], b, X[2]);
        ECP_MULADD_W1(ref c, ref Y[3], Y[3], b, X[3]);
        ECP_MULADD_W1(ref c, ref Y[4], Y[4], b, X[4]);
        ECP_MULADD_W1(ref c, ref Y[5], Y[5], b, X[5]);
        ECP_MULADD_W1(ref c, ref Y[6], Y[6], b, X[6]);
        ECP_MULADD_W1(ref c, ref Y[7], Y[7], b, X[7]);
        Y[8] = c.u32.hi;
    }

    /* Computes Z = Y + b*X and return carry */
    public static void ecp_WordMulAddReduce(Span<U32> Z, ReadOnlySpan<U32> Y, U32 b, ReadOnlySpan<U32> X)
    {
        M64 c = new();
        ECP_MULADD_W0(ref c, ref Z[0], Y[0], b, X[0]);
        ECP_MULADD_W1(ref c, ref Z[1], Y[1], b, X[1]);
        ECP_MULADD_W1(ref c, ref Z[2], Y[2], b, X[2]);
        ECP_MULADD_W1(ref c, ref Z[3], Y[3], b, X[3]);
        ECP_MULADD_W1(ref c, ref Z[4], Y[4], b, X[4]);
        ECP_MULADD_W1(ref c, ref Z[5], Y[5], b, X[5]);
        ECP_MULADD_W1(ref c, ref Z[6], Y[6], b, X[6]);
        ECP_MULADD_W1(ref c, ref Z[7], Y[7], b, X[7]);

        /* Z += c.u32.hi * 38 */
        ECP_MULADD_W0(ref c, ref Z[0], Z[0], c.u32.hi, 38);
        ECP_ADD_C1(ref c, ref Z[1], Z[1]);
        ECP_ADD_C1(ref c, ref Z[2], Z[2]);
        ECP_ADD_C1(ref c, ref Z[3], Z[3]);
        ECP_ADD_C1(ref c, ref Z[4], Z[4]);
        ECP_ADD_C1(ref c, ref Z[5], Z[5]);
        ECP_ADD_C1(ref c, ref Z[6], Z[6]);
        ECP_ADD_C1(ref c, ref Z[7], Z[7]);

        /* One more time at most */
        ECP_MULADD_W0(ref c, ref Z[0], Z[0], c.u32.hi, 38);
        ECP_ADD_C1(ref c, ref Z[1], Z[1]);
        ECP_ADD_C1(ref c, ref Z[2], Z[2]);
        ECP_ADD_C1(ref c, ref Z[3], Z[3]);
        ECP_ADD_C1(ref c, ref Z[4], Z[4]);
        ECP_ADD_C1(ref c, ref Z[5], Z[5]);
        ECP_ADD_C1(ref c, ref Z[6], Z[6]);
        ECP_ADD_C1(ref c, ref Z[7], Z[7]);
    }

    /* Computes Z = X*Y mod P. */
    /* Output fits into 8 words but could be greater than P */
    public static void ecp_MulReduce(Span<U32> Z, ReadOnlySpan<U32> X, ReadOnlySpan<U32> Y)
    {
        Span<U32> T = stackalloc U32[16];

        ecp_mul_set(T[0..], X[0], Y);
        ecp_mul_add(T[1..], X[1], Y);
        ecp_mul_add(T[2..], X[2], Y);
        ecp_mul_add(T[3..], X[3], Y);
        ecp_mul_add(T[4..], X[4], Y);
        ecp_mul_add(T[5..], X[5], Y);
        ecp_mul_add(T[6..], X[6], Y);
        ecp_mul_add(T[7..], X[7], Y);

        /* We have T = X*Y, now do the reduction in size */

        ecp_WordMulAddReduce(Z, T, 38, T[8..]);
    }

    /* Computes Z = X*Y */
    public static void ecp_Mul(Span<U32> Z, ReadOnlySpan<U32> X, ReadOnlySpan<U32> Y)
    {
        ecp_mul_set(Z[0..], X[0], Y);
        ecp_mul_add(Z[1..], X[1], Y);
        ecp_mul_add(Z[2..], X[2], Y);
        ecp_mul_add(Z[3..], X[3], Y);
        ecp_mul_add(Z[4..], X[4], Y);
        ecp_mul_add(Z[5..], X[5], Y);
        ecp_mul_add(Z[6..], X[6], Y);
        ecp_mul_add(Z[7..], X[7], Y);
    }

    /* Computes Z = X*Y mod P. */
    public static void ecp_SqrReduce(Span<U32> Y, ReadOnlySpan<U32> X)
    {
        /* TBD: Implementation is based on multiply */
        /*      Optimize for squaring */

        Span<U32> T = stackalloc U32[16];

        ecp_mul_set(T[0..], X[0], X);
        ecp_mul_add(T[1..], X[1], X);
        ecp_mul_add(T[2..], X[2], X);
        ecp_mul_add(T[3..], X[3], X);
        ecp_mul_add(T[4..], X[4], X);
        ecp_mul_add(T[5..], X[5], X);
        ecp_mul_add(T[6..], X[6], X);
        ecp_mul_add(T[7..], X[7], X);

        /* We have T = X*X, now do the reduction in size */

        ecp_WordMulAddReduce(Y, T, 38, T[8..]);
    }

    /* Computes Z = X*Y mod P. */
    public static void ecp_MulMod(Span<U32> Z, ReadOnlySpan<U32> X, ReadOnlySpan<U32> Y)
    {
        ecp_MulReduce(Z, X, Y);
        ecp_Mod(Z);
    }

    /* Courtesy of DJB */
    /* Return out = 1/z mod P */
    public static void ecp_Inverse(Span<U32> @out, ReadOnlySpan<U32> z)
    {
        int i;
        Span<U32> t0 = stackalloc U32[8];
        Span<U32> t1 = stackalloc U32[8];
        Span<U32> z2 = stackalloc U32[8];
        Span<U32> z9 = stackalloc U32[8];
        Span<U32> z11 = stackalloc U32[8];
        Span<U32> z2_5_0 = stackalloc U32[8];
        Span<U32> z2_10_0 = stackalloc U32[8];
        Span<U32> z2_20_0 = stackalloc U32[8];
        Span<U32> z2_50_0 = stackalloc U32[8];
        Span<U32> z2_100_0 = stackalloc U32[8];

        /* 2 */
        ecp_SqrReduce(z2, z);
        /* 4 */
        ecp_SqrReduce(t1, z2);
        /* 8 */
        ecp_SqrReduce(t0, t1);
        /* 9 */
        ecp_MulReduce(z9, t0, z);
        /* 11 */
        ecp_MulReduce(z11, z9, z2);
        /* 22 */
        ecp_SqrReduce(t0, z11);
        /* 2^5 - 2^0 = 31 */
        ecp_MulReduce(z2_5_0, t0, z9);

        /* 2^6 - 2^1 */
        ecp_SqrReduce(t0, z2_5_0);
        /* 2^7 - 2^2 */
        ecp_SqrReduce(t1, t0);
        /* 2^8 - 2^3 */
        ecp_SqrReduce(t0, t1);
        /* 2^9 - 2^4 */
        ecp_SqrReduce(t1, t0);
        /* 2^10 - 2^5 */
        ecp_SqrReduce(t0, t1);
        /* 2^10 - 2^0 */
        ecp_MulReduce(z2_10_0, t0, z2_5_0);

        /* 2^11 - 2^1 */
        ecp_SqrReduce(t0, z2_10_0);
        /* 2^12 - 2^2 */
        ecp_SqrReduce(t1, t0);
        /* 2^20 - 2^10 */
        for (i = 2; i < 10; i += 2)
        {
            ecp_SqrReduce(t0, t1);
            ecp_SqrReduce(t1, t0);
        }

        /* 2^20 - 2^0 */
        ecp_MulReduce(z2_20_0, t1, z2_10_0);

        /* 2^21 - 2^1 */
        ecp_SqrReduce(t0, z2_20_0);
        /* 2^22 - 2^2 */
        ecp_SqrReduce(t1, t0);
        /* 2^40 - 2^20 */
        for (i = 2; i < 20; i += 2)
        {
            ecp_SqrReduce(t0, t1);
            ecp_SqrReduce(t1, t0);
        }

        /* 2^40 - 2^0 */
        ecp_MulReduce(t0, t1, z2_20_0);

        /* 2^41 - 2^1 */
        ecp_SqrReduce(t1, t0);
        /* 2^42 - 2^2 */
        ecp_SqrReduce(t0, t1);
        /* 2^50 - 2^10 */
        for (i = 2; i < 10; i += 2)
        {
            ecp_SqrReduce(t1, t0);
            ecp_SqrReduce(t0, t1);
        }

        /* 2^50 - 2^0 */
        ecp_MulReduce(z2_50_0, t0, z2_10_0);

        /* 2^51 - 2^1 */
        ecp_SqrReduce(t0, z2_50_0);
        /* 2^52 - 2^2 */
        ecp_SqrReduce(t1, t0);
        /* 2^100 - 2^50 */
        for (i = 2; i < 50; i += 2)
        {
            ecp_SqrReduce(t0, t1);
            ecp_SqrReduce(t1, t0);
        }

        /* 2^100 - 2^0 */
        ecp_MulReduce(z2_100_0, t1, z2_50_0);

        /* 2^101 - 2^1 */
        ecp_SqrReduce(t1, z2_100_0);
        /* 2^102 - 2^2 */
        ecp_SqrReduce(t0, t1);
        /* 2^200 - 2^100 */
        for (i = 2; i < 100; i += 2)
        {
            ecp_SqrReduce(t1, t0);
            ecp_SqrReduce(t0, t1);
        }

        /* 2^200 - 2^0 */
        ecp_MulReduce(t1, t0, z2_100_0);

        /* 2^201 - 2^1 */
        ecp_SqrReduce(t0, t1);
        /* 2^202 - 2^2 */
        ecp_SqrReduce(t1, t0);
        /* 2^250 - 2^50 */
        for (i = 2; i < 50; i += 2)
        {
            ecp_SqrReduce(t0, t1);
            ecp_SqrReduce(t1, t0);
        }

        /* 2^250 - 2^0 */
        ecp_MulReduce(t0, t1, z2_50_0);

        /* 2^251 - 2^1 */
        ecp_SqrReduce(t1, t0);
        /* 2^252 - 2^2 */
        ecp_SqrReduce(t0, t1);
        /* 2^253 - 2^3 */
        ecp_SqrReduce(t1, t0);
        /* 2^254 - 2^4 */
        ecp_SqrReduce(t0, t1);
        /* 2^255 - 2^5 */
        ecp_SqrReduce(t1, t0);
        /* 2^255 - 21 */
        ecp_MulReduce(@out, t1, z11);
    }
}
