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
    /// Trim private key
    /// </summary>
    /// <param name="X"></param>
    public static void ecp_TrimSecretKey(Span<U8> X)
    {
        X[0] &= 248;
        X[31] &= 63;
        X[31] |= 64;
    }
    
    /// <summary>
    /// Convert big-endian byte array to little-endian byte array and vice versa 
    /// </summary>
    /// <param name="Y"></param>
    /// <param name="X"></param>
    public static void ecp_ReverseByteOrder(Span<U8> Y, ReadOnlySpan<U8> X)
    {
        for (int i = 0; i < 32; i++) Y[i] = X[31-i];
    }

    /// <summary>
    /// Convert little-endian byte array to little-endian word array
    /// </summary>
    /// <param name="Y"></param>
    /// <param name="X"></param>
    public static void ecp_BytesToWords(Span<U32> Y, ReadOnlySpan<U8> X)
    {
        M32 m = new();

        for (int i = 0, j = 0; i < 8; i++)
        {
            m.u8.b0 = X[j++];
            m.u8.b1 = X[j++];
            m.u8.b2 = X[j++];
            m.u8.b3 = X[j++];
            Y[i] = m.u32;
        }
    }

    /// <summary>
    /// Convert little-endian word array to little-endian byte array
    /// </summary>
    /// <param name="Y"></param>
    /// <param name="X"></param>
    public static void ecp_WordsToBytes(Span<U8> Y, ReadOnlySpan<U32> X)
    {
        M32 m = new();
        for (int i = 0, j = 0; i < 32;)
        {
            m.u32 = X[j++];
            Y[i++] = m.u8.b0;
            Y[i++] = m.u8.b1;
            Y[i++] = m.u8.b2;
            Y[i++] = m.u8.b3;
        }
    }
    
    public static void ecp_EncodeInt(Span<U8> Y, ReadOnlySpan<U32> X, U8 parity)
    {
        int j = 0;
        M32 m;
    
        for (int i = 0; i < 28;)
        {
            m.u32 = X[j++];
            Y[i++] = m.u8.b0;
            Y[i++] = m.u8.b1;
            Y[i++] = m.u8.b2;
            Y[i++] = m.u8.b3;
        }

        m.u32 = X[j];
        Y[28] = m.u8.b0;
        Y[29] = m.u8.b1;
        Y[30] = m.u8.b2;
        Y[31] = (U8)((m.u8.b3 & 0x7f) | (parity << 7));
    }
    
    public static U8 ecp_DecodeInt(Span<U32> Y, ReadOnlySpan<U8> X)
    {
        int j = 0;
        M32 m = new();
    
        for (int i = 0; i < 7; i++)
        {
            m.u8.b0 = X[j++];
            m.u8.b1 = X[j++];
            m.u8.b2 = X[j++];
            m.u8.b3 = X[j++];
            Y[i] = m.u32;
        }

        m.u8.b0 = X[j++];
        m.u8.b1 = X[j++];
        m.u8.b2 = X[j++];
        m.u8.b3 = (U8)(X[j] & 0x7f);
        
        Y[7] = m.u32;

        return (U8)((X[j] >> 7) & 1);
    }
    
    public static void ecp_4Folds(Span<U8> Y, ReadOnlySpan<U32> X)
    {
        U8 a, b;
        for (int i = 32, k = 0; i-- > 0; k++)
        {
            a = 0;
            b = 0;
            for (int j = 8; j > 1;)
            {
                j -= 2;
                a = (U8)((a << 1) + ((X[j+1] >> i) & 1));
                b = (U8)((b << 1) + ((X[j] >> i) & 1));
            }
            Y[k] = a;
            Y[k + 32] = b;
        }
    }

    public static void ecp_8Folds(Span<U8> Y, ReadOnlySpan<U32> X)
    {
        U8 a = 0;
        for (int i = 32, k = 0; i-- > 0;)
        {
            for (int j = 8; j-- > 0;)
            {
                a = (U8)((a << 1) + ((X[j] >> i) & 1));
            }
            Y[k++] = a;
        }
    }
}
