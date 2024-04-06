namespace Wheel.Crypto.Elliptic.EdDSA.Internal.Curve25519;

public static class Logic
{

    /// <summary>
    /// Timing safe memory compare
    /// </summary>
    /// <returns></returns>
    public static bool ed25519_verify(ReadOnlySpan<byte> x, ReadOnlySpan<byte> y, int len)
    {
        int diff = 0;
        for (int i = 0; i != len; ++i)
        {
            diff |= x[i] ^ y[i];
        }
        return !Convert.ToBoolean(diff);
    }

    /// <summary>
    /// Xor every byte of X with every byte of Y
    /// </summary>
    /// <param name="x"></param>
    /// <param name="y"></param>
    /// <param name="len"></param>
    public static void ed25519_xor(Span<byte> x, ReadOnlySpan<byte> y, int len)
    {
        for (int i = 0; i != len; ++i)
        {
             x[i] ^= y[i];
        }
    }
}
