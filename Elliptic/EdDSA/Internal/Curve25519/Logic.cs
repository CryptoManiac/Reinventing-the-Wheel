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
}
