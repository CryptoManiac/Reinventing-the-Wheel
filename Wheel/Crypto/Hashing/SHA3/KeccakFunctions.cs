namespace Wheel.Crypto.Hashing.SHA3.Internal
{
    internal static class KeccakFunctions
	{
        public static ulong SHA3_ROTL64(ulong x, int y) => (x << y) | (x >> (64 - y));
        public static uint SHA3_CW(uint x) => x & (~KeccakConstants.SHA3_USE_KECCAK_FLAG);
    }
}

