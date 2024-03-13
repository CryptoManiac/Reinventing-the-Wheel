namespace Wheel.Crypto.Hashing.SHA3.Internal
{
    internal static class KeccakConstants
	{
        public const int SHA3_ROUNDS = 24;
        public const int SHA3_SPONGE_WORDS = 25; // Calculated as 1600 / 8 / sizeof(ulong)
        public const uint SHA3_USE_KECCAK_FLAG = 0x80000000;

        public static readonly int[] keccakf_rotc = new int[24]{
             1,  3,  6, 10,
            15, 21, 28, 36,
            45, 55,  2, 14,
            27, 41, 56,  8,
            25, 43, 62, 18,
            39, 61, 20, 44
        };

        public static readonly int[] keccakf_piln = new int[24] {
            10,  7, 11, 17,
            18,  3,  5, 16,
             8, 21, 24,  4,
            15, 23, 19, 13,
            12,  2, 20, 14,
            22,  9,  6,  1
        };

        public readonly static ulong[] keccakf_rndc = new ulong[24]{
            0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
            0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
            0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
            0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
            0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
            0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
            0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
            0x8000000000008080, 0x0000000080000001, 0x8000000080008008
        };

    }
}

