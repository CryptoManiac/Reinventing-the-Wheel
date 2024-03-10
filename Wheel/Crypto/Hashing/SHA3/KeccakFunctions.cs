namespace Wheel.Crypto.Hashing.SHA3.Internal
{
	public static class KeccakFunctions
	{
        public static ulong SHA3_ROTL64(ulong x, int y) => (x << y) | (x >> ((sizeof(ulong) * 8) - y));
        public static uint SHA3_CW(uint x) => x & (~KeccakConstants.SHA3_USE_KECCAK_FLAG);

        public static void keccakf(Span<ulong> s)
        {
            Span<ulong> bc = stackalloc ulong[5];

            int i, j, round;
            ulong t;

            for (round = 0; round < KeccakConstants.SHA3_ROUNDS; round++)
            {

                /* Theta */
                for (i = 0; i < 5; i++)
                {
                    bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];
                }

                for (i = 0; i < 5; i++)
                {
                    t = bc[(i + 4) % 5] ^ SHA3_ROTL64(bc[(i + 1) % 5], 1);
                    for (j = 0; j < 25; j += 5)
                    {
                        s[j + i] ^= t;
                    }
                }

                /* Rho Pi */
                t = s[1];
                for (i = 0; i < 24; i++)
                {
                    j = KeccakConstants.keccakf_piln[i];
                    bc[0] = s[j];
                    s[j] = SHA3_ROTL64(t, KeccakConstants.keccakf_rotc[i]);
                    t = bc[0];
                }

                /* Chi */
                for (j = 0; j < 25; j += 5)
                {
                    for (i = 0; i < 5; i++)
                    {
                        bc[i] = s[j + i];
                    }

                    for (i = 0; i < 5; i++)
                    {
                        s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
                    }
                }

                /* Iota */
                s[0] ^= KeccakConstants.keccakf_rndc[round];
            }
        }
    }
}

