using System.Runtime.CompilerServices;

namespace Wheel.Symmetric.AES.Internal
{
    /// <summary>
    /// Expanded encryption key
    /// </summary>
    public struct AESRoundKey : IDisposable
    {
        internal unsafe fixed byte data[TypeByteSz];
        public const int TypeByteSz = 4 * AESCTR.AES_keyExpSize;

        /// <summary>
        /// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.
        /// </summary>
        /// <param name="Key">AES key to expand from</param>
        internal unsafe void Expand(in AESKey Key)
        {
            int i, j, k;
            StateWord tempa = new(); // Used for the column/row operations

            // The first round key is the key itself.
            for (i = 0; i < AESCTR.Nk; ++i)
            {
                data[(i * 4) + 0] = Key.data[(i * 4) + 0];
                data[(i * 4) + 1] = Key.data[(i * 4) + 1];
                data[(i * 4) + 2] = Key.data[(i * 4) + 2];
                data[(i * 4) + 3] = Key.data[(i * 4) + 3];
            }

            // Other round keys are found from the previous round keys.
            for (i = AESCTR.Nk; i < AESCTR.Nb * (AESCTR.Nr + 1); ++i)
            {
                {
                    k = (i - 1) * 4;
                    tempa.data[0] = data[k + 0];
                    tempa.data[1] = data[k + 1];
                    tempa.data[2] = data[k + 2];
                    tempa.data[3] = data[k + 3];
                }

                if (i % AESCTR.Nk == 0)
                {

                    tempa.RotWord();
                    tempa.SubWord();
                    tempa.data[0] ^= AESCTR.Rcon[i / AESCTR.Nk];
                }

                if (i % AESCTR.Nk == 4)
                {
                    tempa.SubWord();
                }

                j = i * 4;
                k = (i - AESCTR.Nk) * 4;
                data[j + 0] = (byte)(data[k + 0] ^ tempa.data[0]);
                data[j + 1] = (byte)(data[k + 1] ^ tempa.data[1]);
                data[j + 2] = (byte)(data[k + 2] ^ tempa.data[2]);
                data[j + 3] = (byte)(data[k + 3] ^ tempa.data[3]);
            }
        }

        public unsafe void Dispose()
        {
            fixed (byte* ptr = &data[0])
            {
                Unsafe.InitBlockUnaligned(ptr, 0, TypeByteSz);
            }
        }
    }
}
