using System.Runtime.InteropServices;
using Wheel.Crypto.Miscellaneous.Support;

namespace Wheel.Crypto.Hashing.SHA3.Internal
{
    [StructLayout(LayoutKind.Explicit)]
    public struct Keccak : IHasher
    {
        /// <summary>
        /// the double size of the hash output in
        /// words (e.g. 16 for Keccak 512)
        /// </summary>
        [FieldOffset(0)]
        public readonly uint capacityWords;

        /// <summary>
        /// 0..7--the next byte after the set one
        /// (starts from 0; 0--none are buffered)
        /// </summary>
        [FieldOffset(4)]
        public int byteIndex;

        /// <summary>
        /// 0..24--the next word to integrate input
        /// (starts from 0)
        /// </summary>
        [FieldOffset(8)]
        public uint wordIndex;

        /// <summary>
        /// the portion of the input message that we didn't consume yet
        /// </summary>
        [FieldOffset(12)]
        public ulong saved;

        /// <summary>
        /// Keccak data mixer
        /// </summary>
        [FieldOffset(20)]
        private unsafe fixed ulong registers[KeccakConstants.SHA3_SPONGE_WORDS];

        public readonly bool IsKeccak
        {
            get { return 0 != (capacityWords & KeccakConstants.SHA3_USE_KECCAK_FLAG); }
        }

        public readonly int HashSz
        {
            get { return (int)capacityWords * 4; }
        }

        public Keccak(int bitSize, bool isKeccak)
        {
            if (bitSize != 256 && bitSize != 384 && bitSize != 512)
            {
                throw new InvalidOperationException("Valid bitSize values are: 256, 384 or 512");
            }

            capacityWords = (uint)bitSize / 32;

            if (isKeccak)
            {
                capacityWords |= KeccakConstants.SHA3_USE_KECCAK_FLAG;
            }

        }

        public unsafe void Reset()
        {
            fixed(void* ptr = &this)
            {
                // Skip the first 4 bytes to keep the capacityWords intact
                new Span<byte>((byte*)ptr + sizeof(uint), sizeof(Keccak) - sizeof(uint)).Clear();
            }
        }

        public void Update(in ReadOnlySpan<byte> input)
        {
            // 0...7 -- how much is needed to have a word
            int offset = WriteTail(input);
            int words = (input.Length - offset) / 8;

            // now work in full words directly from input
            for (int i = 0; i < words; i++, offset += 8)
            {
                unsafe
                {
                    registers[wordIndex] ^= (input[offset]) |
                        ((ulong)input[offset + 1] << 8 * 1) |
                        ((ulong)input[offset + 2] << 8 * 2) |
                        ((ulong)input[offset + 3] << 8 * 3) |
                        ((ulong)input[offset + 4] << 8 * 4) |
                        ((ulong)input[offset + 5] << 8 * 5) |
                        ((ulong)input[offset + 6] << 8 * 6) |
                         ((ulong)input[offset + 7] << 8 * 7);
                }

                if (++wordIndex == (KeccakConstants.SHA3_SPONGE_WORDS - KeccakFunctions.SHA3_CW(capacityWords)))
                {
                    KeccakF();
                    wordIndex = 0;
                }
            }

            // Add remaining odd bytes
            while (offset < input.Length)
            {
                saved |= (ulong)input[offset++] << (byteIndex++ * 8);
            }
        }

        private int WriteTail(in ReadOnlySpan<byte> input)
        {
            // 0...7 -- how much is needed to have a word
            int old_tail = (8 - byteIndex) & 7;

            if (input.Length < old_tail)
            {
                // have no complete word or haven't started
                // the word yet
                foreach(var b in input)
                {
                    saved |= (ulong)b << (byteIndex++ * 8);
                }
                return input.Length;
            }

            if (old_tail > 0)
            {
                for (int i = 0; i < old_tail; ++i)
                {
                    saved |= (ulong)input[i] << (byteIndex++ * 8);
                }

                // now ready to add saved to the sponge

                unsafe
                {
                    registers[wordIndex] ^= saved;
                }

                byteIndex = 0;
                saved = 0;

                if (++wordIndex == (KeccakConstants.SHA3_SPONGE_WORDS - KeccakFunctions.SHA3_CW(capacityWords)))
                {
                    KeccakF();
                    wordIndex = 0;
                }

                return old_tail;
            }

            // No offset
            return 0;
        }

        public void Digest(Span<byte> hash)
        {
            if (hash.Length != HashSz)
            {
                throw new InvalidOperationException("Target buffer size doesn't match the expected " + HashSz + " bytes");
            }

            /// This is simply the 'update' with the padding block.
            /// The padding block is 0x01 || 0x00* || 0x80. First 0x01 and last 0x80 
            /// bytes are always present, but they can be the same byte.

            // Append 2-bit suffix 01, per SHA-3 spec. Instead of 1 for padding we
            //  use 1<<2 below. The 0x02 below corresponds to the suffix 01.
            //  Overall, we feed 0, then 1, and finally 1 to start padding. Without
            //  M || 01, we would simply use 1 to start padding.

            ulong t;

            if (IsKeccak)
            {
                // Keccak version
                t = ((ulong)1) << (byteIndex * 8);
            }
            else
            {
                // SHA3 version
                t = ((ulong)(0x02 | (1 << 2))) << (byteIndex * 8);
            }

            unsafe
            {
                registers[wordIndex] ^= saved ^ t;
                registers[KeccakConstants.SHA3_SPONGE_WORDS - KeccakFunctions.SHA3_CW(capacityWords) - 1] ^= 0x8000000000000000UL;
            }

            KeccakF();

            // Revert byte order on BE machines
            //  Considering that Itanium is dead, this is unlikely to ever be useful
            if (!BitConverter.IsLittleEndian)
            {
                for (uint i = 0; i < KeccakConstants.SHA3_SPONGE_WORDS; i++)
                {
                    unsafe
                    {
                        Common.REVERT(ref registers[i]);
                    }
                }
            }

            unsafe
            {
                fixed (void* source = &registers[0])
                {
                    new Span<byte>(source, hash.Length).CopyTo(hash);
                }
            }

            // Reset hasher state
            Reset();
        }

        public byte[] Digest()
        {
            byte[] hash = new byte[HashSz];
            Digest(hash);
            return hash;
        }

        private unsafe void KeccakF()
        {
            Span<ulong> bc = stackalloc ulong[5];

            for (int round = 0; round < KeccakConstants.SHA3_ROUNDS; ++round)
            {

                /* Theta */
                for (int i = 0; i < 5; ++i)
                {
                    bc[i] = registers[i] ^ registers[i + 5] ^ registers[i + 10] ^ registers[i + 15] ^ registers[i + 20];
                }

                for (int i = 0; i < 5; ++i)
                {
                    ulong t1 = bc[(i + 4) % 5] ^ KeccakFunctions.SHA3_ROTL64(bc[(i + 1) % 5], 1);
                    for (int j = 0; j < 25; j += 5)
                    {
                        registers[j + i] ^= t1;
                    }
                }

                /* Rho Pi */
                ulong t = registers[1];
                for (int i = 0; i < 24; ++i)
                {
                    int j = KeccakConstants.keccakf_piln[i];
                    bc[0] = registers[j];
                    registers[j] = KeccakFunctions.SHA3_ROTL64(t, KeccakConstants.keccakf_rotc[i]);
                    t = bc[0];
                }

                /* Chi */
                for (int j = 0; j < 25; j += 5)
                {
                    for (int i = 0; i < 5; ++i)
                    {
                        bc[i] = registers[j + i];
                    }

                    for (int i = 0; i < 5; ++i)
                    {
                        registers[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
                    }
                }

                /* Iota */
                registers[0] ^= KeccakConstants.keccakf_rndc[round];
            }
        }
    }
}
