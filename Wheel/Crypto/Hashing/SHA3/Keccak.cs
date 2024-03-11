using Wheel.Crypto.Miscellaneous.Support;

namespace Wheel.Crypto.Hashing.SHA3.Internal
{
    public class Keccak : IHasher
    {
        /// <summary>
        /// 0..7--the next byte after the set one
        /// (starts from 0; 0--none are buffered)
        /// </summary>
        public int byteIndex;

        /// <summary>
        /// 0..24--the next word to integrate input
        /// (starts from 0)
        /// </summary>
        public uint wordIndex;

        /// <summary>
        /// the double size of the hash output in
        /// words (e.g. 16 for Keccak 512)
        /// </summary>
        public readonly uint capacityWords;

        /// <summary>
        /// the portion of the input message that we didn't consume yet
        /// </summary>
        public ulong saved;

        /// <summary>
        /// Keccak data mixer
        /// </summary>
        private KeccakSpounge spounge;

        public bool IsKeccak
        {
            get { return 0 != (capacityWords & KeccakConstants.SHA3_USE_KECCAK_FLAG); }
        }

        public int HashSz
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

        public void Reset()
        {
            spounge.Reset();
            wordIndex = 0;
            byteIndex = 0;
            saved = 0;
        }

        public void Update(byte[] input)
        {
            // 0...7 -- how much is needed to have a word
            int offset = WriteTail(input);
            int words = (input.Length - offset) / 8;

            // now work in full words directly from input
            for (int i = 0; i < words; i++, offset += 8)
            {
                spounge[wordIndex] ^= (input[offset]) |
                        ((ulong)input[offset + 1] << 8 * 1) |
                        ((ulong)input[offset + 2] << 8 * 2) |
                        ((ulong)input[offset + 3] << 8 * 3) |
                        ((ulong)input[offset + 4] << 8 * 4) |
                        ((ulong)input[offset + 5] << 8 * 5) |
                        ((ulong)input[offset + 6] << 8 * 6) |
                        ((ulong)input[offset + 7] << 8 * 7);

                if (++wordIndex == (KeccakConstants.SHA3_SPONGE_WORDS - KeccakFunctions.SHA3_CW(capacityWords)))
                {
                    spounge.KeccakF();
                    wordIndex = 0;
                }
            }

            // Add remaining odd bytes
            while (offset < input.Length)
            {
                saved |= (ulong)input[offset++] << (byteIndex++ * 8);
            }
        }

        private int WriteTail(byte[] input)
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
                spounge[wordIndex] ^= saved;
                byteIndex = 0;
                saved = 0;

                if (++wordIndex == (KeccakConstants.SHA3_SPONGE_WORDS - KeccakFunctions.SHA3_CW(capacityWords)))
                {
                    spounge.KeccakF();
                    wordIndex = 0;
                }

                return old_tail;
            }

            // No offset
            return 0;
        }

        /// <summary>
        /// This is simply the 'update' with the padding block.
        /// The padding block is 0x01 || 0x00* || 0x80. First 0x01 and last 0x80 
        /// bytes are always present, but they can be the same byte.
        /// </summary>
        public void Digest(Span<byte> hash)
        {
            if (hash.Length < HashSz)
            {
                throw new ArgumentOutOfRangeException(nameof(hash), hash.Length, "Hash buffer must be at least " + HashSz + " bytes long");
            }

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

            spounge[wordIndex] ^= saved ^ t;
            spounge[KeccakConstants.SHA3_SPONGE_WORDS - KeccakFunctions.SHA3_CW(capacityWords) - 1] ^= 0x8000000000000000UL;
            spounge.KeccakF();

            // Revert byte order on BE machines
            //  Considering that Itanium is dead, this is unlikely to ever be useful
            if (!BitConverter.IsLittleEndian)
            {
                for (uint i = 0; i < KeccakConstants.SHA3_SPONGE_WORDS; i++)
                {
                    spounge[i] = Common.REVERT(spounge[i]);
                }
            }

            spounge.bytes.Store(hash);

            // Reset hasher state
            Reset();
        }

        public byte[] Digest()
        {
            byte[] hash = new byte[HashSz];
            Digest(hash);
            return hash;
        }
    }
}

