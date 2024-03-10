using System.Runtime.InteropServices;

namespace Wheel.Crypto.Hashing.SHA3.Internal
{
    public class Keccak : IHasher
    {
        private InternalKeccakState ctx;

        public Keccak(int bitSize, bool isKeccak)
        {
            ctx = new(bitSize, isKeccak);
        }

        public void Reset()
        {
            ctx.Reset();
        }

        public void Update(byte[] input)
        {
            // 0...7 -- how much is needed to have a word
            int offset = WriteTail(input);

            int words = (input.Length - offset) / 8;
            int tail = input.Length - offset - words * 8;

            // For calm of my ming
            var spounge = ctx.spounge;

            // now work in full words directly from input
            for (int i = 0; i < words; i++, offset += 8)
            {
                spounge[ctx.wordIndex] ^= (input[offset]) |
                        ((ulong)input[offset + 1] << 8 * 1) |
                        ((ulong)input[offset + 2] << 8 * 2) |
                        ((ulong)input[offset + 3] << 8 * 3) |
                        ((ulong)input[offset + 4] << 8 * 4) |
                        ((ulong)input[offset + 5] << 8 * 5) |
                        ((ulong)input[offset + 6] << 8 * 6) |
                        ((ulong)input[offset + 7] << 8 * 7);

                if (++ctx.wordIndex == (KeccakConstants.SHA3_SPONGE_WORDS - KeccakFunctions.SHA3_CW(ctx.capacityWords)))
                {
                    KeccakFunctions.keccakf(spounge);
                    ctx.wordIndex = 0;
                }
            }

            // Add remaining odd bytes
            while (tail-- > 0)
            {
                ctx.saved |= (ulong)input[offset++] << (ctx.byteIndex++ * 8);
            }
        }

        private int WriteTail(byte[] input)
        {
            // 0...7 -- how much is needed to have a word
            int old_tail = (8 - ctx.byteIndex) & 7;

            if (input.Length < old_tail)
            {
                // have no complete word or haven't started
                // the word yet
                foreach(var b in input)
                {
                    ctx.saved |= (ulong)b << (ctx.byteIndex++ * 8);
                }
                return input.Length;
            }

            if (old_tail > 0)
            {
                for (int i = 0; i < old_tail; ++i)
                {
                    ctx.saved |= (ulong)input[i] << (ctx.byteIndex++ * 8);
                }

                // now ready to add saved to the sponge
                ctx.spounge[ctx.wordIndex] ^= ctx.saved;
                ctx.byteIndex = 0;
                ctx.saved = 0;

                if (++ctx.wordIndex == (KeccakConstants.SHA3_SPONGE_WORDS - KeccakFunctions.SHA3_CW(ctx.capacityWords)))
                {
                    KeccakFunctions.keccakf(ctx.spounge);
                    ctx.wordIndex = 0;
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
            if (hash.Length < ctx.HashSz)
            {
                throw new ArgumentOutOfRangeException(nameof(hash), hash.Length, "Hash buffer must be at least " + ctx.HashSz + " bytes long");
            }

            // Append 2-bit suffix 01, per SHA-3 spec. Instead of 1 for padding we
            //  use 1<<2 below. The 0x02 below corresponds to the suffix 01.
            //  Overall, we feed 0, then 1, and finally 1 to start padding. Without
            //  M || 01, we would simply use 1 to start padding.

            ulong t;

            if (ctx.IsKeccak)
            {
                // Keccak version
                t = ((ulong)1) << (ctx.byteIndex * 8);
            }
            else
            {
                // SHA3 version
                t = ((ulong)(0x02 | (1 << 2))) << (ctx.byteIndex * 8);
            }

            ctx.spounge[ctx.wordIndex] ^= ctx.saved ^ t;
            ctx.spounge[KeccakConstants.SHA3_SPONGE_WORDS - (int)KeccakFunctions.SHA3_CW(ctx.capacityWords) - 1] ^= 0x8000000000000000UL;
            KeccakFunctions.keccakf(ctx.spounge);
            ctx.spoungeBytes.AsSpan(0, ctx.HashSz).CopyTo(hash);

            // Reset hasher state
            Reset();
        }

        public byte[] Digest()
        {
            byte[] hash = new byte[ctx.HashSz];
            Digest(hash);
            return hash;
        }

        public bool IsKeccak
        {
            get
            {
                return ctx.IsKeccak;
            }
        }
    }
}

