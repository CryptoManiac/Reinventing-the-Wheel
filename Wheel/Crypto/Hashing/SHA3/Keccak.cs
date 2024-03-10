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
            // Do nothing if buffer is empty
            if (input.Length != 0)
            {
                unsafe
                {
                    fixed (byte* ptr = &input[0])
                    {
                        Update(ptr, input.Length);
                    }
                }
            }
        }

        private unsafe void Update(byte* buf, int len)
        {
            // 0...7 -- how much is needed to have a word
            int old_tail = (8 - ctx.byteIndex) & 7;

            if (len < old_tail)
            {
                // have no complete word or haven't started
                // the word yet
                while (len-- > 0)
                {
                    ctx.saved |= (ulong)*buf++ << (ctx.byteIndex++ * 8);
                }
                return;
            }

            if (old_tail > 0)
            {
                len -= old_tail;
                while (old_tail-- > 0)
                {
                    ctx.saved |= (ulong)*buf++ << (ctx.byteIndex++ * 8);
                }

                // now ready to add saved to the sponge
                ctx.s[ctx.wordIndex] ^= ctx.saved;
                ctx.byteIndex = 0;
                ctx.saved = 0;

                if (++ctx.wordIndex == (KeccakConstants.SHA3_SPONGE_WORDS - KeccakFunctions.SHA3_CW(ctx.capacityWords)))
                {
                    fixed (ulong* s = &ctx.s[0])
                    {
                        KeccakFunctions.keccakf(new Span<ulong>(s, KeccakConstants.SHA3_SPONGE_WORDS));
                    }

                    ctx.wordIndex = 0;
                }
            }

            // now work in full words directly from input

            int words = len / sizeof(ulong);
            int tail = len - words * sizeof(ulong);

            for (int i = 0; i < words; i++, buf += sizeof(ulong))
            {
                ctx.s[ctx.wordIndex] ^= (buf[0]) |
                        ((ulong)buf[1] << 8 * 1) |
                        ((ulong)buf[2] << 8 * 2) |
                        ((ulong)buf[3] << 8 * 3) |
                        ((ulong)buf[4] << 8 * 4) |
                        ((ulong)buf[5] << 8 * 5) |
                        ((ulong)buf[6] << 8 * 6) |
                        ((ulong)buf[7] << 8 * 7);

                if (++ctx.wordIndex == (KeccakConstants.SHA3_SPONGE_WORDS - KeccakFunctions.SHA3_CW(ctx.capacityWords)))
                {
                    fixed (ulong* s = &ctx.s[0])
                    {
                        KeccakFunctions.keccakf(new Span<ulong>(s, KeccakConstants.SHA3_SPONGE_WORDS));
                    }
                    ctx.wordIndex = 0;
                }
            }

            while (tail-- > 0)
            {
                ctx.saved |= (ulong)*buf++ << (ctx.byteIndex++ * 8);
            }
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

            unsafe
            {
                ctx.s[ctx.wordIndex] ^= ctx.saved ^ t;
                ctx.s[KeccakConstants.SHA3_SPONGE_WORDS - KeccakFunctions.SHA3_CW(ctx.capacityWords) - 1] ^= 0x8000000000000000UL;

                fixed (ulong* s = &ctx.s[0])
                {
                    KeccakFunctions.keccakf(new Span<ulong>(s, KeccakConstants.SHA3_SPONGE_WORDS));
                }

                fixed (byte* ptr = &ctx.sb[0])
                {
                    new Span<byte>(ptr, ctx.HashSz).CopyTo(hash);
                }
            }
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

