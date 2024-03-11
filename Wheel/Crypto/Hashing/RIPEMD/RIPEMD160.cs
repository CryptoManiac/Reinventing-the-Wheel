using Wheel.Crypto.Hashing.RIPEMD.Internal;

namespace Wheel.Crypto.Hashing.RIPEMD
{
	public struct RIPEMD160 : IHasher
	{
        private uint bytesLo = 0, bytesHi = 0;
        private InternalRIPEMDState state = new(InternalRIPEMDConstants.ripemd_init_state);
        private InternalRIPEMDBlock block = new();

        public RIPEMD160()
        {
        }

        public readonly int HashSz => 20;

        public byte[] Digest()
        {
            byte[] hash = new byte[20];
            Digest(hash);
            return hash;
        }

        public void Digest(Span<byte> digest)
        {
            InternalRIPEMDOps.Finish(ref state, ref block, bytesLo, bytesHi);
            state.Store(digest);
            Reset(); // In case it's sensitive
        }

        public void Reset()
        {
            bytesLo = 0;
            bytesHi = 0;
            state.Set(InternalRIPEMDConstants.ripemd_init_state);
            block.Reset();
        }

        public static byte[] Hash(byte[] input)
        {
            RIPEMD160 hasher = new();
            hasher.Update(input);
            return hasher.Digest();
        }

        public static void Hash(Span<byte> digest, byte[] input)
        {
            RIPEMD160 hasher = new();
            hasher.Update(input);
            hasher.Digest(digest);
        }

        public void Update(byte[] input)
        {
            uint len = (uint)input.Length;

            // Update bitcount
            uint t = bytesLo;
            if ((bytesLo = t + len) < t)
            {
                // Carry from low to high
                ++bytesHi;
            }

            // Bytes already in key
            uint i = t % 64;

            // i is always less than block size
            if (64 - i > len)
            {
                block.Write(input, i);
                return;
            }

            // Distance from the beginning
            // of the input array
            int offset = 0;

            if (i > 0)
            {
                // First chunk is an odd size
                block.Write(input.AsSpan(offset, 64 - (int)i), i);
                InternalRIPEMDOps.Compress(ref state, block);
                offset += 64 - (int)i;
                len -= 64 - i;
            }

            while (len >= 64)
            {
                // Process data in 64-byte chunks
                block.Write(input.AsSpan(offset, 64), i);
                InternalRIPEMDOps.Compress(ref state, block);
                offset += 64;
                len -= 64;
            }

            if (len > 0)
            {
                // Handle any remaining bytes of data.
                block.Write(input.AsSpan(offset, (int)len), 0);
            }
        }
    }
}

