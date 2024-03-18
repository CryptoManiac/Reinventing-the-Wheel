using System.Runtime.InteropServices;
using Wheel.Crypto.Hashing.RIPEMD.Internal;

namespace Wheel.Crypto.Hashing.RIPEMD
{
    [StructLayout(LayoutKind.Explicit)]
    public struct RIPEMD160 : IHasher
	{
        [FieldOffset(0)]
        private uint bytesLo = 0;

        [FieldOffset(4)]
        private uint bytesHi = 0;

        [FieldOffset(8)]
        private InternalRIPEMDState state = InternalRIPEMDConstants.ripemd_init_state;

        [FieldOffset(12 + InternalRIPEMDBlock.TypeByteSz)]
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
            state = InternalRIPEMDConstants.ripemd_init_state;
            block.Reset();
        }

        public static byte[] Hash(ReadOnlySpan<byte> input)
        {
            RIPEMD160 hasher = new();
            hasher.Update(input);
            return hasher.Digest();
        }

        public static void Hash(Span<byte> digest, ReadOnlySpan<byte> input)
        {
            RIPEMD160 hasher = new();
            hasher.Update(input);
            hasher.Digest(digest);
        }

        public void Update(ReadOnlySpan<byte> input)
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
                block.Write(input.Slice(offset, 64 - (int)i), i);
                InternalRIPEMDOps.Compress(ref state, block);
                offset += 64 - (int)i;
                len -= 64 - i;
            }

            while (len >= 64)
            {
                // Process data in 64-byte chunks
                block.Write(input.Slice(offset, 64), i);
                InternalRIPEMDOps.Compress(ref state, block);
                offset += 64;
                len -= 64;
            }

            if (len > 0)
            {
                // Handle any remaining bytes of data.
                block.Write(input.Slice(offset, (int)len), 0);
            }
        }

        public void Dispose()
        {
            Reset();
        }
    }
}

