using System.Runtime.InteropServices;

namespace Wheel.Crypto.Hashing.SHA3.Internal
{
    [StructLayout(LayoutKind.Explicit)]
    public unsafe struct InternalKeccakState
    {
        /// <summary>
        /// 0..7--the next byte after the set one
        /// (starts from 0; 0--none are buffered)
        /// </summary>
        [FieldOffset(0)]
        public int byteIndex;

        /// <summary>
        /// 0..24--the next word to integrate input
        /// (starts from 0)
        /// </summary>
        [FieldOffset(4)]
        public int wordIndex;

        /// <summary>
        /// the double size of the hash output in
        /// words (e.g. 16 for Keccak 512)
        /// </summary>
        [FieldOffset(8)]
        public uint capacityWords;

        /// <summary>
        /// the portion of the input message that we didn't consume yet
        /// </summary>
        [FieldOffset(12)]
        public ulong saved;

        /// <summary>
        /// Overlapping Keccak state data field
        /// </summary>
        [FieldOffset(20)]
        public fixed ulong s[KeccakConstants.SHA3_SPONGE_WORDS];

        /// <summary>
        /// Overlapping Keccak state data field
        /// </summary>
        [FieldOffset(20)]
        public fixed byte sb[KeccakConstants.SHA3_SPONGE_WORDS * 8];

        public bool IsKeccak
        {
            get { return 0 != (capacityWords & KeccakConstants.SHA3_USE_KECCAK_FLAG); }
        }

        public int HashSz
        {
            get { return (int)capacityWords * 4; }
        }

        public InternalKeccakState(int bitSize, bool useKeccak)
        {
            if (bitSize != 256 && bitSize != 384 && bitSize != 512)
            {
                throw new InvalidOperationException("Valid bitSize values are: 256, 384 or 512");
            }

            fixed (void* ptr = &this)
            {
                new Span<byte>(ptr, sizeof(InternalKeccakState)).Clear();
            }

            capacityWords = (uint)bitSize / 32;

            if (useKeccak)
            {
                capacityWords |= KeccakConstants.SHA3_USE_KECCAK_FLAG;
            }
        }

        /// <summary>
        /// Reset to postinit-like state
        /// </summary>
        public unsafe void Reset()
        {
            uint capacity = capacityWords;
            fixed (void* ptr = &this)
            {
                new Span<byte>(ptr, sizeof(InternalKeccakState)).Clear();
            }
            capacityWords = capacity;
        }
    }
}

