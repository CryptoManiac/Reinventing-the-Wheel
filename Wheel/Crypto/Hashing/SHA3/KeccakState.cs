using System.Runtime.InteropServices;

namespace Wheel.Crypto.Hashing.SHA3.Internal
{
    public struct InternalKeccakState
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
        public int wordIndex;

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
        /// Overlapping Keccak state data field
        /// </summary>
        public readonly byte[] spoungeBytes;

        /// <summary>
        /// Overlapping Keccak state data field
        /// </summary>
        public readonly Span<ulong> spounge {
            get { return MemoryMarshal.Cast<byte, ulong>(spoungeBytes); }
        }

        public bool IsKeccak
        {
            get { return 0 != (capacityWords & KeccakConstants.SHA3_USE_KECCAK_FLAG); }
        }

        public readonly int HashSz
        {
            get { return (int)capacityWords * 4; }
        }

        public InternalKeccakState(int bitSize, bool useKeccak) : this()
        {
            if (bitSize != 256 && bitSize != 384 && bitSize != 512)
            {
                throw new InvalidOperationException("Valid bitSize values are: 256, 384 or 512");
            }

            spoungeBytes = new byte[KeccakConstants.SHA3_SPONGE_WORDS * 8];
            capacityWords = (uint)bitSize / 32;

            if (useKeccak)
            {
                capacityWords |= KeccakConstants.SHA3_USE_KECCAK_FLAG;
            }
        }

        /// <summary>
        /// Reset to postinit-like state
        /// </summary>
        public void Reset()
        {
            spounge.Clear();
            wordIndex = 0;
            byteIndex = 0;
            saved = 0;
        }
    }
}

