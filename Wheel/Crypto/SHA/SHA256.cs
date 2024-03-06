using Wheel.Crypto.Primitives.ByteVectors;
using Wheel.Crypto.Primitives.WordVectors;
using Wheel.Crypto.Miscellaneous.Support;
using System.Runtime.CompilerServices;

namespace Wheel.Crypto.SHA
{
    public class SHA256
	{
        /// <summary>
        /// True after Digest() has been called
        /// </summary>
        private bool finished;

        /// <summary>
        /// Current data block length in bytes
        /// </summary>
        private uint blockLen;

        /// <summary>
        /// Total input length in bits
        /// </summary>
        private ulong bitLen;

        /// <summary>
        /// Pending block data to transform
        /// </summary>
        private ByteVec64 pendingBlock = new();

        /// <summary>
        /// Current hashing state
        /// </summary>
        private WordVec8 state = new();

        /// <summary>
        /// Vector for the final result
        /// </summary>
        private ByteVec32 result = new();

        /// <summary>
        /// Vector for sum() calculation in Transform()
        /// </summary>
        WordVec64 wordPad = new();

        public SHA256()
        {
            Reset();
        }

        /// <summary>
        /// Reset to initial state
        /// </summary>
        public void Reset()
        {
            blockLen = 0;
            bitLen = 0;
            pendingBlock.Reset();
            state.SetWords(SHA256Misc.init_state);
            wordPad.Reset();
            finished = false;
        }

        /// <summary>
        /// Update hasher with new data bytes
        /// </summary>
        /// <param name="input">Input bytes to update hasher with</param>
        /// <exception cref="InvalidOperationException"></exception>
        public void Update(byte[] input)
        {
            if (finished)
            {
                throw new InvalidOperationException("Called Update() on finished hasher");
            }

            for (int i = 0; i < input.Length; ++i)
            {
                pendingBlock[(int)blockLen++] = input[i];
                if (blockLen == 64)
                {
                    Transform();

                    // End of the block
                    bitLen += 512;
                    blockLen = 0;
                }
            }
        }

        /// <summary>
        /// Get SHA256 hash as a new byte array
        /// </summary>
        /// <returns></returns>
        public byte[] Digest()
        {
            Finish();
            return result.GetBytes();
        }

        /// <summary>
        /// Write SHA256 hash into given byte array
        /// </summary>
        /// <param name="hash">Byte array to write into</param>
        /// <param name="offset">Byte array offset beginning from zero</param>
        public void Digest(ref byte[] hash, int offset = 0)
        {
            Finish();
            result.StoreByteArray(ref hash, offset);
        }

        private void Transform()
        {
            // Split data in 32 bit blocks for the first 16 words
            wordPad.Set16Words(pendingBlock.wv16);

            // SHA uses big endian byte ordering
            wordPad.Revert16Words();

            // Remaining 48 blocks
            for (int i = 16; i < 64; ++i)
            {
                wordPad[i] = SHA256Misc.SIG1(wordPad[i - 2]) + wordPad[i - 7] + SHA256Misc.SIG0(wordPad[i - 15]) + wordPad[i - 16];
            }

            uint a = state[0];
            uint b = state[1];
            uint c = state[2];
            uint d = state[3];
            uint e = state[4];
            uint f = state[5];
            uint g = state[6];
            uint h = state[7];
            
            for (int i = 0; i < 64; ++i)
            {
                uint t1 = h + SHA256Misc.SIGMA1(e) + SHA256Misc.CHOOSE(e, f, g) + SHA256Misc.K[i] + wordPad[i];
                uint t2 = SHA256Misc.SIGMA0(a) + SHA256Misc.MAJ(a, b, c);

                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }

            state.AddWords(a, b, c, d, e, f, g, h);
        }

        private void Finish()
        {
            if (finished)
            {
                throw new InvalidOperationException("Called Digest() on a finished hasher");
            }

            int i = (int)blockLen;
            byte end = (byte)(blockLen < 56 ? 56 : 64);

            pendingBlock[i++] = 0x80; // Append a bit 1
            while (i < end)
            {
                pendingBlock[i++] = 0x00; // Pad with zeros
            }

            if (blockLen >= 56)
            {
                Transform();
                uint lastWord = pendingBlock.wv16[15];
                pendingBlock.Reset();
                pendingBlock.wv16[15] = lastWord;
            }

            // Append to the padding the total message's
            // length in bits and transform.
            bitLen += blockLen * 8;
            pendingBlock.dwv8[7] = Common.REVERT(bitLen);
            Transform();

            // Store result
            result.wv8.SetWords(state);

            // SHA uses big endian byte ordering
            result.wv8.RevertWords();

            // Don't let call us anymore
            finished = true;
        }
    }

    /// <summary>
    /// Constants and functions which are specific for SHA-256
    /// </summary>
    internal static class SHA256Misc
    {
        /// <summary>
        /// SHA-256 init state words
        /// </summary>
        public static readonly WordVec8 init_state = new(
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
            );

        /// <summary>
        /// SHA-256 round constants
        /// </summary>
        public static readonly WordVec64 K = new(
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
            );

        // Inline for performance reasons
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint ROTR(uint x, int n) => (x >> n) | (x << (32 - n));
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint CHOOSE(uint e, uint f, uint g) => (e & f) ^ (~e & g);
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint MAJ(uint a, uint b, uint c) => (a & (b | c)) | (b & c);
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint SIG0(uint x) => ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3);
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint SIG1(uint x) => ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10);

        // Inlining these methods might cause more harm than good
        public static uint SIGMA0(uint x) => ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
        public static uint SIGMA1(uint x) => ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
    }
}
