using Wheel.Crypto.Primitives.ByteVectors;
using Wheel.Crypto.Primitives.WordVectors;
using Wheel.Crypto.Miscellaneous.Support;

namespace Wheel.Crypto.SHA
{
    public class SHA512
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
        private ByteVec128 pendingBlock = new();

        /// <summary>
        /// Current hashing state
        /// </summary>
        private DWordVec8 state = new();

        /// <summary>
        /// Vector for the final result
        /// </summary>
        private ByteVec64 result = new();

        /// <summary>
        /// Vector for sum() calculation in Transform()
        /// </summary>
        DWordVec80 wordPad = new();

        public SHA512()
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
            state.SetWords(SHA512Misc.init_state);
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
                if (blockLen == 128)
                {
                    Transform();

                    // End of the block
                    bitLen += 1024;
                    blockLen = 0;
                }
            }
        }

        /// <summary>
        /// Get SHA512 hash as a new byte array
        /// </summary>
        /// <returns></returns>
        public byte[] Digest()
        {
            Finish();
            return result.GetBytes();
        }

        /// <summary>
        /// Write SHA512 hash into given byte array
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
            // Split data in 64 bit blocks for the first 16 words
            wordPad.Set16Words(pendingBlock.dwv16);

            // SHA uses big endian byte ordering
            wordPad.Revert16Words();

            // Remaining blocks
            for (int i = 16; i < 80; ++i)
            {
                wordPad[i] = SHA512Misc.SIG1(wordPad[i - 2]) + wordPad[i - 7] + SHA512Misc.SIG0(wordPad[i - 15]) + wordPad[i - 16];
            }

            ulong a = state[0];
            ulong b = state[1];
            ulong c = state[2];
            ulong d = state[3];
            ulong e = state[4];
            ulong f = state[5];
            ulong g = state[6];
            ulong h = state[7];
            
            for (int i = 0; i < 80; ++i)
            {
                ulong t1 = h + SHA512Misc.SIGMA1(e) + SHA512Misc.CHOOSE(e, f, g) + SHA512Misc.K[i] + wordPad[i];
                ulong t2 = SHA512Misc.SIGMA0(a) + SHA512Misc.MAJ(a, b, c);

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
            byte end = (byte)(blockLen < 120 ? 120 : 128);

            pendingBlock[i++] = 0x80; // Append a bit 1
            while (i < end)
            {
                pendingBlock[i++] = 0x00; // Pad with zeros
            }

            if (blockLen >= 120)
            {
                Transform();
                ulong lastWord = pendingBlock.dwv16[15];
                pendingBlock.Reset();
                pendingBlock.dwv16[15] = lastWord;
            }

            // Append to the padding the total message's
            // length in bits and transform.
            bitLen += blockLen * 8;
            pendingBlock.dwv16[15] = Common.REVERT(bitLen);
            Transform();

            // Store result
            result.dwv8.SetWords(state);

            // SHA uses big endian byte ordering
            result.dwv8.RevertWords();

            // Don't let call us anymore
            finished = true;
        }
    }

    /// <summary>
    /// Constants which are specific for SHA-512
    /// </summary>
    internal static class SHA512Misc
    {
        /// <summary>
        /// SHA-512 init state words
        /// </summary>
        public static readonly DWordVec8 init_state = new(
                  0x6a09e667f3bcc908,
                  0xbb67ae8584caa73b,
                  0x3c6ef372fe94f82b,
                  0xa54ff53a5f1d36f1,
                  0x510e527fade682d1,
                  0x9b05688c2b3e6c1f,
                  0x1f83d9abfb41bd6b,
                  0x5be0cd19137e2179
            );

        /// <summary>
        /// SHA-512 round constants
        /// </summary>
        public static readonly DWordVec80 K = new(
                  0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
                  0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
                  0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
                  0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
                  0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
                  0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
                  0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
                  0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
                  0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
                  0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
                  0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
                  0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
                  0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
                  0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
                  0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
                  0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
            );

        private static ulong SHFR(ulong x, int n) => x >> n;
        private static ulong ROTR(ulong x, int n) => (x >> n) | (x << (64 - n));
        public static ulong CHOOSE(ulong x, ulong y, ulong z) => (x & y) ^ (~x & z);
        public static ulong MAJ(ulong x, ulong y, ulong z) => (x & y) ^ (x & z) ^ (y & z);
        public static ulong SIGMA0(ulong x) => ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39);
        public static ulong SIGMA1(ulong x) => ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41);
        public static ulong SIG0(ulong x) => ROTR(x, 1) ^ ROTR(x, 8) ^ SHFR(x, 7);
        public static ulong SIG1(ulong x) => ROTR(x, 19) ^ ROTR(x, 61) ^ SHFR(x, 6);
    }
}
