using System;
using System.Runtime.InteropServices;
using Wheel.Crypto.Primitives;
using Wheel.Crypto.Primitives.ByteVectors;
using Wheel.Crypto.Primitives.WordVectors;

namespace Wheel.Crypto.RIPEMD
{
	public class RIPEMD160 : IHasherInterface
	{
        private int bytesLo, bytesHi;
        private WordVec5 iv = new();
        private ByteVec64 key = new();

		public RIPEMD160()
		{
            Reset();
		}

        public byte[] Digest()
        {
            byte[] hash = new byte[20];
            Digest(hash);
            return hash;
        }

        public void Digest(Span<byte> digest)
        {
            RIPEMD160Misc.Finish(ref iv, ref key, bytesLo, bytesHi);

            for (int i = 0; i < 5; ++i)
            {
                uint t = iv[(uint)i];
                digest[i * 4 + 0] = (byte)t;
                digest[i * 4 + 1] = (byte)(t >> 8);
                digest[i * 4 + 2] = (byte)(t >> 16);
                digest[i * 4 + 3] = (byte)(t >> 24);
            }

            Reset(); // In case it's sensitive
        }

        public void Reset()
        {
            bytesLo = 0;
            bytesHi = 0;
            iv.SetWords(RIPEMD160Misc.ripemd_init_state);
            key.Reset();
        }

        public void Update(byte[] input)
        {
            int len = input.Length;

            // Update bitcount
            int t = bytesLo;

            bytesLo += len;

            if (bytesLo < t)
            {
                // Carry from low to high
                ++bytesHi;
            }

            // Bytes already in key
            int i = t % 64;

            // i is always less than block size
            if (64 - i > len)
            {
                key.Write(input, (uint)i);
                return;
            }

            // Distance from the beginning
            // of the input array
            int offset = 0;

            if (i > 0)
            {
                // Have to cast for Span constructor here
                int chunkLen = 64 - i;

                // First chunk is an odd size
                Span<byte> blockToWrite = new(input, offset, chunkLen);
                key.Write(blockToWrite, (uint)i);
                key.wv16.RevertWords();
                RIPEMD160Misc.Compress(ref iv, key.wv16);
                offset += chunkLen;
                len -= chunkLen;
            }

            while (len >= 64)
            {
                // Process data in 64-byte chunks
                Span<byte> blockToWrite = new(input, offset, 64);
                key.Write(blockToWrite, (uint)i);
                key.wv16.RevertWords();
                offset += 64;
                len -= 64;
            }

            if (len > 0)
            {
                // Handle any remaining bytes of data.
                Span<byte> blockToWrite = new(input, offset, len);
                key.Write(blockToWrite, 0);
            }
        }
    }

    internal static class RIPEMD160Misc
    {
        /// <summary>
        /// RIPEMD-160 initial constants
        /// </summary>
        public static WordVec5 ripemd_init_state = new(0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0);

        /// <summary>
        /// ROL(x, n) cyclically rotates x over n bits to the left.
        /// x must be of an unsigned 32 bits type and 0 <= n < 32.
        /// </summary>
        /// <param name="x"></param>
        /// <param name="n"></param>
        /// <returns></returns>
        static uint ROL(uint x, int n) => (((x) << (n)) | ((x) >> (32 - (n))));

        // the three basic functions F(), G() and H()
        static uint F(uint x, uint y, uint z) => ((x) ^ (y) ^ (z));
        static uint G(uint x, uint y, uint z) => (((x) & (y)) | (~(x) & (z)));
        static uint H(uint x, uint y, uint z) => (((x) | ~(y)) ^ (z));
        static uint I(uint x, uint y, uint z) => (((x) & (z)) | ((y) & ~(z)));

        static uint J(uint x, uint y, uint z) => ((x) ^ ((y) | ~(z)));

        // the eight basic operations FF() through III()
        static void FF(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s) {
            a += F(b, c, d) + x;
            a = ROL(a, s) + e;
            c = ROL(c, 10);
        }

        static void GG(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s) {
            a += G(b, c, d) + x + 0x5a827999;
            a = ROL(a, s) + e;
            c = ROL(c, 10);
        }

        static void HH(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s) {
            a += H(b, c, d) + x + 0x6ed9eba1;
            a = ROL(a, s) + e;
	        c = ROL(c, 10);
	    }

        static void II(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s) {
            a += I(b, c, d) + x + 0x8f1bbcdc;
            a = ROL(a, s) + e;
            c = ROL(c, 10);
	    }

        static void JJ(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s) {
            a += J(b, c, d) + x + 0xa953fd4e;
            a = ROL(a, s) + e;
            c = ROL(c, 10);
        }

        static void FFF(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s)	{
            a += F(b, c, d) + x;
            a = ROL(a, s) + e;
	        c = ROL(c, 10);
        }

        static void GGG(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s)	{
            a += G(b, c, d) + x + 0x7a6d76e9;
            a = ROL(a, s) + e;
            c = ROL(c, 10);
        }

        static void HHH(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s) {
            a += H(b, c, d) + x + 0x6d703ef3;
            a = ROL(a, s) + e;
	        c = ROL(c, 10);
        }

        static void III(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s) {
            a += I(b, c, d) + x + 0x5c4dd124;
            a = ROL(a, s) + e;
            c = ROL(c, 10);
        }

        static void JJJ(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s) {
            a += J(b, c, d) + x + 0x50a28be6;
            a = ROL(a, s) + e;
            c = ROL(c, 10);
	    }

        /// <summary>
        /// The compression function.
        /// Transforms MDbuf using message bytes X[0] through X[15]
        /// </summary>
        public static void Compress(ref WordVec5 MDbuf, in WordVec16 X)
        {
            uint aa = MDbuf[0];
            uint bb = MDbuf[1];
            uint cc = MDbuf[2];
            uint dd = MDbuf[3];
            uint ee = MDbuf[4];

            uint aaa = MDbuf[0];
            uint bbb = MDbuf[1];
            uint ccc = MDbuf[2];
            uint ddd = MDbuf[3];
            uint eee = MDbuf[4];

            // round 1
            FF(ref aa, bb, ref cc, dd, ee, X[0], 11);
            FF(ref ee, aa, ref bb, cc, dd, X[1], 14);
            FF(ref dd, ee, ref aa, bb, cc, X[2], 15);
            FF(ref cc, dd, ref ee, aa, bb, X[3], 12);
            FF(ref bb, cc, ref dd, ee, aa, X[4], 5);
            FF(ref aa, bb, ref cc, dd, ee, X[5], 8);
            FF(ref ee, aa, ref bb, cc, dd, X[6], 7);
            FF(ref dd, ee, ref aa, bb, cc, X[7], 9);
            FF(ref cc, dd, ref ee, aa, bb, X[8], 11);
            FF(ref bb, cc, ref dd, ee, aa, X[9], 13);
            FF(ref aa, bb, ref cc, dd, ee, X[10], 14);
            FF(ref ee, aa, ref bb, cc, dd, X[11], 15);
            FF(ref dd, ee, ref aa, bb, cc, X[12], 6);
            FF(ref cc, dd, ref ee, aa, bb, X[13], 7);
            FF(ref bb, cc, ref dd, ee, aa, X[14], 9);
            FF(ref aa, bb, ref cc, dd, ee, X[15], 8);

            // round 2
            GG(ref ee, aa, ref bb, cc, dd, X[7], 7);
            GG(ref dd, ee, ref aa, bb, cc, X[4], 6);
            GG(ref cc, dd, ref ee, aa, bb, X[13], 8);
            GG(ref bb, cc, ref dd, ee, aa, X[1], 13);
            GG(ref aa, bb, ref cc, dd, ee, X[10], 11);
            GG(ref ee, aa, ref bb, cc, dd, X[6], 9);
            GG(ref dd, ee, ref aa, bb, cc, X[15], 7);
            GG(ref cc, dd, ref ee, aa, bb, X[3], 15);
            GG(ref bb, cc, ref dd, ee, aa, X[12], 7);
            GG(ref aa, bb, ref cc, dd, ee, X[0], 12);
            GG(ref ee, aa, ref bb, cc, dd, X[9], 15);
            GG(ref dd, ee, ref aa, bb, cc, X[5], 9);
            GG(ref cc, dd, ref ee, aa, bb, X[2], 11);
            GG(ref bb, cc, ref dd, ee, aa, X[14], 7);
            GG(ref aa, bb, ref cc, dd, ee, X[11], 13);
            GG(ref ee, aa, ref bb, cc, dd, X[8], 12);

            // round 3
            HH(ref dd, ee, ref aa, bb, cc, X[3], 11);
            HH(ref cc, dd, ref ee, aa, bb, X[10], 13);
            HH(ref bb, cc, ref dd, ee, aa, X[14], 6);
            HH(ref aa, bb, ref cc, dd, ee, X[4], 7);
            HH(ref ee, aa, ref bb, cc, dd, X[9], 14);
            HH(ref dd, ee, ref aa, bb, cc, X[15], 9);
            HH(ref cc, dd, ref ee, aa, bb, X[8], 13);
            HH(ref bb, cc, ref dd, ee, aa, X[1], 15);
            HH(ref aa, bb, ref cc, dd, ee, X[2], 14);
            HH(ref ee, aa, ref bb, cc, dd, X[7], 8);
            HH(ref dd, ee, ref aa, bb, cc, X[0], 13);
            HH(ref cc, dd, ref ee, aa, bb, X[6], 6);
            HH(ref bb, cc, ref dd, ee, aa, X[13], 5);
            HH(ref aa, bb, ref cc, dd, ee, X[11], 12);
            HH(ref ee, aa, ref bb, cc, dd, X[5], 7);
            HH(ref dd, ee, ref aa, bb, cc, X[12], 5);

            // round 4
            II(ref cc, dd, ref ee, aa, bb, X[1], 11);
            II(ref bb, cc, ref dd, ee, aa, X[9], 12);
            II(ref aa, bb, ref cc, dd, ee, X[11], 14);
            II(ref ee, aa, ref bb, cc, dd, X[10], 15);
            II(ref dd, ee, ref aa, bb, cc, X[0], 14);
            II(ref cc, dd, ref ee, aa, bb, X[8], 15);
            II(ref bb, cc, ref dd, ee, aa, X[12], 9);
            II(ref aa, bb, ref cc, dd, ee, X[4], 8);
            II(ref ee, aa, ref bb, cc, dd, X[13], 9);
            II(ref dd, ee, ref aa, bb, cc, X[3], 14);
            II(ref cc, dd, ref ee, aa, bb, X[7], 5);
            II(ref bb, cc, ref dd, ee, aa, X[15], 6);
            II(ref aa, bb, ref cc, dd, ee, X[14], 8);
            II(ref ee, aa, ref bb, cc, dd, X[5], 6);
            II(ref dd, ee, ref aa, bb, cc, X[6], 5);
            II(ref cc, dd, ref ee, aa, bb, X[2], 12);

            // round 5
            JJ(ref bb, cc, ref dd, ee, aa, X[4], 9);
            JJ(ref aa, bb, ref cc, dd, ee, X[0], 15);
            JJ(ref ee, aa, ref bb, cc, dd, X[5], 5);
            JJ(ref dd, ee, ref aa, bb, cc, X[9], 11);
            JJ(ref cc, dd, ref ee, aa, bb, X[7], 6);
            JJ(ref bb, cc, ref dd, ee, aa, X[12], 8);
            JJ(ref aa, bb, ref cc, dd, ee, X[2], 13);
            JJ(ref ee, aa, ref bb, cc, dd, X[10], 12);
            JJ(ref dd, ee, ref aa, bb, cc, X[14], 5);
            JJ(ref cc, dd, ref ee, aa, bb, X[1], 12);
            JJ(ref bb, cc, ref dd, ee, aa, X[3], 13);
            JJ(ref aa, bb, ref cc, dd, ee, X[8], 14);
            JJ(ref ee, aa, ref bb, cc, dd, X[11], 11);
            JJ(ref dd, ee, ref aa, bb, cc, X[6], 8);
            JJ(ref cc, dd, ref ee, aa, bb, X[15], 5);
            JJ(ref bb, cc, ref dd, ee, aa, X[13], 6);

            // parallel round 1
            JJJ(ref aaa, bbb, ref ccc, ddd, eee, X[5], 8);
            JJJ(ref eee, aaa, ref bbb, ccc, ddd, X[14], 9);
            JJJ(ref ddd, eee, ref aaa, bbb, ccc, X[7], 9);
            JJJ(ref ccc, ddd, ref eee, aaa, bbb, X[0], 11);
            JJJ(ref bbb, ccc, ref ddd, eee, aaa, X[9], 13);
            JJJ(ref aaa, bbb, ref ccc, ddd, eee, X[2], 15);
            JJJ(ref eee, aaa, ref bbb, ccc, ddd, X[11], 15);
            JJJ(ref ddd, eee, ref aaa, bbb, ccc, X[4], 5);
            JJJ(ref ccc, ddd, ref eee, aaa, bbb, X[13], 7);
            JJJ(ref bbb, ccc, ref ddd, eee, aaa, X[6], 7);
            JJJ(ref aaa, bbb, ref ccc, ddd, eee, X[15], 8);
            JJJ(ref eee, aaa, ref bbb, ccc, ddd, X[8], 11);
            JJJ(ref ddd, eee, ref aaa, bbb, ccc, X[1], 14);
            JJJ(ref ccc, ddd, ref eee, aaa, bbb, X[10], 14);
            JJJ(ref bbb, ccc, ref ddd, eee, aaa, X[3], 12);
            JJJ(ref aaa, bbb, ref ccc, ddd, eee, X[12], 6);

            // parallel round 2
            III(ref eee, aaa, ref bbb, ccc, ddd, X[6], 9);
            III(ref ddd, eee, ref aaa, bbb, ccc, X[11], 13);
            III(ref ccc, ddd, ref eee, aaa, bbb, X[3], 15);
            III(ref bbb, ccc, ref ddd, eee, aaa, X[7], 7);
            III(ref aaa, bbb, ref ccc, ddd, eee, X[0], 12);
            III(ref eee, aaa, ref bbb, ccc, ddd, X[13], 8);
            III(ref ddd, eee, ref aaa, bbb, ccc, X[5], 9);
            III(ref ccc, ddd, ref eee, aaa, bbb, X[10], 11);
            III(ref bbb, ccc, ref ddd, eee, aaa, X[14], 7);
            III(ref aaa, bbb, ref ccc, ddd, eee, X[15], 7);
            III(ref eee, aaa, ref bbb, ccc, ddd, X[8], 12);
            III(ref ddd, eee, ref aaa, bbb, ccc, X[12], 7);
            III(ref ccc, ddd, ref eee, aaa, bbb, X[4], 6);
            III(ref bbb, ccc, ref ddd, eee, aaa, X[9], 15);
            III(ref aaa, bbb, ref ccc, ddd, eee, X[1], 13);
            III(ref eee, aaa, ref bbb, ccc, ddd, X[2], 11);

            // parallel round 3
            HHH(ref ddd, eee, ref aaa, bbb, ccc, X[15], 9);
            HHH(ref ccc, ddd, ref eee, aaa, bbb, X[5], 7);
            HHH(ref bbb, ccc, ref ddd, eee, aaa, X[1], 15);
            HHH(ref aaa, bbb, ref ccc, ddd, eee, X[3], 11);
            HHH(ref eee, aaa, ref bbb, ccc, ddd, X[7], 8);
            HHH(ref ddd, eee, ref aaa, bbb, ccc, X[14], 6);
            HHH(ref ccc, ddd, ref eee, aaa, bbb, X[6], 6);
            HHH(ref bbb, ccc, ref ddd, eee, aaa, X[9], 14);
            HHH(ref aaa, bbb, ref ccc, ddd, eee, X[11], 12);
            HHH(ref eee, aaa, ref bbb, ccc, ddd, X[8], 13);
            HHH(ref ddd, eee, ref aaa, bbb, ccc, X[12], 5);
            HHH(ref ccc, ddd, ref eee, aaa, bbb, X[2], 14);
            HHH(ref bbb, ccc, ref ddd, eee, aaa, X[10], 13);
            HHH(ref aaa, bbb, ref ccc, ddd, eee, X[0], 13);
            HHH(ref eee, aaa, ref bbb, ccc, ddd, X[4], 7);
            HHH(ref ddd, eee, ref aaa, bbb, ccc, X[13], 5);

            // parallel round 4
            GGG(ref ccc, ddd, ref eee, aaa, bbb, X[8], 15);
            GGG(ref bbb, ccc, ref ddd, eee, aaa, X[6], 5);
            GGG(ref aaa, bbb, ref ccc, ddd, eee, X[4], 8);
            GGG(ref eee, aaa, ref bbb, ccc, ddd, X[1], 11);
            GGG(ref ddd, eee, ref aaa, bbb, ccc, X[3], 14);
            GGG(ref ccc, ddd, ref eee, aaa, bbb, X[11], 14);
            GGG(ref bbb, ccc, ref ddd, eee, aaa, X[15], 6);
            GGG(ref aaa, bbb, ref ccc, ddd, eee, X[0], 14);
            GGG(ref eee, aaa, ref bbb, ccc, ddd, X[5], 6);
            GGG(ref ddd, eee, ref aaa, bbb, ccc, X[12], 9);
            GGG(ref ccc, ddd, ref eee, aaa, bbb, X[2], 12);
            GGG(ref bbb, ccc, ref ddd, eee, aaa, X[13], 9);
            GGG(ref aaa, bbb, ref ccc, ddd, eee, X[9], 12);
            GGG(ref eee, aaa, ref bbb, ccc, ddd, X[7], 5);
            GGG(ref ddd, eee, ref aaa, bbb, ccc, X[10], 15);
            GGG(ref ccc, ddd, ref eee, aaa, bbb, X[14], 8);

            // parallel round 5
            FFF(ref bbb, ccc, ref ddd, eee, aaa, X[12], 8);
            FFF(ref aaa, bbb, ref ccc, ddd, eee, X[15], 5);
            FFF(ref eee, aaa, ref bbb, ccc, ddd, X[10], 12);
            FFF(ref ddd, eee, ref aaa, bbb, ccc, X[4], 9);
            FFF(ref ccc, ddd, ref eee, aaa, bbb, X[1], 12);
            FFF(ref bbb, ccc, ref ddd, eee, aaa, X[5], 5);
            FFF(ref aaa, bbb, ref ccc, ddd, eee, X[8], 14);
            FFF(ref eee, aaa, ref bbb, ccc, ddd, X[7], 6);
            FFF(ref ddd, eee, ref aaa, bbb, ccc, X[6], 8);
            FFF(ref ccc, ddd, ref eee, aaa, bbb, X[2], 13);
            FFF(ref bbb, ccc, ref ddd, eee, aaa, X[13], 6);
            FFF(ref aaa, bbb, ref ccc, ddd, eee, X[14], 5);
            FFF(ref eee, aaa, ref bbb, ccc, ddd, X[0], 15);
            FFF(ref ddd, eee, ref aaa, bbb, ccc, X[3], 13);
            FFF(ref ccc, ddd, ref eee, aaa, bbb, X[9], 11);
            FFF(ref bbb, ccc, ref ddd, eee, aaa, X[11], 11);

            // combine results
            ddd += cc + MDbuf[1];

            // final result for MDbuf[0]
            MDbuf[1] = MDbuf[2] + dd + eee;
            MDbuf[2] = MDbuf[3] + ee + aaa;
            MDbuf[3] = MDbuf[4] + aa + bbb;
            MDbuf[4] = MDbuf[0] + bb + ccc;
            MDbuf[0] = ddd;
        }

        /// <summary>
        ///  puts bytes from block into X and pad out; appends length
        ///  and finally, compresses the last block(s)
        ///  note: length in bits == 8 * (lswlen + 2^32 mswlen).
        ///  note: there are(lswlen mod 64) bytes left in strptr.
        /// </summary>
        /// <param name="MDbuf"></param>
        /// <param name="block"></param>
        /// <param name="lswlen"></param>
        /// <param name="mswlen"></param>
        public static void Finish(ref WordVec5 MDbuf, ref ByteVec64 block, int lswlen, int mswlen)
        {
            WordVec16 X = new();

            // put bytes from strptr into X
            for (uint i = 0, offset = 0; i < (lswlen & 63); i++)
            {
                // byte i goes into word X[i div 4] at pos. 8*(i mod 4)
                X[i >> 2] ^= (uint)block[offset++] << (8 * ((int)i & 3));
            }

            // append the bit m_n == 1
            X[((uint)lswlen >> 2) & 15] ^= (uint)1 << (8 * (lswlen & 3) + 7);

            if ((lswlen & 63) > 55)
            {
                // length goes to next block
                Compress(ref MDbuf, X);
                X.Reset();
            }

            // append length in bits
            X[14] = (uint) lswlen << 3;
            X[15] = ((uint)lswlen >> 29) | ((uint)mswlen << 3);
            Compress(ref MDbuf, X);
        }
    }
}

