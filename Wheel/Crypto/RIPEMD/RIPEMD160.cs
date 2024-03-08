using System;
using System.Runtime.CompilerServices;
using Wheel.Crypto.Primitives;
using Wheel.Crypto.Primitives.ByteVectors;
using Wheel.Crypto.Primitives.WordVectors;

namespace Wheel.Crypto.RIPEMD
{
	public class RIPEMD160 : IHasherInterface
	{
        private uint bytesLo, bytesHi;
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
                key.Write(input, i);
                return;
            }

            // Distance from the beginning
            // of the input array
            int offset = 0;

            if (i > 0)
            {
                // First chunk is an odd size
                key.Write(input.AsSpan(offset, 64 - (int)i), i);
                RIPEMD160Misc.Compress(ref iv, key.wv16);
                offset += 64 - (int)i;
                len -= 64 - i;
            }

            while (len >= 64)
            {
                // Process data in 64-byte chunks
                key.Write(input.AsSpan(offset, 64), i);
                RIPEMD160Misc.Compress(ref iv, key.wv16);
                offset += 64;
                len -= 64;
            }

            if (len > 0)
            {
                // Handle any remaining bytes of data.
                key.Write(input.AsSpan(offset, (int)len), 0);
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
        static void FF(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s)
        {
            a += F(b, c, d) + x;
            a = ROL(a, s) + e;
            c = ROL(c, 10);
        }

        static void GG(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s)
        {
            a += G(b, c, d) + x + 0x5a827999;
            a = ROL(a, s) + e;
            c = ROL(c, 10);
        }

        static void HH(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s)
        {
            a += H(b, c, d) + x + 0x6ed9eba1;
            a = ROL(a, s) + e;
            c = ROL(c, 10);
        }

        static void II(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s)
        {
            a += I(b, c, d) + x + 0x8f1bbcdc;
            a = ROL(a, s) + e;
            c = ROL(c, 10);
        }

        static void JJ(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s)
        {
            a += J(b, c, d) + x + 0xa953fd4e;
            a = ROL(a, s) + e;
            c = ROL(c, 10);
        }

        static void FFF(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s)
        {
            a += F(b, c, d) + x;
            a = ROL(a, s) + e;
            c = ROL(c, 10);
        }

        static void GGG(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s)
        {
            a += G(b, c, d) + x + 0x7a6d76e9;
            a = ROL(a, s) + e;
            c = ROL(c, 10);
        }

        static void HHH(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s)
        {
            a += H(b, c, d) + x + 0x6d703ef3;
            a = ROL(a, s) + e;
            c = ROL(c, 10);
        }

        static void III(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s)
        {
            a += I(b, c, d) + x + 0x5c4dd124;
            a = ROL(a, s) + e;
            c = ROL(c, 10);
        }

        static void JJJ(ref uint a, uint b, ref uint c, uint d, uint e, uint x, int s)
        {
            a += J(b, c, d) + x + 0x50a28be6;
            a = ROL(a, s) + e;
            c = ROL(c, 10);
        }

        /// <summary>
        /// First part of compression function
        /// </summary>
        /// <returns>(AA, BB, CC, DD, EE)</returns>
        private static Tuple<uint, uint, uint, uint, uint> Compress_I(WordVec5 MDbuf, WordVec16 X)
        {
            uint aa = MDbuf.w00;
            uint bb = MDbuf.w01;
            uint cc = MDbuf.w02;
            uint dd = MDbuf.w03;
            uint ee = MDbuf.w04;

            // round 1
            FF(ref aa, bb, ref cc, dd, ee, X.w00, 11);
            FF(ref ee, aa, ref bb, cc, dd, X.w01, 14);
            FF(ref dd, ee, ref aa, bb, cc, X.w02, 15);
            FF(ref cc, dd, ref ee, aa, bb, X.w03, 12);
            FF(ref bb, cc, ref dd, ee, aa, X.w04, 5);
            FF(ref aa, bb, ref cc, dd, ee, X.w05, 8);
            FF(ref ee, aa, ref bb, cc, dd, X.w06, 7);
            FF(ref dd, ee, ref aa, bb, cc, X.w07, 9);
            FF(ref cc, dd, ref ee, aa, bb, X.w08, 11);
            FF(ref bb, cc, ref dd, ee, aa, X.w09, 13);
            FF(ref aa, bb, ref cc, dd, ee, X.w10, 14);
            FF(ref ee, aa, ref bb, cc, dd, X.w11, 15);
            FF(ref dd, ee, ref aa, bb, cc, X.w12, 6);
            FF(ref cc, dd, ref ee, aa, bb, X.w13, 7);
            FF(ref bb, cc, ref dd, ee, aa, X.w14, 9);
            FF(ref aa, bb, ref cc, dd, ee, X.w15, 8);

            // round 2
            GG(ref ee, aa, ref bb, cc, dd, X.w07, 7);
            GG(ref dd, ee, ref aa, bb, cc, X.w04, 6);
            GG(ref cc, dd, ref ee, aa, bb, X.w13, 8);
            GG(ref bb, cc, ref dd, ee, aa, X.w01, 13);
            GG(ref aa, bb, ref cc, dd, ee, X.w10, 11);
            GG(ref ee, aa, ref bb, cc, dd, X.w06, 9);
            GG(ref dd, ee, ref aa, bb, cc, X.w15, 7);
            GG(ref cc, dd, ref ee, aa, bb, X.w03, 15);
            GG(ref bb, cc, ref dd, ee, aa, X.w12, 7);
            GG(ref aa, bb, ref cc, dd, ee, X.w00, 12);
            GG(ref ee, aa, ref bb, cc, dd, X.w09, 15);
            GG(ref dd, ee, ref aa, bb, cc, X.w05, 9);
            GG(ref cc, dd, ref ee, aa, bb, X.w02, 11);
            GG(ref bb, cc, ref dd, ee, aa, X.w14, 7);
            GG(ref aa, bb, ref cc, dd, ee, X.w11, 13);
            GG(ref ee, aa, ref bb, cc, dd, X.w08, 12);

            // round 3
            HH(ref dd, ee, ref aa, bb, cc, X.w03, 11);
            HH(ref cc, dd, ref ee, aa, bb, X.w10, 13);
            HH(ref bb, cc, ref dd, ee, aa, X.w14, 6);
            HH(ref aa, bb, ref cc, dd, ee, X.w04, 7);
            HH(ref ee, aa, ref bb, cc, dd, X.w09, 14);
            HH(ref dd, ee, ref aa, bb, cc, X.w15, 9);
            HH(ref cc, dd, ref ee, aa, bb, X.w08, 13);
            HH(ref bb, cc, ref dd, ee, aa, X.w01, 15);
            HH(ref aa, bb, ref cc, dd, ee, X.w02, 14);
            HH(ref ee, aa, ref bb, cc, dd, X.w07, 8);
            HH(ref dd, ee, ref aa, bb, cc, X.w00, 13);
            HH(ref cc, dd, ref ee, aa, bb, X.w06, 6);
            HH(ref bb, cc, ref dd, ee, aa, X.w13, 5);
            HH(ref aa, bb, ref cc, dd, ee, X.w11, 12);
            HH(ref ee, aa, ref bb, cc, dd, X.w05, 7);
            HH(ref dd, ee, ref aa, bb, cc, X.w12, 5);

            // round 4
            II(ref cc, dd, ref ee, aa, bb, X.w01, 11);
            II(ref bb, cc, ref dd, ee, aa, X.w09, 12);
            II(ref aa, bb, ref cc, dd, ee, X.w11, 14);
            II(ref ee, aa, ref bb, cc, dd, X.w10, 15);
            II(ref dd, ee, ref aa, bb, cc, X.w00, 14);
            II(ref cc, dd, ref ee, aa, bb, X.w08, 15);
            II(ref bb, cc, ref dd, ee, aa, X.w12, 9);
            II(ref aa, bb, ref cc, dd, ee, X.w04, 8);
            II(ref ee, aa, ref bb, cc, dd, X.w13, 9);
            II(ref dd, ee, ref aa, bb, cc, X.w03, 14);
            II(ref cc, dd, ref ee, aa, bb, X.w07, 5);
            II(ref bb, cc, ref dd, ee, aa, X.w15, 6);
            II(ref aa, bb, ref cc, dd, ee, X.w14, 8);
            II(ref ee, aa, ref bb, cc, dd, X.w05, 6);
            II(ref dd, ee, ref aa, bb, cc, X.w06, 5);
            II(ref cc, dd, ref ee, aa, bb, X.w02, 12);

            // round 5
            JJ(ref bb, cc, ref dd, ee, aa, X.w04, 9);
            JJ(ref aa, bb, ref cc, dd, ee, X.w00, 15);
            JJ(ref ee, aa, ref bb, cc, dd, X.w05, 5);
            JJ(ref dd, ee, ref aa, bb, cc, X.w09, 11);
            JJ(ref cc, dd, ref ee, aa, bb, X.w07, 6);
            JJ(ref bb, cc, ref dd, ee, aa, X.w12, 8);
            JJ(ref aa, bb, ref cc, dd, ee, X.w02, 13);
            JJ(ref ee, aa, ref bb, cc, dd, X.w10, 12);
            JJ(ref dd, ee, ref aa, bb, cc, X.w14, 5);
            JJ(ref cc, dd, ref ee, aa, bb, X.w01, 12);
            JJ(ref bb, cc, ref dd, ee, aa, X.w03, 13);
            JJ(ref aa, bb, ref cc, dd, ee, X.w08, 14);
            JJ(ref ee, aa, ref bb, cc, dd, X.w11, 11);
            JJ(ref dd, ee, ref aa, bb, cc, X.w06, 8);
            JJ(ref cc, dd, ref ee, aa, bb, X.w15, 5);
            JJ(ref bb, cc, ref dd, ee, aa, X.w13, 6);

            return new(aa, bb, cc, dd, ee);
        }

        /// <summary>
        /// First part of compression function
        /// </summary>
        /// <returns>(AAA, BBB, CCC, DDD, EEE)</returns>
        private static Tuple<uint, uint, uint, uint, uint> Compress_II(WordVec5 MDbuf, WordVec16 X)
        {
            uint aaa = MDbuf.w00;
            uint bbb = MDbuf.w01;
            uint ccc = MDbuf.w02;
            uint ddd = MDbuf.w03;
            uint eee = MDbuf.w04;

            // parallel round 1
            JJJ(ref aaa, bbb, ref ccc, ddd, eee, X.w05, 8);
            JJJ(ref eee, aaa, ref bbb, ccc, ddd, X.w14, 9);
            JJJ(ref ddd, eee, ref aaa, bbb, ccc, X.w07, 9);
            JJJ(ref ccc, ddd, ref eee, aaa, bbb, X.w00, 11);
            JJJ(ref bbb, ccc, ref ddd, eee, aaa, X.w09, 13);
            JJJ(ref aaa, bbb, ref ccc, ddd, eee, X.w02, 15);
            JJJ(ref eee, aaa, ref bbb, ccc, ddd, X.w11, 15);
            JJJ(ref ddd, eee, ref aaa, bbb, ccc, X.w04, 5);
            JJJ(ref ccc, ddd, ref eee, aaa, bbb, X.w13, 7);
            JJJ(ref bbb, ccc, ref ddd, eee, aaa, X.w06, 7);
            JJJ(ref aaa, bbb, ref ccc, ddd, eee, X.w15, 8);
            JJJ(ref eee, aaa, ref bbb, ccc, ddd, X.w08, 11);
            JJJ(ref ddd, eee, ref aaa, bbb, ccc, X.w01, 14);
            JJJ(ref ccc, ddd, ref eee, aaa, bbb, X.w10, 14);
            JJJ(ref bbb, ccc, ref ddd, eee, aaa, X.w03, 12);
            JJJ(ref aaa, bbb, ref ccc, ddd, eee, X.w12, 6);

            // parallel round 2
            III(ref eee, aaa, ref bbb, ccc, ddd, X.w06, 9);
            III(ref ddd, eee, ref aaa, bbb, ccc, X.w11, 13);
            III(ref ccc, ddd, ref eee, aaa, bbb, X.w03, 15);
            III(ref bbb, ccc, ref ddd, eee, aaa, X.w07, 7);
            III(ref aaa, bbb, ref ccc, ddd, eee, X.w00, 12);
            III(ref eee, aaa, ref bbb, ccc, ddd, X.w13, 8);
            III(ref ddd, eee, ref aaa, bbb, ccc, X.w05, 9);
            III(ref ccc, ddd, ref eee, aaa, bbb, X.w10, 11);
            III(ref bbb, ccc, ref ddd, eee, aaa, X.w14, 7);
            III(ref aaa, bbb, ref ccc, ddd, eee, X.w15, 7);
            III(ref eee, aaa, ref bbb, ccc, ddd, X.w08, 12);
            III(ref ddd, eee, ref aaa, bbb, ccc, X.w12, 7);
            III(ref ccc, ddd, ref eee, aaa, bbb, X.w04, 6);
            III(ref bbb, ccc, ref ddd, eee, aaa, X.w09, 15);
            III(ref aaa, bbb, ref ccc, ddd, eee, X.w01, 13);
            III(ref eee, aaa, ref bbb, ccc, ddd, X.w02, 11);

            // parallel round 3
            HHH(ref ddd, eee, ref aaa, bbb, ccc, X.w15, 9);
            HHH(ref ccc, ddd, ref eee, aaa, bbb, X.w05, 7);
            HHH(ref bbb, ccc, ref ddd, eee, aaa, X.w01, 15);
            HHH(ref aaa, bbb, ref ccc, ddd, eee, X.w03, 11);
            HHH(ref eee, aaa, ref bbb, ccc, ddd, X.w07, 8);
            HHH(ref ddd, eee, ref aaa, bbb, ccc, X.w14, 6);
            HHH(ref ccc, ddd, ref eee, aaa, bbb, X.w06, 6);
            HHH(ref bbb, ccc, ref ddd, eee, aaa, X.w09, 14);
            HHH(ref aaa, bbb, ref ccc, ddd, eee, X.w11, 12);
            HHH(ref eee, aaa, ref bbb, ccc, ddd, X.w08, 13);
            HHH(ref ddd, eee, ref aaa, bbb, ccc, X.w12, 5);
            HHH(ref ccc, ddd, ref eee, aaa, bbb, X.w02, 14);
            HHH(ref bbb, ccc, ref ddd, eee, aaa, X.w10, 13);
            HHH(ref aaa, bbb, ref ccc, ddd, eee, X.w00, 13);
            HHH(ref eee, aaa, ref bbb, ccc, ddd, X.w04, 7);
            HHH(ref ddd, eee, ref aaa, bbb, ccc, X.w13, 5);

            // parallel round 4
            GGG(ref ccc, ddd, ref eee, aaa, bbb, X.w08, 15);
            GGG(ref bbb, ccc, ref ddd, eee, aaa, X.w06, 5);
            GGG(ref aaa, bbb, ref ccc, ddd, eee, X.w04, 8);
            GGG(ref eee, aaa, ref bbb, ccc, ddd, X.w01, 11);
            GGG(ref ddd, eee, ref aaa, bbb, ccc, X.w03, 14);
            GGG(ref ccc, ddd, ref eee, aaa, bbb, X.w11, 14);
            GGG(ref bbb, ccc, ref ddd, eee, aaa, X.w15, 6);
            GGG(ref aaa, bbb, ref ccc, ddd, eee, X.w00, 14);
            GGG(ref eee, aaa, ref bbb, ccc, ddd, X.w05, 6);
            GGG(ref ddd, eee, ref aaa, bbb, ccc, X.w12, 9);
            GGG(ref ccc, ddd, ref eee, aaa, bbb, X.w02, 12);
            GGG(ref bbb, ccc, ref ddd, eee, aaa, X.w13, 9);
            GGG(ref aaa, bbb, ref ccc, ddd, eee, X.w09, 12);
            GGG(ref eee, aaa, ref bbb, ccc, ddd, X.w07, 5);
            GGG(ref ddd, eee, ref aaa, bbb, ccc, X.w10, 15);
            GGG(ref ccc, ddd, ref eee, aaa, bbb, X.w14, 8);

            // parallel round 5
            FFF(ref bbb, ccc, ref ddd, eee, aaa, X.w12, 8);
            FFF(ref aaa, bbb, ref ccc, ddd, eee, X.w15, 5);
            FFF(ref eee, aaa, ref bbb, ccc, ddd, X.w10, 12);
            FFF(ref ddd, eee, ref aaa, bbb, ccc, X.w04, 9);
            FFF(ref ccc, ddd, ref eee, aaa, bbb, X.w01, 12);
            FFF(ref bbb, ccc, ref ddd, eee, aaa, X.w05, 5);
            FFF(ref aaa, bbb, ref ccc, ddd, eee, X.w08, 14);
            FFF(ref eee, aaa, ref bbb, ccc, ddd, X.w07, 6);
            FFF(ref ddd, eee, ref aaa, bbb, ccc, X.w06, 8);
            FFF(ref ccc, ddd, ref eee, aaa, bbb, X.w02, 13);
            FFF(ref bbb, ccc, ref ddd, eee, aaa, X.w13, 6);
            FFF(ref aaa, bbb, ref ccc, ddd, eee, X.w14, 5);
            FFF(ref eee, aaa, ref bbb, ccc, ddd, X.w00, 15);
            FFF(ref ddd, eee, ref aaa, bbb, ccc, X.w03, 13);
            FFF(ref ccc, ddd, ref eee, aaa, bbb, X.w09, 11);
            FFF(ref bbb, ccc, ref ddd, eee, aaa, X.w11, 11);

            return new(aaa, bbb, ccc, ddd, eee);
        }

        /// <summary>
        /// The compression function.
        /// Transforms MDbuf using message bytes X[0] through X[15]
        /// </summary>
        public static void Compress(ref WordVec5 MDbuf, in WordVec16 X)
        {
            var (aa, bb, cc, dd, ee) = Compress_I(MDbuf, X);
            var (aaa, bbb, ccc, ddd, eee) = Compress_II(MDbuf, X);

            // combine results
            ddd += cc + MDbuf.w01;

            // final result for MDbuf[0]
            MDbuf.w01 = MDbuf.w02 + dd + eee;
            MDbuf.w02 = MDbuf.w03 + ee + aaa;
            MDbuf.w03 = MDbuf.w04 + aa + bbb;
            MDbuf.w04 = MDbuf.w00 + bb + ccc;
            MDbuf.w00 = ddd;
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
        public static void Finish(ref WordVec5 MDbuf, ref ByteVec64 block, uint lswlen, uint mswlen)
        {
            WordVec16 X = new();

            // put bytes from strptr into X
            for (uint i = 0, offset = 0; i < (lswlen & 63); i++)
            {
                // byte i goes into word X[i div 4] at pos. 8*(i mod 4)
                X[i >> 2] ^= (uint)block[offset++] << (8 * ((int)i & 3));
            }

            // append the bit m_n == 1
            X[(lswlen >> 2) & 15] ^= (uint)1 << (8 * ((int)lswlen & 3) + 7);

            if ((lswlen & 63) > 55)
            {
                // length goes to next block
                Compress(ref MDbuf, X);
                X.Reset();
            }

            // append length in bits
            X.w14 = lswlen << 3;
            X.w15 = (lswlen >> 29) | (mswlen << 3);
            Compress(ref MDbuf, X);
        }
    }
}

