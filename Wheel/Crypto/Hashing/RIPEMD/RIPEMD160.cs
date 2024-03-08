using Wheel.Crypto.Primitives.ByteVectors;
using Wheel.Crypto.Primitives.WordVectors;

namespace Wheel.Crypto.Hashing.RIPEMD
{
	public class RIPEMD160 : IHasher
	{
        private uint bytesLo, bytesHi;
        private ByteVec20 iv = new();
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
            RIPEMD160Misc.Finish(ref iv.wv5, ref key, bytesLo, bytesHi);
            iv.Store(digest);
            Reset(); // In case it's sensitive
        }

        public void Reset()
        {
            bytesLo = 0;
            bytesHi = 0;
            iv.wv5.SetWords(RIPEMD160Misc.ripemd_init_state);
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
                RIPEMD160Misc.Compress(ref iv.wv5, key.wv16);
                offset += 64 - (int)i;
                len -= 64 - i;
            }

            while (len >= 64)
            {
                // Process data in 64-byte chunks
                key.Write(input.AsSpan(offset, 64), i);
                RIPEMD160Misc.Compress(ref iv.wv5, key.wv16);
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
        private static void Compress_I(ref WordVec5 st, in WordVec16 X)
        {
            // Copies of key and state
            // for quicker lookup
            uint X0 = X.w00;
            uint X1 = X.w01;
            uint X2 = X.w02;
            uint X3 = X.w03;
            uint X4 = X.w04;
            uint X5 = X.w05;
            uint X6 = X.w06;
            uint X7 = X.w07;
            uint X8 = X.w08;
            uint X9 = X.w09;
            uint X10 = X.w10;
            uint X11 = X.w11;
            uint X12 = X.w12;
            uint X13 = X.w13;
            uint X14 = X.w14;
            uint X15 = X.w15;
            uint aa = st.w00;
            uint bb = st.w01;
            uint cc = st.w02;
            uint dd = st.w03;
            uint ee = st.w04;

            // round 1
            FF(ref aa, bb, ref cc, dd, ee, X0, 11);
            FF(ref ee, aa, ref bb, cc, dd, X1, 14);
            FF(ref dd, ee, ref aa, bb, cc, X2, 15);
            FF(ref cc, dd, ref ee, aa, bb, X3, 12);
            FF(ref bb, cc, ref dd, ee, aa, X4, 5);
            FF(ref aa, bb, ref cc, dd, ee, X5, 8);
            FF(ref ee, aa, ref bb, cc, dd, X6, 7);
            FF(ref dd, ee, ref aa, bb, cc, X7, 9);
            FF(ref cc, dd, ref ee, aa, bb, X8, 11);
            FF(ref bb, cc, ref dd, ee, aa, X9, 13);
            FF(ref aa, bb, ref cc, dd, ee, X10, 14);
            FF(ref ee, aa, ref bb, cc, dd, X11, 15);
            FF(ref dd, ee, ref aa, bb, cc, X12, 6);
            FF(ref cc, dd, ref ee, aa, bb, X13, 7);
            FF(ref bb, cc, ref dd, ee, aa, X14, 9);
            FF(ref aa, bb, ref cc, dd, ee, X15, 8);

            // round 2
            GG(ref ee, aa, ref bb, cc, dd, X7, 7);
            GG(ref dd, ee, ref aa, bb, cc, X4, 6);
            GG(ref cc, dd, ref ee, aa, bb, X13, 8);
            GG(ref bb, cc, ref dd, ee, aa, X1, 13);
            GG(ref aa, bb, ref cc, dd, ee, X10, 11);
            GG(ref ee, aa, ref bb, cc, dd, X6, 9);
            GG(ref dd, ee, ref aa, bb, cc, X15, 7);
            GG(ref cc, dd, ref ee, aa, bb, X3, 15);
            GG(ref bb, cc, ref dd, ee, aa, X12, 7);
            GG(ref aa, bb, ref cc, dd, ee, X0, 12);
            GG(ref ee, aa, ref bb, cc, dd, X9, 15);
            GG(ref dd, ee, ref aa, bb, cc, X5, 9);
            GG(ref cc, dd, ref ee, aa, bb, X2, 11);
            GG(ref bb, cc, ref dd, ee, aa, X14, 7);
            GG(ref aa, bb, ref cc, dd, ee, X11, 13);
            GG(ref ee, aa, ref bb, cc, dd, X8, 12);

            // round 3
            HH(ref dd, ee, ref aa, bb, cc, X3, 11);
            HH(ref cc, dd, ref ee, aa, bb, X10, 13);
            HH(ref bb, cc, ref dd, ee, aa, X14, 6);
            HH(ref aa, bb, ref cc, dd, ee, X4, 7);
            HH(ref ee, aa, ref bb, cc, dd, X9, 14);
            HH(ref dd, ee, ref aa, bb, cc, X15, 9);
            HH(ref cc, dd, ref ee, aa, bb, X8, 13);
            HH(ref bb, cc, ref dd, ee, aa, X1, 15);
            HH(ref aa, bb, ref cc, dd, ee, X2, 14);
            HH(ref ee, aa, ref bb, cc, dd, X7, 8);
            HH(ref dd, ee, ref aa, bb, cc, X0, 13);
            HH(ref cc, dd, ref ee, aa, bb, X6, 6);
            HH(ref bb, cc, ref dd, ee, aa, X13, 5);
            HH(ref aa, bb, ref cc, dd, ee, X11, 12);
            HH(ref ee, aa, ref bb, cc, dd, X5, 7);
            HH(ref dd, ee, ref aa, bb, cc, X12, 5);

            // round 4
            II(ref cc, dd, ref ee, aa, bb, X1, 11);
            II(ref bb, cc, ref dd, ee, aa, X9, 12);
            II(ref aa, bb, ref cc, dd, ee, X11, 14);
            II(ref ee, aa, ref bb, cc, dd, X10, 15);
            II(ref dd, ee, ref aa, bb, cc, X0, 14);
            II(ref cc, dd, ref ee, aa, bb, X8, 15);
            II(ref bb, cc, ref dd, ee, aa, X12, 9);
            II(ref aa, bb, ref cc, dd, ee, X4, 8);
            II(ref ee, aa, ref bb, cc, dd, X13, 9);
            II(ref dd, ee, ref aa, bb, cc, X3, 14);
            II(ref cc, dd, ref ee, aa, bb, X7, 5);
            II(ref bb, cc, ref dd, ee, aa, X15, 6);
            II(ref aa, bb, ref cc, dd, ee, X14, 8);
            II(ref ee, aa, ref bb, cc, dd, X5, 6);
            II(ref dd, ee, ref aa, bb, cc, X6, 5);
            II(ref cc, dd, ref ee, aa, bb, X2, 12);

            // round 5
            JJ(ref bb, cc, ref dd, ee, aa, X4, 9);
            JJ(ref aa, bb, ref cc, dd, ee, X0, 15);
            JJ(ref ee, aa, ref bb, cc, dd, X5, 5);
            JJ(ref dd, ee, ref aa, bb, cc, X9, 11);
            JJ(ref cc, dd, ref ee, aa, bb, X7, 6);
            JJ(ref bb, cc, ref dd, ee, aa, X12, 8);
            JJ(ref aa, bb, ref cc, dd, ee, X2, 13);
            JJ(ref ee, aa, ref bb, cc, dd, X10, 12);
            JJ(ref dd, ee, ref aa, bb, cc, X14, 5);
            JJ(ref cc, dd, ref ee, aa, bb, X1, 12);
            JJ(ref bb, cc, ref dd, ee, aa, X3, 13);
            JJ(ref aa, bb, ref cc, dd, ee, X8, 14);
            JJ(ref ee, aa, ref bb, cc, dd, X11, 11);
            JJ(ref dd, ee, ref aa, bb, cc, X6, 8);
            JJ(ref cc, dd, ref ee, aa, bb, X15, 5);
            JJ(ref bb, cc, ref dd, ee, aa, X13, 6);

            // Results
            st.w00 = aa;
            st.w01 = bb;
            st.w02 = cc;
            st.w03 = dd;
            st.w04 = ee;
        }

        /// <summary>
        /// Second part of compression function
        /// </summary>
        private static void Compress_II(ref WordVec5 st, in WordVec16 X)
        {
            // Copies of key and state
            // for quicker lookup
            uint X0 = X.w00;
            uint X1 = X.w01;
            uint X2 = X.w02;
            uint X3 = X.w03;
            uint X4 = X.w04;
            uint X5 = X.w05;
            uint X6 = X.w06;
            uint X7 = X.w07;
            uint X8 = X.w08;
            uint X9 = X.w09;
            uint X10 = X.w10;
            uint X11 = X.w11;
            uint X12 = X.w12;
            uint X13 = X.w13;
            uint X14 = X.w14;
            uint X15 = X.w15;

            uint aaa = st.w00;
            uint bbb = st.w01;
            uint ccc = st.w02;
            uint ddd = st.w03;
            uint eee = st.w04;

            // parallel round 1
            JJJ(ref aaa, bbb, ref ccc, ddd, eee, X5, 8);
            JJJ(ref eee, aaa, ref bbb, ccc, ddd, X14, 9);
            JJJ(ref ddd, eee, ref aaa, bbb, ccc, X7, 9);
            JJJ(ref ccc, ddd, ref eee, aaa, bbb, X0, 11);
            JJJ(ref bbb, ccc, ref ddd, eee, aaa, X9, 13);
            JJJ(ref aaa, bbb, ref ccc, ddd, eee, X2, 15);
            JJJ(ref eee, aaa, ref bbb, ccc, ddd, X11, 15);
            JJJ(ref ddd, eee, ref aaa, bbb, ccc, X4, 5);
            JJJ(ref ccc, ddd, ref eee, aaa, bbb, X13, 7);
            JJJ(ref bbb, ccc, ref ddd, eee, aaa, X6, 7);
            JJJ(ref aaa, bbb, ref ccc, ddd, eee, X15, 8);
            JJJ(ref eee, aaa, ref bbb, ccc, ddd, X8, 11);
            JJJ(ref ddd, eee, ref aaa, bbb, ccc, X1, 14);
            JJJ(ref ccc, ddd, ref eee, aaa, bbb, X10, 14);
            JJJ(ref bbb, ccc, ref ddd, eee, aaa, X3, 12);
            JJJ(ref aaa, bbb, ref ccc, ddd, eee, X12, 6);

            // parallel round 2
            III(ref eee, aaa, ref bbb, ccc, ddd, X6, 9);
            III(ref ddd, eee, ref aaa, bbb, ccc, X11, 13);
            III(ref ccc, ddd, ref eee, aaa, bbb, X3, 15);
            III(ref bbb, ccc, ref ddd, eee, aaa, X7, 7);
            III(ref aaa, bbb, ref ccc, ddd, eee, X0, 12);
            III(ref eee, aaa, ref bbb, ccc, ddd, X13, 8);
            III(ref ddd, eee, ref aaa, bbb, ccc, X5, 9);
            III(ref ccc, ddd, ref eee, aaa, bbb, X10, 11);
            III(ref bbb, ccc, ref ddd, eee, aaa, X14, 7);
            III(ref aaa, bbb, ref ccc, ddd, eee, X15, 7);
            III(ref eee, aaa, ref bbb, ccc, ddd, X8, 12);
            III(ref ddd, eee, ref aaa, bbb, ccc, X12, 7);
            III(ref ccc, ddd, ref eee, aaa, bbb, X4, 6);
            III(ref bbb, ccc, ref ddd, eee, aaa, X9, 15);
            III(ref aaa, bbb, ref ccc, ddd, eee, X1, 13);
            III(ref eee, aaa, ref bbb, ccc, ddd, X2, 11);

            // parallel round 3
            HHH(ref ddd, eee, ref aaa, bbb, ccc, X15, 9);
            HHH(ref ccc, ddd, ref eee, aaa, bbb, X5, 7);
            HHH(ref bbb, ccc, ref ddd, eee, aaa, X1, 15);
            HHH(ref aaa, bbb, ref ccc, ddd, eee, X3, 11);
            HHH(ref eee, aaa, ref bbb, ccc, ddd, X7, 8);
            HHH(ref ddd, eee, ref aaa, bbb, ccc, X14, 6);
            HHH(ref ccc, ddd, ref eee, aaa, bbb, X6, 6);
            HHH(ref bbb, ccc, ref ddd, eee, aaa, X9, 14);
            HHH(ref aaa, bbb, ref ccc, ddd, eee, X11, 12);
            HHH(ref eee, aaa, ref bbb, ccc, ddd, X8, 13);
            HHH(ref ddd, eee, ref aaa, bbb, ccc, X12, 5);
            HHH(ref ccc, ddd, ref eee, aaa, bbb, X2, 14);
            HHH(ref bbb, ccc, ref ddd, eee, aaa, X10, 13);
            HHH(ref aaa, bbb, ref ccc, ddd, eee, X0, 13);
            HHH(ref eee, aaa, ref bbb, ccc, ddd, X4, 7);
            HHH(ref ddd, eee, ref aaa, bbb, ccc, X13, 5);

            // parallel round 4
            GGG(ref ccc, ddd, ref eee, aaa, bbb, X8, 15);
            GGG(ref bbb, ccc, ref ddd, eee, aaa, X6, 5);
            GGG(ref aaa, bbb, ref ccc, ddd, eee, X4, 8);
            GGG(ref eee, aaa, ref bbb, ccc, ddd, X1, 11);
            GGG(ref ddd, eee, ref aaa, bbb, ccc, X3, 14);
            GGG(ref ccc, ddd, ref eee, aaa, bbb, X11, 14);
            GGG(ref bbb, ccc, ref ddd, eee, aaa, X15, 6);
            GGG(ref aaa, bbb, ref ccc, ddd, eee, X0, 14);
            GGG(ref eee, aaa, ref bbb, ccc, ddd, X5, 6);
            GGG(ref ddd, eee, ref aaa, bbb, ccc, X12, 9);
            GGG(ref ccc, ddd, ref eee, aaa, bbb, X2, 12);
            GGG(ref bbb, ccc, ref ddd, eee, aaa, X13, 9);
            GGG(ref aaa, bbb, ref ccc, ddd, eee, X9, 12);
            GGG(ref eee, aaa, ref bbb, ccc, ddd, X7, 5);
            GGG(ref ddd, eee, ref aaa, bbb, ccc, X10, 15);
            GGG(ref ccc, ddd, ref eee, aaa, bbb, X14, 8);

            // parallel round 5
            FFF(ref bbb, ccc, ref ddd, eee, aaa, X12, 8);
            FFF(ref aaa, bbb, ref ccc, ddd, eee, X15, 5);
            FFF(ref eee, aaa, ref bbb, ccc, ddd, X10, 12);
            FFF(ref ddd, eee, ref aaa, bbb, ccc, X4, 9);
            FFF(ref ccc, ddd, ref eee, aaa, bbb, X1, 12);
            FFF(ref bbb, ccc, ref ddd, eee, aaa, X5, 5);
            FFF(ref aaa, bbb, ref ccc, ddd, eee, X8, 14);
            FFF(ref eee, aaa, ref bbb, ccc, ddd, X7, 6);
            FFF(ref ddd, eee, ref aaa, bbb, ccc, X6, 8);
            FFF(ref ccc, ddd, ref eee, aaa, bbb, X2, 13);
            FFF(ref bbb, ccc, ref ddd, eee, aaa, X13, 6);
            FFF(ref aaa, bbb, ref ccc, ddd, eee, X14, 5);
            FFF(ref eee, aaa, ref bbb, ccc, ddd, X0, 15);
            FFF(ref ddd, eee, ref aaa, bbb, ccc, X3, 13);
            FFF(ref ccc, ddd, ref eee, aaa, bbb, X9, 11);
            FFF(ref bbb, ccc, ref ddd, eee, aaa, X11, 11);

            // Results
            st.w00 = aaa;
            st.w01 = bbb;
            st.w02 = ccc;
            st.w03 = ddd;
            st.w04 = eee;
        }

        /// <summary>
        /// The compression function.
        /// Transforms MDbuf using message bytes X[0] through X[15]
        /// </summary>
        public static void Compress(ref WordVec5 MDbuf, in WordVec16 X)
        {
            WordVec5 s1 = MDbuf;
            WordVec5 s2 = MDbuf;

            Compress_I(ref s1, X);
            Compress_II(ref s2, X);

            // combine results
            s2.w03 += s1.w02 + MDbuf.w01;

            // final result for MDbuf[0]
            MDbuf.w01 = MDbuf.w02 + s1.w03 + s2.w04;
            MDbuf.w02 = MDbuf.w03 + s1.w04 + s2.w00;
            MDbuf.w03 = MDbuf.w04 + s1.w00 + s2.w01;
            MDbuf.w04 = MDbuf.w00 + s1.w01 + s2.w02;
            MDbuf.w00 = s2.w03;
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

