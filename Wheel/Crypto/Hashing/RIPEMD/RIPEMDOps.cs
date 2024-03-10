namespace Wheel.Crypto.Hashing.RIPEMD.Internal
{
	public static class InternalRIPEMDOps
	{
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
        private static void Compress_I(ref InternalRIPEMDState st, in InternalRIPEMDBlock X)
        {
            // Copies of key and state
            // for quicker lookup
            uint X0 = X.X00;
            uint X1 = X.X01;
            uint X2 = X.X02;
            uint X3 = X.X03;
            uint X4 = X.X04;
            uint X5 = X.X05;
            uint X6 = X.X06;
            uint X7 = X.X07;
            uint X8 = X.X08;
            uint X9 = X.X09;
            uint X10 = X.X10;
            uint X11 = X.X11;
            uint X12 = X.X12;
            uint X13 = X.X13;
            uint X14 = X.X14;
            uint X15 = X.X15;
            uint aa = st.X00;
            uint bb = st.X01;
            uint cc = st.X02;
            uint dd = st.X03;
            uint ee = st.X04;

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
            st.X00 = aa;
            st.X01 = bb;
            st.X02 = cc;
            st.X03 = dd;
            st.X04 = ee;
        }

        /// <summary>
        /// Second part of compression function
        /// </summary>
        private static void Compress_II(ref InternalRIPEMDState st, in InternalRIPEMDBlock X)
        {
            // Copies of key and state
            // for quicker lookup
            uint X0 = X.X00;
            uint X1 = X.X01;
            uint X2 = X.X02;
            uint X3 = X.X03;
            uint X4 = X.X04;
            uint X5 = X.X05;
            uint X6 = X.X06;
            uint X7 = X.X07;
            uint X8 = X.X08;
            uint X9 = X.X09;
            uint X10 = X.X10;
            uint X11 = X.X11;
            uint X12 = X.X12;
            uint X13 = X.X13;
            uint X14 = X.X14;
            uint X15 = X.X15;

            uint aaa = st.X00;
            uint bbb = st.X01;
            uint ccc = st.X02;
            uint ddd = st.X03;
            uint eee = st.X04;

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
            st.X00 = aaa;
            st.X01 = bbb;
            st.X02 = ccc;
            st.X03 = ddd;
            st.X04 = eee;
        }

        /// <summary>
        /// The compression function.
        /// Transforms MDbuf using message bytes X[0] through X[15]
        /// </summary>
        public static void Compress(ref InternalRIPEMDState MDbuf, in InternalRIPEMDBlock X)
        {
            InternalRIPEMDState s1 = MDbuf;
            InternalRIPEMDState s2 = MDbuf;

            Compress_I(ref s1, X);
            Compress_II(ref s2, X);

            // combine results
            s2.X03 += s1.X02 + MDbuf.X01;

            // final result for MDbuf[0]
            MDbuf.X01 = MDbuf.X02 + s1.X03 + s2.X04;
            MDbuf.X02 = MDbuf.X03 + s1.X04 + s2.X00;
            MDbuf.X03 = MDbuf.X04 + s1.X00 + s2.X01;
            MDbuf.X04 = MDbuf.X00 + s1.X01 + s2.X02;
            MDbuf.X00 = s2.X03;
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
        public static void Finish(ref InternalRIPEMDState MDbuf, ref InternalRIPEMDBlock block, uint lswlen, uint mswlen)
        {
            InternalRIPEMDBlock X = new();

            // put bytes from strptr into X
            for (uint i = 0, offset = 0; i < (lswlen & 63); i++)
            {
                // byte i goes into word X[i div 4] at pos. 8*(i mod 4)
                X[i >> 2] ^= (uint)block.bytes[offset++] << (8 * ((int)i & 3));
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
            X.X14 = lswlen << 3;
            X.X15 = (lswlen >> 29) | (mswlen << 3);
            Compress(ref MDbuf, X);
        }
    }
}

