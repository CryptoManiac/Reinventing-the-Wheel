namespace Wheel.Crypto.Hashing.RIPEMD.Internal
{
    internal static class InternalRIPEMDOps
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
        private static void Compress_I(ref InternalRIPEMDState state, in InternalRIPEMDBlock X)
        {
            uint aa = state.X00;
            uint bb = state.X01;
            uint cc = state.X02;
            uint dd = state.X03;
            uint ee = state.X04;

            // round 1
            FF(ref aa, bb, ref cc, dd, ee, X.X00, 11);
            FF(ref ee, aa, ref bb, cc, dd, X.X01, 14);
            FF(ref dd, ee, ref aa, bb, cc, X.X02, 15);
            FF(ref cc, dd, ref ee, aa, bb, X.X03, 12);
            FF(ref bb, cc, ref dd, ee, aa, X.X04, 5);
            FF(ref aa, bb, ref cc, dd, ee, X.X05, 8);
            FF(ref ee, aa, ref bb, cc, dd, X.X06, 7);
            FF(ref dd, ee, ref aa, bb, cc, X.X07, 9);
            FF(ref cc, dd, ref ee, aa, bb, X.X08, 11);
            FF(ref bb, cc, ref dd, ee, aa, X.X09, 13);
            FF(ref aa, bb, ref cc, dd, ee, X.X10, 14);
            FF(ref ee, aa, ref bb, cc, dd, X.X11, 15);
            FF(ref dd, ee, ref aa, bb, cc, X.X12, 6);
            FF(ref cc, dd, ref ee, aa, bb, X.X13, 7);
            FF(ref bb, cc, ref dd, ee, aa, X.X14, 9);
            FF(ref aa, bb, ref cc, dd, ee, X.X15, 8);

            // round 2
            GG(ref ee, aa, ref bb, cc, dd, X.X07, 7);
            GG(ref dd, ee, ref aa, bb, cc, X.X04, 6);
            GG(ref cc, dd, ref ee, aa, bb, X.X13, 8);
            GG(ref bb, cc, ref dd, ee, aa, X.X01, 13);
            GG(ref aa, bb, ref cc, dd, ee, X.X10, 11);
            GG(ref ee, aa, ref bb, cc, dd, X.X06, 9);
            GG(ref dd, ee, ref aa, bb, cc, X.X15, 7);
            GG(ref cc, dd, ref ee, aa, bb, X.X03, 15);
            GG(ref bb, cc, ref dd, ee, aa, X.X12, 7);
            GG(ref aa, bb, ref cc, dd, ee, X.X00, 12);
            GG(ref ee, aa, ref bb, cc, dd, X.X09, 15);
            GG(ref dd, ee, ref aa, bb, cc, X.X05, 9);
            GG(ref cc, dd, ref ee, aa, bb, X.X02, 11);
            GG(ref bb, cc, ref dd, ee, aa, X.X14, 7);
            GG(ref aa, bb, ref cc, dd, ee, X.X11, 13);
            GG(ref ee, aa, ref bb, cc, dd, X.X08, 12);

            // round 3
            HH(ref dd, ee, ref aa, bb, cc, X.X03, 11);
            HH(ref cc, dd, ref ee, aa, bb, X.X10, 13);
            HH(ref bb, cc, ref dd, ee, aa, X.X14, 6);
            HH(ref aa, bb, ref cc, dd, ee, X.X04, 7);
            HH(ref ee, aa, ref bb, cc, dd, X.X09, 14);
            HH(ref dd, ee, ref aa, bb, cc, X.X15, 9);
            HH(ref cc, dd, ref ee, aa, bb, X.X08, 13);
            HH(ref bb, cc, ref dd, ee, aa, X.X01, 15);
            HH(ref aa, bb, ref cc, dd, ee, X.X02, 14);
            HH(ref ee, aa, ref bb, cc, dd, X.X07, 8);
            HH(ref dd, ee, ref aa, bb, cc, X.X00, 13);
            HH(ref cc, dd, ref ee, aa, bb, X.X06, 6);
            HH(ref bb, cc, ref dd, ee, aa, X.X13, 5);
            HH(ref aa, bb, ref cc, dd, ee, X.X11, 12);
            HH(ref ee, aa, ref bb, cc, dd, X.X05, 7);
            HH(ref dd, ee, ref aa, bb, cc, X.X12, 5);

            // round 4
            II(ref cc, dd, ref ee, aa, bb, X.X01, 11);
            II(ref bb, cc, ref dd, ee, aa, X.X09, 12);
            II(ref aa, bb, ref cc, dd, ee, X.X11, 14);
            II(ref ee, aa, ref bb, cc, dd, X.X10, 15);
            II(ref dd, ee, ref aa, bb, cc, X.X00, 14);
            II(ref cc, dd, ref ee, aa, bb, X.X08, 15);
            II(ref bb, cc, ref dd, ee, aa, X.X12, 9);
            II(ref aa, bb, ref cc, dd, ee, X.X04, 8);
            II(ref ee, aa, ref bb, cc, dd, X.X13, 9);
            II(ref dd, ee, ref aa, bb, cc, X.X03, 14);
            II(ref cc, dd, ref ee, aa, bb, X.X07, 5);
            II(ref bb, cc, ref dd, ee, aa, X.X15, 6);
            II(ref aa, bb, ref cc, dd, ee, X.X14, 8);
            II(ref ee, aa, ref bb, cc, dd, X.X05, 6);
            II(ref dd, ee, ref aa, bb, cc, X.X06, 5);
            II(ref cc, dd, ref ee, aa, bb, X.X02, 12);

            // round 5
            JJ(ref bb, cc, ref dd, ee, aa, X.X04, 9);
            JJ(ref aa, bb, ref cc, dd, ee, X.X00, 15);
            JJ(ref ee, aa, ref bb, cc, dd, X.X05, 5);
            JJ(ref dd, ee, ref aa, bb, cc, X.X09, 11);
            JJ(ref cc, dd, ref ee, aa, bb, X.X07, 6);
            JJ(ref bb, cc, ref dd, ee, aa, X.X12, 8);
            JJ(ref aa, bb, ref cc, dd, ee, X.X02, 13);
            JJ(ref ee, aa, ref bb, cc, dd, X.X10, 12);
            JJ(ref dd, ee, ref aa, bb, cc, X.X14, 5);
            JJ(ref cc, dd, ref ee, aa, bb, X.X01, 12);
            JJ(ref bb, cc, ref dd, ee, aa, X.X03, 13);
            JJ(ref aa, bb, ref cc, dd, ee, X.X08, 14);
            JJ(ref ee, aa, ref bb, cc, dd, X.X11, 11);
            JJ(ref dd, ee, ref aa, bb, cc, X.X06, 8);
            JJ(ref cc, dd, ref ee, aa, bb, X.X15, 5);
            JJ(ref bb, cc, ref dd, ee, aa, X.X13, 6);

            // Results
            state.X00 = aa;
            state.X01 = bb;
            state.X02 = cc;
            state.X03 = dd;
            state.X04 = ee;
        }

        /// <summary>
        /// Second part of compression function
        /// </summary>
        private static void Compress_II(ref InternalRIPEMDState state, in InternalRIPEMDBlock X)
        {
            uint aaa = state.X00;
            uint bbb = state.X01;
            uint ccc = state.X02;
            uint ddd = state.X03;
            uint eee = state.X04;

            // parallel round 1
            JJJ(ref aaa, bbb, ref ccc, ddd, eee, X.X05, 8);
            JJJ(ref eee, aaa, ref bbb, ccc, ddd, X.X14, 9);
            JJJ(ref ddd, eee, ref aaa, bbb, ccc, X.X07, 9);
            JJJ(ref ccc, ddd, ref eee, aaa, bbb, X.X00, 11);
            JJJ(ref bbb, ccc, ref ddd, eee, aaa, X.X09, 13);
            JJJ(ref aaa, bbb, ref ccc, ddd, eee, X.X02, 15);
            JJJ(ref eee, aaa, ref bbb, ccc, ddd, X.X11, 15);
            JJJ(ref ddd, eee, ref aaa, bbb, ccc, X.X04, 5);
            JJJ(ref ccc, ddd, ref eee, aaa, bbb, X.X13, 7);
            JJJ(ref bbb, ccc, ref ddd, eee, aaa, X.X06, 7);
            JJJ(ref aaa, bbb, ref ccc, ddd, eee, X.X15, 8);
            JJJ(ref eee, aaa, ref bbb, ccc, ddd, X.X08, 11);
            JJJ(ref ddd, eee, ref aaa, bbb, ccc, X.X01, 14);
            JJJ(ref ccc, ddd, ref eee, aaa, bbb, X.X10, 14);
            JJJ(ref bbb, ccc, ref ddd, eee, aaa, X.X03, 12);
            JJJ(ref aaa, bbb, ref ccc, ddd, eee, X.X12, 6);

            // parallel round 2
            III(ref eee, aaa, ref bbb, ccc, ddd, X.X06, 9);
            III(ref ddd, eee, ref aaa, bbb, ccc, X.X11, 13);
            III(ref ccc, ddd, ref eee, aaa, bbb, X.X03, 15);
            III(ref bbb, ccc, ref ddd, eee, aaa, X.X07, 7);
            III(ref aaa, bbb, ref ccc, ddd, eee, X.X00, 12);
            III(ref eee, aaa, ref bbb, ccc, ddd, X.X13, 8);
            III(ref ddd, eee, ref aaa, bbb, ccc, X.X05, 9);
            III(ref ccc, ddd, ref eee, aaa, bbb, X.X10, 11);
            III(ref bbb, ccc, ref ddd, eee, aaa, X.X14, 7);
            III(ref aaa, bbb, ref ccc, ddd, eee, X.X15, 7);
            III(ref eee, aaa, ref bbb, ccc, ddd, X.X08, 12);
            III(ref ddd, eee, ref aaa, bbb, ccc, X.X12, 7);
            III(ref ccc, ddd, ref eee, aaa, bbb, X.X04, 6);
            III(ref bbb, ccc, ref ddd, eee, aaa, X.X09, 15);
            III(ref aaa, bbb, ref ccc, ddd, eee, X.X01, 13);
            III(ref eee, aaa, ref bbb, ccc, ddd, X.X02, 11);

            // parallel round 3
            HHH(ref ddd, eee, ref aaa, bbb, ccc, X.X15, 9);
            HHH(ref ccc, ddd, ref eee, aaa, bbb, X.X05, 7);
            HHH(ref bbb, ccc, ref ddd, eee, aaa, X.X01, 15);
            HHH(ref aaa, bbb, ref ccc, ddd, eee, X.X03, 11);
            HHH(ref eee, aaa, ref bbb, ccc, ddd, X.X07, 8);
            HHH(ref ddd, eee, ref aaa, bbb, ccc, X.X14, 6);
            HHH(ref ccc, ddd, ref eee, aaa, bbb, X.X06, 6);
            HHH(ref bbb, ccc, ref ddd, eee, aaa, X.X09, 14);
            HHH(ref aaa, bbb, ref ccc, ddd, eee, X.X11, 12);
            HHH(ref eee, aaa, ref bbb, ccc, ddd, X.X08, 13);
            HHH(ref ddd, eee, ref aaa, bbb, ccc, X.X12, 5);
            HHH(ref ccc, ddd, ref eee, aaa, bbb, X.X02, 14);
            HHH(ref bbb, ccc, ref ddd, eee, aaa, X.X10, 13);
            HHH(ref aaa, bbb, ref ccc, ddd, eee, X.X00, 13);
            HHH(ref eee, aaa, ref bbb, ccc, ddd, X.X04, 7);
            HHH(ref ddd, eee, ref aaa, bbb, ccc, X.X13, 5);

            // parallel round 4
            GGG(ref ccc, ddd, ref eee, aaa, bbb, X.X08, 15);
            GGG(ref bbb, ccc, ref ddd, eee, aaa, X.X06, 5);
            GGG(ref aaa, bbb, ref ccc, ddd, eee, X.X04, 8);
            GGG(ref eee, aaa, ref bbb, ccc, ddd, X.X01, 11);
            GGG(ref ddd, eee, ref aaa, bbb, ccc, X.X03, 14);
            GGG(ref ccc, ddd, ref eee, aaa, bbb, X.X11, 14);
            GGG(ref bbb, ccc, ref ddd, eee, aaa, X.X15, 6);
            GGG(ref aaa, bbb, ref ccc, ddd, eee, X.X00, 14);
            GGG(ref eee, aaa, ref bbb, ccc, ddd, X.X05, 6);
            GGG(ref ddd, eee, ref aaa, bbb, ccc, X.X12, 9);
            GGG(ref ccc, ddd, ref eee, aaa, bbb, X.X02, 12);
            GGG(ref bbb, ccc, ref ddd, eee, aaa, X.X13, 9);
            GGG(ref aaa, bbb, ref ccc, ddd, eee, X.X09, 12);
            GGG(ref eee, aaa, ref bbb, ccc, ddd, X.X07, 5);
            GGG(ref ddd, eee, ref aaa, bbb, ccc, X.X10, 15);
            GGG(ref ccc, ddd, ref eee, aaa, bbb, X.X14, 8);

            // parallel round 5
            FFF(ref bbb, ccc, ref ddd, eee, aaa, X.X12, 8);
            FFF(ref aaa, bbb, ref ccc, ddd, eee, X.X15, 5);
            FFF(ref eee, aaa, ref bbb, ccc, ddd, X.X10, 12);
            FFF(ref ddd, eee, ref aaa, bbb, ccc, X.X04, 9);
            FFF(ref ccc, ddd, ref eee, aaa, bbb, X.X01, 12);
            FFF(ref bbb, ccc, ref ddd, eee, aaa, X.X05, 5);
            FFF(ref aaa, bbb, ref ccc, ddd, eee, X.X08, 14);
            FFF(ref eee, aaa, ref bbb, ccc, ddd, X.X07, 6);
            FFF(ref ddd, eee, ref aaa, bbb, ccc, X.X06, 8);
            FFF(ref ccc, ddd, ref eee, aaa, bbb, X.X02, 13);
            FFF(ref bbb, ccc, ref ddd, eee, aaa, X.X13, 6);
            FFF(ref aaa, bbb, ref ccc, ddd, eee, X.X14, 5);
            FFF(ref eee, aaa, ref bbb, ccc, ddd, X.X00, 15);
            FFF(ref ddd, eee, ref aaa, bbb, ccc, X.X03, 13);
            FFF(ref ccc, ddd, ref eee, aaa, bbb, X.X09, 11);
            FFF(ref bbb, ccc, ref ddd, eee, aaa, X.X11, 11);

            // Results
            state.X00 = aaa;
            state.X01 = bbb;
            state.X02 = ccc;
            state.X03 = ddd;
            state.X04 = eee;
        }

        /// <summary>
        /// The compression function.
        /// Transforms MDbuf using message bytes X[0] through X[15]
        /// </summary>
        public static void Compress(ref InternalRIPEMDState state, in InternalRIPEMDBlock X)
        {
            InternalRIPEMDState s1 = new(state);
            InternalRIPEMDState s2 = new(state);

            Compress_I(ref s1, X);
            Compress_II(ref s2, X);

            // combine results
            s2.X03 += s1.X02 + state.X01;

            // final result for MDbuf[0]
            state.X01 = state.X02 + s1.X03 + s2.X04;
            state.X02 = state.X03 + s1.X04 + s2.X00;
            state.X03 = state.X04 + s1.X00 + s2.X01;
            state.X04 = state.X00 + s1.X01 + s2.X02;
            state.X00 = s2.X03;
        }

        /// <summary>
        ///  puts bytes from block into X and pad out; appends length
        ///  and finally, compresses the last block(s)
        ///  note: length in bits == 8 * (lswlen + 2^32 mswlen).
        ///  note: there are(lswlen mod 64) bytes left in strptr.
        /// </summary>
        /// <param name="state"></param>
        /// <param name="block"></param>
        /// <param name="lswlen"></param>
        /// <param name="mswlen"></param>
        public static void Finish(ref InternalRIPEMDState state, ref InternalRIPEMDBlock block, uint lswlen, uint mswlen)
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
                Compress(ref state, X);
                X.Reset();
            }

            // append length in bits
            X.X14 = lswlen << 3;
            X.X15 = (lswlen >> 29) | (mswlen << 3);
            Compress(ref state, X);
        }
    }
}

