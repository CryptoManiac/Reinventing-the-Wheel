using Wheel.Crypto.Elliptic.EllipticCommon.VeryLongInt;

namespace Wheel.Crypto.Elliptic.ECDSA
{
    /// <summary>
    /// SECP224R1 specific implementations
    /// </summary>
    public readonly partial struct ECCurve
    {
        /// <summary>
        /// Compute a = sqrt(a) (mod curve_p)
        /// </summary>
        /// <param name="a"></param>
        public static void ModSQRT_SECP224R1(in ECCurve curve, Span<ulong> a)
        {
            int num_words = curve.NUM_WORDS;
            Span<ulong> e1 = stackalloc ulong[num_words];
            Span<ulong> f1 = stackalloc ulong[num_words];
            Span<ulong> d0 = stackalloc ulong[num_words];
            Span<ulong> e0 = stackalloc ulong[num_words];
            Span<ulong> f0 = stackalloc ulong[num_words];
            Span<ulong> d1 = stackalloc ulong[num_words];

            // s = a; using constant instead of random value
            mod_sqrt_secp224r1_rp(curve, d0, e0, f0, a, a);           // RP (d0, e0, f0, c, s)
            mod_sqrt_secp224r1_rs(curve, d1, e1, f1, d0, e0, f0);     // RS (d1, e1, f1, d0, e0, f0)
            for (int i = 1; i <= 95; i++)
            {
                VLI.Set(d0, d1, num_words);          // d0 <-- d1
                VLI.Set(e0, e1, num_words);          // e0 <-- e1
                VLI.Set(f0, f1, num_words);          // f0 <-- f1
                mod_sqrt_secp224r1_rs(curve, d1, e1, f1, d0, e0, f0); // RS (d1, e1, f1, d0, e0, f0)
                if (VLI.IsZero(d1, num_words))
                {     // if d1 == 0
                    break;
                }
            }
            VLI.ModInv(f1, e0, curve.p, num_words); // f1 <-- 1 / e0
            curve.ModMult(a, d0, f1);              // a  <-- d0 / e0
        }

        /// <summary>
        /// Computes result = product % p
        /// </summary>
        public static void MMod_SECP224R1(in ECCurve curve, Span<ulong> result, Span<ulong> product)
        {
            int num_words = curve.NUM_WORDS;
            ReadOnlySpan<ulong> p = curve.p;
            Span<ulong> tmp = stackalloc ulong[num_words];
            int carry = 0;

            // t
            VLI.Set(result, product, num_words);
            result[num_words - 1] &= 0xffffffff;

            // s1
            tmp[0] = 0;
            tmp[1] = product[3] & 0xffffffff00000000;
            tmp[2] = product[4];
            tmp[3] = product[5] & 0xffffffff;
            VLI.Add(result, result, tmp, num_words);

            // s2
            tmp[1] = product[5] & 0xffffffff00000000;
            tmp[2] = product[6];
            tmp[3] = 0;
            VLI.Add(result, result, tmp, num_words);

            // d1
            tmp[0] = (product[3] >> 32) | (product[4] << 32);
            tmp[1] = (product[4] >> 32) | (product[5] << 32);
            tmp[2] = (product[5] >> 32) | (product[6] << 32);
            tmp[3] = product[6] >> 32;
            carry -= (int)VLI.Sub(result, result, tmp, num_words);

            // d2
            tmp[0] = (product[5] >> 32) | (product[6] << 32);
            tmp[1] = product[6] >> 32;
            tmp[2] = tmp[3] = 0;
            carry -= (int)VLI.Sub(result, result, tmp, num_words);

            if (carry < 0)
            {
                do
                {
                    carry += (int)VLI.Add(result, result, p, num_words);
                } while (carry < 0);
            }
            else
            {
                while (VLI.VarTimeCmp(p, result, num_words) != 1)
                {
                    VLI.Sub(result, result, p, num_words);
                }
            }
        }

        /// <summary>
        /// Routine 3.2.4 RS;  from http://www.nsa.gov/ia/_files/nist-routines.pdf
        /// </summary>
        private static void mod_sqrt_secp224r1_rs(in ECCurve curve, Span<ulong> d1, Span<ulong> e1, Span<ulong> f1, ReadOnlySpan<ulong> d0, ReadOnlySpan<ulong> e0, ReadOnlySpan<ulong> f0) {
            int num_words = curve.NUM_WORDS;
            Span<ulong> t = stackalloc ulong[num_words];
            ReadOnlySpan<ulong> p = curve.p;

            curve.ModSquare(t, d0);                               // t <-- d0 ^ 2
            curve.ModMult(e1, d0, e0);                            // e1 <-- d0 * e0
            VLI.ModAdd(d1, t, f0, p, num_words);  // d1 <-- t  + f0
            VLI.ModAdd(e1, e1, e1, p, num_words); // e1 <-- e1 + e1
            curve.ModMult(f1, t, f0);                             // f1 <-- t  * f0
            VLI.ModAdd(f1, f1, f1, p, num_words); // f1 <-- f1 + f1
            VLI.ModAdd(f1, f1, f1, p, num_words); // f1 <-- f1 + f1
        }

        /// <summary>
        /// Routine 3.2.5 RSS;  from http://www.nsa.gov/ia/_files/nist-routines.pdf
        /// </summary>
        private static void mod_sqrt_secp224r1_rss(in ECCurve curve, Span<ulong> d1, Span<ulong> e1, Span<ulong> f1, ReadOnlySpan<ulong> d0, ReadOnlySpan<ulong> e0, ReadOnlySpan<ulong> f0, int j)
        {
            int num_words = curve.NUM_WORDS;
            VLI.Set(d1, d0, num_words); // d1 <-- d0
            VLI.Set(e1, e0, num_words); // e1 <-- e0
            VLI.Set(f1, f0, num_words); // f1 <-- f0
            for (int i = 1; i <= j; ++i)
            {
                mod_sqrt_secp224r1_rs(curve, d1, e1, f1, d1, e1, f1); // RS (d1,e1,f1,d1,e1,f1)
            }
        }

        /// <summary>
        /// Routine 3.2.6 RM;  from http://www.nsa.gov/ia/_files/nist-routines.pdf
        /// </summary>
        private static void mod_sqrt_secp224r1_rm(in ECCurve curve, Span<ulong> d2, Span<ulong> e2, Span<ulong> f2, ReadOnlySpan<ulong> c, ReadOnlySpan<ulong> d0, ReadOnlySpan<ulong> e0, ReadOnlySpan<ulong> d1, ReadOnlySpan<ulong> e1)
        {
            int num_words = curve.NUM_WORDS;
            Span<ulong> t1 = stackalloc ulong[num_words];
            Span<ulong> t2 = stackalloc ulong[num_words];
            ReadOnlySpan<ulong> p = curve.p;

            curve.ModMult(t1, e0, e1); // t1 <-- e0 * e1
            curve.ModMult(t1, t1, c);  // t1 <-- t1 * c
            // t1 <-- p  - t1
            VLI.ModSub(t1, p, t1, p, num_words);
            curve.ModMult(t2, d0, d1);                            // t2 <-- d0 * d1
            VLI.ModAdd(t2, t2, t1, p, num_words); // t2 <-- t2 + t1
            curve.ModMult(t1, d0, e1);                            // t1 <-- d0 * e1
            curve.ModMult(e2, d1, e0);                            // e2 <-- d1 * e0
            VLI.ModAdd(e2, e2, t1, p, num_words); // e2 <-- e2 + t1
            curve.ModSquare(f2, e2);                              // f2 <-- e2^2
            curve.ModMult(f2, f2, c);                             // f2 <-- f2 * c
            // f2 <-- p  - f2
            VLI.ModSub(f2, p, f2, p, num_words);
            VLI.Set(d2, t2, num_words);           // d2 <-- t2
        }

        /// <summary>
        /// Routine 3.2.7 RP;  from http://www.nsa.gov/ia/_files/nist-routines.pdf
        /// </summary>
        private static void mod_sqrt_secp224r1_rp(in ECCurve curve, Span<ulong> d1, Span<ulong> e1, Span<ulong> f1, ReadOnlySpan<ulong> c, ReadOnlySpan<ulong> r)
        {
            int num_words = curve.NUM_WORDS;
            ReadOnlySpan<ulong> p = curve.p;
            Span<ulong> d0 = stackalloc ulong[num_words];
            Span<ulong> e0 = stackalloc ulong[num_words];
            e0[0] = 1; // e0 <-- 1
            Span<ulong> f0 = stackalloc ulong[num_words];

            VLI.Set(d0, r, num_words); // d0 <-- r
            // f0 <-- p  - c
            VLI.ModSub(f0, p, c, p, num_words);
            for (int i = 0, pow2i = 1; i <= 6; i++)
            {
                mod_sqrt_secp224r1_rss(curve, d1, e1, f1, d0, e0, f0, pow2i); // RSS (d1,e1,f1,d0,e0,f0,2^i)
                mod_sqrt_secp224r1_rm(curve, d1, e1, f1, c, d1, e1, d0, e0);  // RM (d1,e1,f1,c,d1,e1,d0,e0)
                VLI.Set(d0, d1, num_words);                  // d0 <-- d1
                VLI.Set(e0, e1, num_words);                  // e0 <-- e1
                VLI.Set(f0, f1, num_words);                  // f0 <-- f1
                pow2i *= 2;
            }
        }

    }
}

