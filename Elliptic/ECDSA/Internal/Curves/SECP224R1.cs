using Wheel.Crypto.Elliptic.EllipticCommon.VeryLongInt;

namespace Wheel.Crypto.Elliptic.ECDSA
{
    /// <summary>
    /// SECP224R1 specific implementations.
    /// NOTE: These methods are declared static on purpose, it allows us to use their addresses in the curve constructor functions.
    /// </summary>
    public readonly partial struct ECCurve
    {
        /// <summary>
        /// Construct a new instance of the secp224r1 context.
        /// <returns></returns>
        public static unsafe ECCurve Get_SECP224R1()
        {
            return new ECCurve(
                224,
                stackalloc ulong[] { 0x0000000000000001, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF },
                stackalloc ulong[] { 0x13DD29455C5C2A3D, 0xFFFF16A2E0B8F03E, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF },
                stackalloc ulong[] { 0x09ee94a2ae2e151e, 0xffff8b51705c781f, 0xffffffffffffffff, 0x7fffffff },
                stackalloc ulong[] { 0x343280D6115C1D21, 0x4A03C1D356C21122, 0x6BB4BF7F321390B9, 0xB70E0CBD, 0x44D5819985007E34, 0xCD4375A05A074764, 0xB5F723FB4C22DFE6, 0xBD376388 },
                stackalloc ulong[] { 0x270B39432355FFB4, 0x5044B0B7D7BFD8BA, 0x0C04B3ABF5413256, 0xB4050A85 },
                &MMod_SECP224R1,
                &XSide_Generic,
                &ModSQRT_SECP224R1,
                &DoubleJacobian_Generic
            );
        }

        /// <summary>
        /// Compute a = sqrt(a) (mod curve_p)
        /// </summary>
        /// <param name="a"></param>
        private static void ModSQRT_SECP224R1(in ECCurve curve, Span<ulong> a)
        {
            Span<ulong> e1 = stackalloc ulong[curve.NUM_WORDS];
            Span<ulong> f1 = stackalloc ulong[curve.NUM_WORDS];
            Span<ulong> d0 = stackalloc ulong[curve.NUM_WORDS];
            Span<ulong> e0 = stackalloc ulong[curve.NUM_WORDS];
            Span<ulong> f0 = stackalloc ulong[curve.NUM_WORDS];
            Span<ulong> d1 = stackalloc ulong[curve.NUM_WORDS];

            // s = a; using constant instead of random value
            mod_sqrt_secp224r1_rp(curve, d0, e0, f0, a, a);           // RP (d0, e0, f0, c, s)
            mod_sqrt_secp224r1_rs(curve, d1, e1, f1, d0, e0, f0);     // RS (d1, e1, f1, d0, e0, f0)
            for (int i = 1; i <= 95; i++)
            {
                VLI.Set(d0, d1, curve.NUM_WORDS);          // d0 <-- d1
                VLI.Set(e0, e1, curve.NUM_WORDS);          // e0 <-- e1
                VLI.Set(f0, f1, curve.NUM_WORDS);          // f0 <-- f1
                mod_sqrt_secp224r1_rs(curve, d1, e1, f1, d0, e0, f0); // RS (d1, e1, f1, d0, e0, f0)
                if (VLI.IsZero(d1, curve.NUM_WORDS))
                {     // if d1 == 0
                    break;
                }
            }
            VLI.ModInv(f1, e0, curve.P, curve.NUM_WORDS); // f1 <-- 1 / e0
            curve.ModMult(a, d0, f1);              // a  <-- d0 / e0
        }

        /// <summary>
        /// Computes result = product % p
        /// </summary>
        private static void MMod_SECP224R1(in ECCurve curve, Span<ulong> result, Span<ulong> product)
        {
            Span<ulong> tmp = stackalloc ulong[curve.NUM_WORDS];
            int carry = 0;

            // t
            VLI.Set(result, product, curve.NUM_WORDS);
            result[curve.NUM_WORDS - 1] &= 0xffffffff;

            // s1
            tmp[0] = 0;
            tmp[1] = product[3] & 0xffffffff00000000;
            tmp[2] = product[4];
            tmp[3] = product[5] & 0xffffffff;
            VLI.Add(result, result, tmp, curve.NUM_WORDS);

            // s2
            tmp[1] = product[5] & 0xffffffff00000000;
            tmp[2] = product[6];
            tmp[3] = 0;
            VLI.Add(result, result, tmp, curve.NUM_WORDS);

            // d1
            tmp[0] = (product[3] >> 32) | (product[4] << 32);
            tmp[1] = (product[4] >> 32) | (product[5] << 32);
            tmp[2] = (product[5] >> 32) | (product[6] << 32);
            tmp[3] = product[6] >> 32;
            carry -= (int)VLI.Sub(result, result, tmp, curve.NUM_WORDS);

            // d2
            tmp[0] = (product[5] >> 32) | (product[6] << 32);
            tmp[1] = product[6] >> 32;
            tmp[2] = tmp[3] = 0;
            carry -= (int)VLI.Sub(result, result, tmp, curve.NUM_WORDS);

            if (carry < 0)
            {
                do
                {
                    carry += (int)VLI.Add(result, result, curve.P, curve.NUM_WORDS);
                } while (carry < 0);
            }
            else
            {
                while (VLI.VarTimeCmp(curve.P, result, curve.NUM_WORDS) != 1)
                {
                    VLI.Sub(result, result, curve.P, curve.NUM_WORDS);
                }
            }
        }

        /// <summary>
        /// Routine 3.2.4 RS;  from http://www.nsa.gov/ia/_files/nist-routines.pdf
        /// </summary>
        private static void mod_sqrt_secp224r1_rs(in ECCurve curve, Span<ulong> d1, Span<ulong> e1, Span<ulong> f1, ReadOnlySpan<ulong> d0, ReadOnlySpan<ulong> e0, ReadOnlySpan<ulong> f0) {
            Span<ulong> t = stackalloc ulong[curve.NUM_WORDS];

            curve.ModSquare(t, d0);                               // t <-- d0 ^ 2
            curve.ModMult(e1, d0, e0);                            // e1 <-- d0 * e0
            VLI.ModAdd(d1, t, f0, curve.P, curve.NUM_WORDS);  // d1 <-- t  + f0
            VLI.ModAdd(e1, e1, e1, curve.P, curve.NUM_WORDS); // e1 <-- e1 + e1
            curve.ModMult(f1, t, f0);                             // f1 <-- t  * f0
            VLI.ModAdd(f1, f1, f1, curve.P, curve.NUM_WORDS); // f1 <-- f1 + f1
            VLI.ModAdd(f1, f1, f1, curve.P, curve.NUM_WORDS); // f1 <-- f1 + f1
        }

        /// <summary>
        /// Routine 3.2.5 RSS;  from http://www.nsa.gov/ia/_files/nist-routines.pdf
        /// </summary>
        private static void mod_sqrt_secp224r1_rss(in ECCurve curve, Span<ulong> d1, Span<ulong> e1, Span<ulong> f1, ReadOnlySpan<ulong> d0, ReadOnlySpan<ulong> e0, ReadOnlySpan<ulong> f0, int j)
        {
            VLI.Set(d1, d0, curve.NUM_WORDS); // d1 <-- d0
            VLI.Set(e1, e0, curve.NUM_WORDS); // e1 <-- e0
            VLI.Set(f1, f0, curve.NUM_WORDS); // f1 <-- f0
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
            Span<ulong> t1 = stackalloc ulong[curve.NUM_WORDS];
            Span<ulong> t2 = stackalloc ulong[curve.NUM_WORDS];

            curve.ModMult(t1, e0, e1); // t1 <-- e0 * e1
            curve.ModMult(t1, t1, c);  // t1 <-- t1 * c
            // t1 <-- p  - t1
            VLI.ModSub(t1, curve.P, t1, curve.P, curve.NUM_WORDS);
            curve.ModMult(t2, d0, d1);                            // t2 <-- d0 * d1
            VLI.ModAdd(t2, t2, t1, curve.P, curve.NUM_WORDS); // t2 <-- t2 + t1
            curve.ModMult(t1, d0, e1);                            // t1 <-- d0 * e1
            curve.ModMult(e2, d1, e0);                            // e2 <-- d1 * e0
            VLI.ModAdd(e2, e2, t1, curve.P, curve.NUM_WORDS); // e2 <-- e2 + t1
            curve.ModSquare(f2, e2);                              // f2 <-- e2^2
            curve.ModMult(f2, f2, c);                             // f2 <-- f2 * c
            // f2 <-- p  - f2
            VLI.ModSub(f2, curve.P, f2, curve.P, curve.NUM_WORDS);
            VLI.Set(d2, t2, curve.NUM_WORDS);           // d2 <-- t2
        }

        /// <summary>
        /// Routine 3.2.7 RP;  from http://www.nsa.gov/ia/_files/nist-routines.pdf
        /// </summary>
        private static void mod_sqrt_secp224r1_rp(in ECCurve curve, Span<ulong> d1, Span<ulong> e1, Span<ulong> f1, ReadOnlySpan<ulong> c, ReadOnlySpan<ulong> r)
        {
            Span<ulong> d0 = stackalloc ulong[curve.NUM_WORDS];
            Span<ulong> e0 = stackalloc ulong[curve.NUM_WORDS];
            e0[0] = 1; // e0 <-- 1
            Span<ulong> f0 = stackalloc ulong[curve.NUM_WORDS];

            VLI.Set(d0, r, curve.NUM_WORDS); // d0 <-- r
            // f0 <-- p  - c
            VLI.ModSub(f0, curve.P, c, curve.P, curve.NUM_WORDS);
            for (int i = 0, pow2i = 1; i <= 6; i++)
            {
                mod_sqrt_secp224r1_rss(curve, d1, e1, f1, d0, e0, f0, pow2i); // RSS (d1,e1,f1,d0,e0,f0,2^i)
                mod_sqrt_secp224r1_rm(curve, d1, e1, f1, c, d1, e1, d0, e0);  // RM (d1,e1,f1,c,d1,e1,d0,e0)
                VLI.Set(d0, d1, curve.NUM_WORDS);                  // d0 <-- d1
                VLI.Set(e0, e1, curve.NUM_WORDS);                  // e0 <-- e1
                VLI.Set(f0, f1, curve.NUM_WORDS);                  // f0 <-- f1
                pow2i *= 2;
            }
        }

    }
}

