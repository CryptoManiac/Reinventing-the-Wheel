using Wheel.Crypto.Elliptic.EllipticCommon.VeryLongInt;

namespace Wheel.Crypto.Elliptic.ECDSA
{
    /// <summary>
    /// SECP256K1 specific implementations.
    /// NOTE: These methods are declared static on purpose, it allows us to use their addresses in the curve constructor functions.
    /// </summary>
    public readonly partial struct ECCurve
    {
        /// <summary>
        /// Construct a new instance of the secp256r1 context.
        /// <returns></returns>
        public static unsafe ECCurve Get_SECP256R1()
        {
            return new ECCurve(
                256,
                stackalloc ulong[] { 0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF, 0x0000000000000000, 0xFFFFFFFF00000001 },
                stackalloc ulong[] { 0xF3B9CAC2FC632551, 0xBCE6FAADA7179E84, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF00000000 },
                stackalloc ulong[] { 0x79dce5617e3192a8, 0xde737d56d38bcf42, 0x7fffffff80000000, 0x7fffffff80000000 },
                stackalloc ulong[] { 0xF4A13945D898C296, 0x77037D812DEB33A0, 0xF8BCE6E563A440F2, 0x6B17D1F2E12C4247, 0xCBB6406837BF51F5, 0x2BCE33576B315ECE, 0x8EE7EB4A7C0F9E16, 0x4FE342E2FE1A7F9B },
                stackalloc ulong[] { 0x3BCE3C3E27D2604B, 0x651D06B0CC53B0F6, 0xB3EBBD55769886BC, 0x5AC635D8AA3A93E7 },
                &MMod_SECP256R1,
                &XSide_Generic,
                &ModSQRT_Generic,
                &DoubleJacobian_Generic
            );
        }

        /// <summary>
        /// Computes result = product % p
        /// </summary>
        private static void MMod_SECP256R1(in ECCurve curve, Span<ulong> result, Span<ulong> product)
        {
            Span<ulong> tmp = stackalloc ulong[curve.NUM_WORDS];

            // t
            VLI.Set(result, product, curve.NUM_WORDS);

            // s1
            tmp[0] = 0;
            tmp[1] = product[5] & 0xffffffff00000000;
            tmp[2] = product[6];
            tmp[3] = product[7];
            int carry = (int)VLI.Add(tmp, tmp, tmp, curve.NUM_WORDS);
            carry += (int)VLI.Add(result, result, tmp, curve.NUM_WORDS);

            // s2
            tmp[1] = product[6] << 32;
            tmp[2] = (product[6] >> 32) | (product[7] << 32);
            tmp[3] = product[7] >> 32;
            carry += (int)VLI.Add(tmp, tmp, tmp, curve.NUM_WORDS);
            carry += (int)VLI.Add(result, result, tmp, curve.NUM_WORDS);

            // s3
            tmp[0] = product[4];
            tmp[1] = product[5] & 0xffffffff;
            tmp[2] = 0;
            tmp[3] = product[7];
            carry += (int)VLI.Add(result, result, tmp, curve.NUM_WORDS);

            // s4
            tmp[0] = (product[4] >> 32) | (product[5] << 32);
            tmp[1] = (product[5] >> 32) | (product[6] & 0xffffffff00000000);
            tmp[2] = product[7];
            tmp[3] = (product[6] >> 32) | (product[4] << 32);
            carry += (int)VLI.Add(result, result, tmp, curve.NUM_WORDS);

            // d1 
            tmp[0] = (product[5] >> 32) | (product[6] << 32);
            tmp[1] = (product[6] >> 32);
            tmp[2] = 0;
            tmp[3] = (product[4] & 0xffffffff) | (product[5] << 32);
            carry -= (int)VLI.Sub(result, result, tmp, curve.NUM_WORDS);

            // d2 
            tmp[0] = product[6];
            tmp[1] = product[7];
            tmp[2] = 0;
            tmp[3] = (product[4] >> 32) | (product[5] & 0xffffffff00000000);
            carry -= (int)VLI.Sub(result, result, tmp, curve.NUM_WORDS);

            // d3 
            tmp[0] = (product[6] >> 32) | (product[7] << 32);
            tmp[1] = (product[7] >> 32) | (product[4] << 32);
            tmp[2] = (product[4] >> 32) | (product[5] << 32);
            tmp[3] = (product[6] << 32);
            carry -= (int)VLI.Sub(result, result, tmp, curve.NUM_WORDS);

            // d4 
            tmp[0] = product[7];
            tmp[1] = product[4] & 0xffffffff00000000;
            tmp[2] = product[5];
            tmp[3] = product[6] & 0xffffffff00000000;
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
                while (Convert.ToBoolean(carry) || VLI.VarTimeCmp(curve.P, result, curve.NUM_WORDS) != 1)
                {
                    carry -= (int)VLI.Sub(result, result, curve.P, curve.NUM_WORDS);
                }
            }
        }
    }
}

