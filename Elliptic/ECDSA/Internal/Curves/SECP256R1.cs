using Wheel.Crypto.Elliptic.EllipticCommon.VeryLongInt;

namespace Wheel.Crypto.Elliptic.ECDSA
{
    /// <summary>
    /// SECP256K1 specific implementations
    /// </summary>
    public readonly partial struct ECCurve
    {
        /// <summary>
        /// Computes result = product % p
        /// </summary>
        public static void MMod_SECP256R1(in ECCurve curve, Span<ulong> result, Span<ulong> product)
        {
            int num_words = curve.NUM_WORDS;
            ReadOnlySpan<ulong> p = curve.p;
            Span<ulong> tmp = stackalloc ulong[num_words];

            // t
            VLI.Set(result, product, num_words);

            // s1
            tmp[0] = 0;
            tmp[1] = product[5] & 0xffffffff00000000;
            tmp[2] = product[6];
            tmp[3] = product[7];
            int carry = (int)VLI.Add(tmp, tmp, tmp, num_words);
            carry += (int)VLI.Add(result, result, tmp, num_words);

            // s2
            tmp[1] = product[6] << 32;
            tmp[2] = (product[6] >> 32) | (product[7] << 32);
            tmp[3] = product[7] >> 32;
            carry += (int)VLI.Add(tmp, tmp, tmp, num_words);
            carry += (int)VLI.Add(result, result, tmp, num_words);

            // s3
            tmp[0] = product[4];
            tmp[1] = product[5] & 0xffffffff;
            tmp[2] = 0;
            tmp[3] = product[7];
            carry += (int)VLI.Add(result, result, tmp, num_words);

            // s4
            tmp[0] = (product[4] >> 32) | (product[5] << 32);
            tmp[1] = (product[5] >> 32) | (product[6] & 0xffffffff00000000);
            tmp[2] = product[7];
            tmp[3] = (product[6] >> 32) | (product[4] << 32);
            carry += (int)VLI.Add(result, result, tmp, num_words);

            // d1 
            tmp[0] = (product[5] >> 32) | (product[6] << 32);
            tmp[1] = (product[6] >> 32);
            tmp[2] = 0;
            tmp[3] = (product[4] & 0xffffffff) | (product[5] << 32);
            carry -= (int)VLI.Sub(result, result, tmp, num_words);

            // d2 
            tmp[0] = product[6];
            tmp[1] = product[7];
            tmp[2] = 0;
            tmp[3] = (product[4] >> 32) | (product[5] & 0xffffffff00000000);
            carry -= (int)VLI.Sub(result, result, tmp, num_words);

            // d3 
            tmp[0] = (product[6] >> 32) | (product[7] << 32);
            tmp[1] = (product[7] >> 32) | (product[4] << 32);
            tmp[2] = (product[4] >> 32) | (product[5] << 32);
            tmp[3] = (product[6] << 32);
            carry -= (int)VLI.Sub(result, result, tmp, num_words);

            // d4 
            tmp[0] = product[7];
            tmp[1] = product[4] & 0xffffffff00000000;
            tmp[2] = product[5];
            tmp[3] = product[6] & 0xffffffff00000000;
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
                while (Convert.ToBoolean(carry) || VLI.VarTimeCmp(p, result, num_words) != 1)
                {
                    carry -= (int)VLI.Sub(result, result, p, num_words);
                }
            }
        }
    }
}

