using Wheel.Crypto.Elliptic.EllipticCommon.VeryLongInt;

namespace Wheel.Crypto.Elliptic.ECDSA
{
    /// <summary>
    /// SECP384R1 specific constants and implementations.
    /// NOTE: These methods are declared static on purpose, it allows us to use their addresses in the curve constructor functions.
    /// </summary>
    public readonly partial struct ECCurve
    {
        /// <summary>
        /// Construct a new instance of the secp521r1 context.
        /// <returns></returns>
        public static unsafe ECCurve Get_SECP521R1()
        {
            return new ECCurve(
                521,
                stackalloc ulong[] {
                    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                    0x000001FF },
                stackalloc ulong[] {
                    0xBB6FB71E91386409, 0x3BB5C9B8899C47AE, 0x7FCC0148F709A5D0, 0x51868783BF2F966B,
                    0xFFFFFFFFFFFFFFFA, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                    0x000001FF },
                stackalloc ulong[] {
                    0x5db7db8f489c3204, 0x1ddae4dc44ce23d7, 0xbfe600a47b84d2e8, 0x28c343c1df97cb35,
                    0xfffffffffffffffd, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
                    0x00000ff
                },
                stackalloc ulong[] {
                    0xF97E7E31C2E5BD66, 0x3348B3C1856A429B, 0xFE1DC127A2FFA8DE, 0xA14B5E77EFE75928,
                    0xF828AF606B4D3DBA, 0x9C648139053FB521, 0x9E3ECB662395B442, 0x858E06B70404E9CD,
                    0x000000C6,
                    0x88BE94769FD16650, 0x353C7086A272C240, 0xC550B9013FAD0761, 0x97EE72995EF42640,
                    0x17AFBD17273E662C, 0x98F54449579B4468, 0x5C8A5FB42C7D1BD9, 0x39296A789A3BC004,
                    0x00000118
                },
                stackalloc ulong[] {
                    0xEF451FD46B503F00, 0x3573DF883D2C34F1, 0x1652C0BD3BB1BF07, 0x56193951EC7E937B,
                    0xB8B489918EF109E1, 0xA2DA725B99B315F3, 0x929A21A0B68540EE, 0x953EB9618E1C9A1F,
                    0x00000051
                },
                &MMod_SECP521R1,
                &XSide_Generic,
                &ModSQRT_Generic,
                &DoubleJacobian_Generic
            );
        }

        /// <summary>
        /// Computes result = product % p
        /// </summary>
        public static void MMod_SECP521R1(in ECCurve curve, Span<ulong> result, Span<ulong> product)
        {
            Span<ulong> tmp = stackalloc ulong[curve.NUM_WORDS];

            // t
            VLI.Set(result, product, curve.NUM_WORDS);
            result[curve.NUM_WORDS - 1] &= 0x01FF;

            // s
            for (int i = 0; i < curve.NUM_WORDS - 1; ++i)
            {
                tmp[i] = (product[curve.NUM_WORDS - 1 + i] >> 9) | (product[curve.NUM_WORDS + i] << 55);
            }
            tmp[curve.NUM_WORDS - 1] = product[2 * curve.NUM_WORDS - 2] >> 9;

            int carry = (int)VLI.Add(result, result, tmp, curve.NUM_WORDS);

            while (Convert.ToBoolean(carry) || VLI.VarTimeCmp(curve.P, result, curve.NUM_WORDS) != 1)
            {
                carry -= (int)VLI.Sub(result, result, curve.P, curve.NUM_WORDS);
            }
        }
    }
}

