using Wheel.Crypto.Elliptic.EllipticCommon.VeryLongInt;

namespace Wheel.Crypto.Elliptic.ECDSA
{
    /// <summary>
    /// SECP192R1 specific implementations.
    /// NOTE: These methods are declared static on purpose, it allows us to use their addresses in the curve constructor functions.
    /// </summary>
    public readonly partial struct ECCurve
    {
        /// <summary>
        /// Construct a new instance of the secp192r1 context.
        /// <returns></returns>
        public static unsafe ECCurve Get_SECP192R1()
        {
            return new ECCurve(
                192,
                stackalloc ulong[] { 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF },
                stackalloc ulong[] { 0x146BC9B1B4D22831, 0xFFFFFFFF99DEF836, 0xFFFFFFFFFFFFFFFF },
                stackalloc ulong[] { 0x0a35e4d8da691418, 0xffffffffccef7c1b, 0x7fffffffffffffff },
                stackalloc ulong[] { 0xF4FF0AFD82FF1012, 0x7CBF20EB43A18800, 0x188DA80EB03090F6, 0x73F977A11E794811, 0x631011ED6B24CDD5, 0x07192B95FFC8DA78 },
                stackalloc ulong[] { 0xFEB8DEECC146B9B1, 0x0FA7E9AB72243049, 0x64210519E59C80E7 },
                &MMod_SECP192R1,
                &XSide_Generic,
                &ModSQRT_Generic,
                &DoubleJacobian_Generic
            );
        }

        /// <summary>
        /// Computes result = product % p
        /// </summary>
        public static void MMod_SECP192R1(in ECCurve curve, Span<ulong> result, Span<ulong> product)
        {
            Span<ulong> tmp = stackalloc ulong[curve.NUM_WORDS];
            int carry = 0;

            VLI.Set(result, product, curve.NUM_WORDS);
            VLI.Set(tmp, product.Slice(curve.NUM_WORDS), curve.NUM_WORDS);

            carry = (int)VLI.Add(result, result, tmp, curve.NUM_WORDS);

            tmp[0] = 0;
            tmp[1] = product[3];
            tmp[2] = product[4];
            carry += (int)VLI.Add(result, result, tmp, curve.NUM_WORDS);

            tmp[0] = tmp[1] = product[5];
            tmp[2] = 0;
            carry += (int)VLI.Add(result, result, tmp, curve.NUM_WORDS);

            while (Convert.ToBoolean(carry) || VLI.VarTimeCmp(curve.P, result, curve.NUM_WORDS) != 1)
            {
                carry -= (int)VLI.Sub(result, result, curve.P, curve.NUM_WORDS);
            }
        }
    }
}

