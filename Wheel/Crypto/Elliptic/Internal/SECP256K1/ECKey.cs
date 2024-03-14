using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Wheel.Crypto.Elliptic.Internal.VeryLongInt;

namespace Wheel.Crypto.Elliptic.Internal.SECP256K1
{
    internal static class ECKey
    {
        public static bool ComputePublicKey(Span<ulong> result, ReadOnlySpan<ulong> private_key)
        {
            Span<ulong> tmp1 = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            Span<ulong> tmp2 = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            VLI_Common.Picker<ulong> p2 = new(tmp1, tmp2);
            
            ulong carry;

            // Regularize the bitcount for the private key so that attackers cannot use a side channel
            //  attack to learn the number of leading zeros.
            carry = ECCUtil.regularize_k(private_key, tmp1, tmp2);

            ECCPoint.PointMul(result, Constants.G, p2[VLI_Logic.ZeroIfNotZero(carry)], Constants.NUM_N_BITS + 1);

            // Final validation of computed value
            return !ECCPoint.IsZero(result);
        }

        /// <summary>
        /// Check to see if a public key is valid.
        /// Note that you are not required to check for a valid public key before using any other 
        /// functions. However, you may wish to avoid spending CPU time computing a shared secret or
        /// verifying a signature using an invalid public key.
        /// </summary>
        /// <param name="public_key">The public key to check.</param>
        /// <returns>True if key is valid</returns>
        public static bool IsValidPublicKey(ReadOnlySpan<byte> public_key)
        {
            Span<ulong> native_point = stackalloc ulong[2 * VLI_Common.ECC_MAX_WORDS];

            VLI_Conversion.BytesToNative(native_point, public_key, Constants.NUM_N_BYTES);
            VLI_Conversion.BytesToNative(native_point.Slice(Constants.NUM_WORDS), public_key.Slice(Constants.NUM_N_BYTES), Constants.NUM_N_BYTES);

            return ECCPoint.IsValid(native_point);
        }

        /// <summary>
        /// Check to see if a private key is valid.
        /// Note that you are not required to check for a valid private key before using any other functions.
        /// </summary>
        /// <param name="private_key">The private key to check.</param>
        /// <returns>True if the private key is valid.</returns>
        public static bool IsValidPrivateKey(ReadOnlySpan<byte> private_key)
        {
            Span<ulong> native_key = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];

            VLI_Conversion.BytesToNative(native_key, private_key, Constants.NUM_N_BYTES);

            /* Make sure the private key is in the range [1, n-1]. */
            if (VLI_Logic.IsZero(native_key, Constants.NUM_WORDS))
            {
                return false;
            }

            return VLI_Logic.Cmp(Constants.n, native_key, Constants.NUM_WORDS) == 1;
        }

        /// <summary>
        /// Compress a public key.
        /// </summary>
        /// <param name="public_key">The public key to compress.</param>
        /// <param name="compressed">
        /// Will be filled in with the compressed public key. Must be at least
        /// (curve size + 1) bytes long; for example, if the curve is secp256r1,
        /// compressed must be 33 bytes long.
        /// </param>
        public static void Compress(ReadOnlySpan<byte> public_key, Span<byte> compressed)
        {
            for (int i = 0; i < Constants.NUM_N_BYTES; ++i)
            {
                compressed[i + 1] = public_key[i];
            }
            compressed[0] = (byte) (2 + (public_key[Constants.NUM_N_BYTES * 2 - 1] & 0x01));
        }

        /// <summary>
        /// Decompress a compressed public key.
        /// </summary>
        /// <param name="compressed">The compressed public key.</param>
        /// <param name="public_key">Will be filled in with the decompressed public key.</param>
        public static void Decompress(ReadOnlySpan<byte> compressed, Span<byte> public_key)
        {
            Span<ulong> point = stackalloc ulong[2 * VLI_Common.ECC_MAX_WORDS];
            Span<ulong> y = point.Slice(Constants.NUM_WORDS);

            VLI_Conversion.BytesToNative(point, compressed.Slice(1), Constants.NUM_N_BYTES);
            ECCUtil.x_side(y, point);
            ECCUtil.mod_sqrt_default(y);

            if ((y[0] & 0x01) != ((ulong)compressed[0] & 0x01))
            {
                VLI_Arithmetic.Sub(y, Constants.p, y, Constants.NUM_WORDS);
            }

            VLI_Conversion.NativeToBytes(public_key, Constants.NUM_N_BYTES, point);
            VLI_Conversion.NativeToBytes(public_key.Slice(Constants.NUM_N_BYTES), Constants.NUM_N_BYTES, y);
        }
    }
}
