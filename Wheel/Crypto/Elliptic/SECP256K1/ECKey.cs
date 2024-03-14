using Wheel.Crypto.Elliptic.Internal.SECP256K1;
using Wheel.Crypto.Elliptic.Internal.VeryLongInt;

namespace Wheel.Crypto.Elliptic.SECP256K1
{
    public static class ECKey
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
            compressed[0] = (byte)(2 + (public_key[Constants.NUM_N_BYTES * 2 - 1] & 0x01));
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

        public static bool PrivateKeyTweak(Span<byte> result, ReadOnlySpan<byte> private_key, ReadOnlySpan<byte> scalar)
        {
            Span<ulong> _private = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            Span<ulong> _result = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            Span<ulong> _scalar = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];

            VLI_Conversion.BytesToNative(_private, private_key, Constants.NUM_N_BYTES);
            VLI_Conversion.BytesToNative(_scalar, scalar, Constants.NUM_N_BYTES);

            // Make sure the private key is in the range [1, n-1].
            if (VLI_Logic.IsZero(_private, Constants.NUM_WORDS))
            {
                return false;
            }

            if (VLI_Logic.Cmp(Constants.n, _private, Constants.NUM_WORDS) != 1)
            {
                return false;
            }

            // Make sure that scalar is in the range [1, n-1]
            if (VLI_Logic.IsZero(_scalar, Constants.NUM_WORDS))
            {
                return false;
            }

            if (VLI_Logic.Cmp(Constants.n, _scalar, Constants.NUM_WORDS) != 1)
            {
                return false;
            }

            // Apply scalar addition
            //   r = (a + scalar) % n
            VLI_Arithmetic.ModAdd(_result, _private, _scalar, Constants.n, Constants.NUM_WORDS);

            /* Check again that the new private key is in the range [1, n-1]. */
            if (VLI_Logic.IsZero(_result, Constants.NUM_WORDS))
            {
                return false;
            }

            if (VLI_Logic.Cmp(Constants.n, _result, Constants.NUM_WORDS) != 1)
            {
                return false;
            }

            VLI_Conversion.NativeToBytes(result, Constants.NUM_N_BYTES, _result);

            return true;
        }

        public static bool PublicKeyTweak(Span<byte> result, ReadOnlySpan<byte> public_key, ReadOnlySpan<byte> scalar)
        {
            Span<ulong> _public = stackalloc ulong[VLI_Common.ECC_MAX_WORDS * 2];
            Span<ulong> _result = stackalloc ulong[VLI_Common.ECC_MAX_WORDS * 2];
            Span<ulong> _s_mul_G = stackalloc ulong[VLI_Common.ECC_MAX_WORDS * 2];
            Span<ulong> _scalar = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];

            VLI_Conversion.BytesToNative(_public, public_key, Constants.NUM_N_BYTES);
            VLI_Conversion.BytesToNative(_public.Slice(Constants.NUM_WORDS), public_key.Slice(Constants.NUM_N_BYTES), Constants.NUM_N_BYTES);
            VLI_Conversion.BytesToNative(_scalar, scalar, Constants.NUM_N_BYTES);

            // Make sure that public key is valid
            if (!ECCPoint.IsValid(_public))
            {
                return false;
            }

            // Public key is computed by multiplication i.e. scalar*G is what we need
            if (!ComputePublicKey(_s_mul_G, _scalar))
            {
                return false;
            }

            // R = A + scalar*G
            ECCPoint.PointAdd(_result, _public, _s_mul_G);

            // Ensure that new public key is valid as well
            if (!ECCPoint.IsValid(_result))
            {
                return false;
            }

            VLI_Conversion.NativeToBytes(result, Constants.NUM_N_BYTES, _result);
            VLI_Conversion.NativeToBytes(result.Slice(Constants.NUM_N_BYTES), Constants.NUM_N_BYTES, _result.Slice(Constants.NUM_WORDS));

            return true;
        }
    }
}
