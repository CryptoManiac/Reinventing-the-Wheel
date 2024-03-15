using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Wheel.Crypto.Elliptic.Internal.SECP256K1;
using Wheel.Crypto.Elliptic.Internal.VeryLongInt;
using Wheel.Crypto.Hashing.HMAC;

namespace Wheel.Crypto.Elliptic.SECP256K1
{
    public static class ECKey
    {
        /// <summary>
        /// Compute the corresponding public key for a private key.
        /// </summary>
        /// <param name="public_key">Will be filled in with the corresponding public key</param>
        /// <param name="private_key"> The private key to compute the public key for</param>
        /// <returns>True if the key was computed successfully, False if an error occurred.</returns>
        public static bool ComputePublicKey(Span<byte> public_key, ReadOnlySpan<byte> private_key)
        {
            Span<ulong> _private = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            Span<ulong> _public = stackalloc ulong[VLI_Common.ECC_MAX_WORDS * 2];

            VLI_Conversion.BytesToNative(_private, private_key, Constants.NUM_N_BYTES);

            /* Make sure the private key is in the range [1, n-1]. */
            if (VLI_Logic.IsZero(_private, Constants.NUM_WORDS))
            {
                return false;
            }

            if (VLI_Logic.Cmp(Constants.n, _private, Constants.NUM_WORDS) != 1)
            {
                return false;
            }

            /* Compute public key. */
            if (!ECCPoint.ComputePublicPoint(_public, _private))
            {
                return false;
            }

            VLI_Conversion.NativeToBytes(public_key, Constants.NUM_N_BYTES, _public);
            VLI_Conversion.NativeToBytes(public_key.Slice(Constants.NUM_N_BYTES), Constants.NUM_N_BYTES, _public.Slice(Constants.NUM_WORDS));
            return true;
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

        /// <summary>
        /// Private key tweak by scalar
        /// </summary>
        /// <param name="result"></param>
        /// <param name="private_key"></param>
        /// <param name="scalar"></param>
        /// <returns></returns>
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

        /// <summary>
        /// EC public key tweak by scalar
        /// </summary>
        /// <param name="result"></param>
        /// <param name="public_key"></param>
        /// <param name="scalar"></param>
        /// <returns></returns>
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
            if (!ECCPoint.ComputePublicPoint(_s_mul_G, _scalar))
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

        /// <summary>
        /// Generate an ECDSA signature for a given hash value, with the user-provided provided K
        /// </summary>
        /// <param name="signature">Will be filled in with the signature value</param>
        /// <param name="private_key">Your private key</param>
        /// <param name="message_hash">The hash of the message to sign</param>
        /// <param name="K">Random secret</param>
        /// <returns></returns>
        public static bool SignWithK(Span<byte> signature, ReadOnlySpan<byte> private_key, ReadOnlySpan<byte> message_hash, ReadOnlySpan<ulong> K)
        {
            const int num_words = Constants.NUM_WORDS;
            const int num_bytes = Constants.NUM_N_BYTES;
            const int num_n_words = Constants.NUM_WORDS;
            const int num_n_bits = Constants.NUM_N_BITS;

            ulong carry;

            Span<ulong> p = stackalloc ulong[num_words * 2];
            Span<ulong> s = stackalloc ulong[num_words];
            Span<ulong> tmp = stackalloc ulong[num_words];
            VLI_Common.Picker<ulong> k2 = new(tmp, s);

            // Make a local copy of K for in-place modification
            Span<ulong> k = stackalloc ulong[num_words];
            VLI_Arithmetic.Set(k, K, num_words);

            // Make sure 0 < k < curve_n
            if (VLI_Logic.IsZero(k, num_words) || VLI_Logic.Cmp(Constants.n, k, num_n_words) != 1)
            {
                return false;
            }

            carry = ECCUtil.regularize_k(k, tmp, s);
            ECCPoint.PointMul(p, Constants.G, k2[VLI_Logic.ZeroIfNotZero(carry)], num_n_bits + 1);
            if (VLI_Logic.IsZero(p, num_words))
            {
                return false;
            }

            // Stub: No RNG function is actually used here
            VLI_Arithmetic.Clear(tmp, num_n_words);
            tmp[0] = 1;

            // Prevent side channel analysis of uECC_vli_modInv() to determine
            //   bits of k / the private key by premultiplying by a random number
            VLI_Arithmetic.ModMult(k, k, tmp, Constants.n, num_n_words); // k' = rand * k
            VLI_Arithmetic.ModInv(k, k, Constants.n, num_n_words);       // k = 1 / k'
            VLI_Arithmetic.ModMult(k, k, tmp, Constants.n, num_n_words); // k = 1 / k

            VLI_Conversion.NativeToBytes(signature, num_bytes, p); // store r
            VLI_Conversion.BytesToNative(tmp, private_key, num_bytes); // tmp = d

            s[num_n_words - 1] = 0;
            VLI_Arithmetic.Set(s, p, num_words);
            VLI_Arithmetic.ModMult(s, tmp, s, Constants.n, num_n_words); // s = r*d

            BitsToInt(tmp, message_hash, message_hash.Length);

            VLI_Arithmetic.ModAdd(s, tmp, s, Constants.n, num_n_words); // s = e + r*d
            VLI_Arithmetic.ModMult(s, s, k, Constants.n, num_n_words);  // s = (e + r*d) / k

            if (VLI_Logic.NumBits(s, num_n_words) > num_n_bits)
            {
                return false;
            }

            if (VLI_Logic.Cmp(s, Constants.half_n, num_words) == 1)
            {
                // Apply Low-S rule to signature
                VLI_Arithmetic.Sub(s, Constants.n, s, num_words); // s = n - s
            }

            VLI_Conversion.NativeToBytes(signature.Slice(num_bytes), num_bytes, s);

            return true;
        }

        /// <summary>
        /// Generate an ECDSA signature for a given hash value, using a deterministic algorithm
        /// (see RFC 6979).
        /// 
        /// Usage: Compute a hash of the data you wish to sign and pass it to
        /// this function along with your private key and a hash context. Note that the message_hash
        /// does not need to be computed with the same hash function used by hash_context.
        /// </summary>
        /// <param name="signature">Will be filled in with the signature value</param>
        /// <param name="private_key">Your private key</param>
        /// <param name="message_hash">The hash of the message to sign</param>
        /// <param name="hasher">A hasher to use</param>
        /// <returns></returns>
        public static bool SignDeterministic(Span<byte> signature, ReadOnlySpan<byte> private_key, ReadOnlySpan<byte> message_hash, IMac hasher)
        {
            // Allocate buffer for HMAC results
            Span<byte> K = stackalloc byte[hasher.HashSz];

            // Sequence of iteration is encoded here
            Span<byte> n = stackalloc byte[sizeof(long)];

            // Will retry until succeed
            for (long i = 0; i != Int64.MaxValue; ++i)
            {

                // Init HMAC with private key
                hasher.Init(private_key);

                // Add message hash
                hasher.Update(message_hash);

                // Encode and add iteration sequence
                MemoryMarshal.Cast<byte, long>(n)[0] = i;
                hasher.Update(n);

                // Hash is then used as K parameter
                hasher.Digest(K);

                // Try to sign
                if (SignWithK(signature, private_key, message_hash, MemoryMarshal.Cast<byte, ulong>(K)))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Verify an ECDSA signature.
        /// Usage: Compute the hash of the signed data using the same hash as the signer and
        /// pass it to this function along with the signer's public key and the signature values (r and s).
        /// </summary>
        /// <param name="signature">The signature value</param>
        /// <param name="public_key">The signer's public key</param>
        /// <param name="message_hash">The hash of the signed data</param>
        /// <returns></returns>
        public static bool VerifySignature(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> public_key, ReadOnlySpan<byte> message_hash)
        {
            throw new Exception("Not yet implemented");
        }

        private static void BitsToInt(Span<ulong> native, ReadOnlySpan<byte> bits, int bits_size)
        {
            const int num_n_bytes = Constants.NUM_N_BYTES;
            const int num_n_words = Constants.NUM_WORDS;
            const int num_n_bits = Constants.NUM_N_BITS;

            if (bits_size > num_n_bytes)
            {
                bits_size = num_n_bytes;
            }

            VLI_Arithmetic.Clear(native, num_n_words);
            VLI_Conversion.BytesToNative(native, bits, bits_size);
            if (bits_size * 8 <= num_n_bits)
            {
                return;
            }

            ulong carry = 0;
            int shift = bits_size * 8 - num_n_bits;
            for (int index = num_n_words - 1; index >= 0; --index)
            {
                ulong temp = native[index];
                native[index] = (temp >> shift) | carry;
                carry = temp << (VLI_Common.WORD_BITS - shift);
            }

            /* Reduce mod curve_n */
            if (VLI_Logic.CmpUnsafe(Constants.n, native, num_n_words) != 1)
            {
                VLI_Arithmetic.Sub(native, native, Constants.n, num_n_words);
            }
        }
    }
}
