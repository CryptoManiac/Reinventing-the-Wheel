﻿using System;
using System.Security.Cryptography;
using Wheel.Crypto.Elliptic.Internal.SECP256K1;
using Wheel.Crypto.Elliptic.Internal.VeryLongInt;

namespace Wheel.Crypto.Elliptic.SECP256K1
{
    /// <summary>
    /// Shared secret derivation
    /// </summary>
	public static class ECDH
	{
        /// <summary>
        /// Compute a shared secret given your secret key and someone else's public key. If the public key
        /// is not from a trusted source and has not been previously verified, you should verify it first
        /// using ECKey.IsValidPublicKey() function.
        ///
        /// Note: It is recommended that you hash the result of uECC_shared_secret() before using it for
        /// symmetric encryption or HMAC.
        /// </summary>
        /// <param name="public_key">The public key of the remote party.</param>
        /// <param name="private_key">Your private key.</param>
        /// <param name="secret">Will be filled in with the shared secret value. Must be the same size as the curve size; for example, if the curve is secp256k1, secret must be 32 bytes long. </param>
        /// <returns>True if the shared secret was generated successfully, False if an error occurred.</returns>
        public static bool Derive(ReadOnlySpan<byte> public_key, ReadOnlySpan<byte> private_key, Span<byte> secret)
		{
            Span<ulong> _public = stackalloc ulong[VLI_Common.ECC_MAX_WORDS * 2];
            Span <ulong> _private = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            Span<ulong> tmp = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            VLI_Common.Picker<ulong> p2 = new(_private, tmp);
            ulong carry;
            const int num_words = Constants.NUM_WORDS;
            const int num_bytes = Constants.NUM_BYTES;

            VLI_Conversion.BytesToNative(_private, private_key, Constants.NUM_N_BYTES);
            VLI_Conversion.BytesToNative(_public, public_key, num_bytes);
            VLI_Conversion.BytesToNative(_public.Slice(num_words), public_key.Slice(num_bytes), num_bytes);

            // Regularize the bitcount for the private key so that attackers
            // cannot use a side channel attack to learn the number of leading zeros.
            carry = ECCUtil.regularize_k(_private, _private, tmp);

            ECCPoint.PointMul(_public, _public, p2[Convert.ToUInt64(!Convert.ToBoolean(carry))], Constants.NUM_N_BITS + 1);

            VLI_Conversion.NativeToBytes(secret, num_bytes, _public);

            return !ECCPoint.IsZero(_public);
        }
    }
}

