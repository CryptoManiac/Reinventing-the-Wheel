﻿using System;
using System.Runtime.InteropServices;
using Wheel.Crypto.Elliptic.Internal;
using Wheel.Crypto.Elliptic.Internal.VeryLongInt;
using Wheel.Crypto.Hashing.HMAC;

namespace Wheel.Crypto.Elliptic
{
	public struct ECPrivateKey
	{
        /// <summary>
        /// The secret key funcions are using slices that are being made from this hidden array.
        /// </summary>
        internal unsafe fixed ulong private_key_data[VLI_Common.ECC_MAX_WORDS];

        /// <summary>
        /// ECC implementation to use
        /// </summary>
        private ECCurve curve { get; }

        /// <summary>
        /// Access to the private scalar data
        /// </summary>
        private readonly unsafe Span<ulong> secret_x
        {
            get
            {
                fixed (ulong* ptr = &private_key_data[0])
                {
                    return new Span<ulong>(ptr, curve.NUM_WORDS);
                }
            }
        }

        /// <summary>
        /// Construct the empty key
        /// </summary>
        /// <param name="curve">ECC implementation</param>
        public ECPrivateKey(ECCurve curve)
		{
            this.curve = curve;

            // Init with zeros
            unsafe
            {
                fixed (ulong* ptr = &private_key_data[0])
                {
                    new Span<ulong>(ptr, VLI_Common.ECC_MAX_WORDS).Clear();
                }
            }
        }

        /// <summary>
        /// Does this instance contain a valid key or not
        /// </summary>
        public unsafe readonly bool IsValid
        {
            get => !VLI_Logic.IsZero(secret_x, curve.NUM_N_WORDS) && VLI_Logic.Cmp(curve.n, secret_x, curve.NUM_N_WORDS) == 1;
        }

        /// <summary>
        /// Erase object state
        /// </summary>
        public void Reset()
        {
            VLI_Arithmetic.Clear(secret_x, curve.NUM_WORDS);
        }

        /// <summary>
        /// Dump the native point data
        /// </summary>
        /// <param name="native"></param>
        /// <returns>True if point is valid and copying has been successful</returns>
        public readonly bool UnWrap(ref Span<ulong> native_out)
        {
            if (!IsValid || native_out.Length != curve.NUM_WORDS)
            {
                return false;
            }

            secret_x.CopyTo(native_out);
            return true;
        }

        /// <summary>
        /// Check to see if a serialized private key is valid.
        /// Note that you are not required to check for a valid private key before using any other functions.
        /// </summary>
        /// <param name="private_key">The private key to check.</param>
        /// <returns>True if the private key is valid.</returns>
        public static bool IsValidPrivateKey(ReadOnlySpan<byte> private_key, ECCurve curve)
        {
            Span<ulong> native_key = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];

            VLI_Conversion.BytesToNative(native_key, private_key, curve.NUM_N_BYTES);

            /* Make sure the private key is in the range [1, n-1]. */
            if (VLI_Logic.IsZero(native_key, curve.NUM_N_WORDS))
            {
                return false;
            }

            return VLI_Logic.Cmp(curve.n, native_key, curve.NUM_N_WORDS) == 1;
        }

        /// <summary>
        /// Serialize the native key into big endian number
        /// </summary>
        /// <param name="secret_scalar"></param>
        /// <returns>True if successful and this key is valid</returns>
        public readonly bool Serialize(Span<byte> secret_scalar)
        {
            if (!IsValid || secret_scalar.Length != curve.NUM_BYTES)
            {
                return false;
            }

            VLI_Conversion.NativeToBytes(secret_scalar, curve.NUM_N_BYTES, secret_x);

            return true;
        }

        /// <summary>
        /// Try to init using the provided bytes
        /// </summary>
        /// <param name="private_key">Serialized scalar data</param>
        /// <returns>True if successful</returns>
        public bool Parse(in ReadOnlySpan<byte> private_key)
        {
            Reset();

            Span<ulong> native_key = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];

            VLI_Conversion.BytesToNative(native_key, private_key, curve.NUM_N_BYTES);

            // Make sure the private key is in the range [1, n-1].
            if (VLI_Logic.IsZero(native_key, curve.NUM_N_WORDS) || VLI_Logic.Cmp(curve.n, native_key, curve.NUM_N_WORDS) != 1)
            {
                return false;
            }

            VLI_Arithmetic.Set(secret_x, native_key, curve.NUM_WORDS);
            return true;
        }

        /// <summary>
        /// Compute the corresponding public key for a private key.
        /// </summary>
        /// <param name="public_key">Will be filled in with the corresponding public key</param>
        /// <param name="private_key"> The private key to compute the public key for</param>
        /// <returns>True if the key was computed successfully, False if an error occurred.</returns>
        public readonly bool ComputePublicKey(ref ECPublicKey public_key)
        {
            if (!IsValid)
            {
                return false;
            }

            Span<ulong> _public = stackalloc ulong[VLI_Common.ECC_MAX_WORDS * 2];

            // Compute public key.
            if (!ECCPoint.ComputePublicPoint(curve, _public, secret_x))
            {
                return false;
            }

            unsafe
            {
                fixed(ulong* ptr = &public_key.public_key_data[0])
                {
                    Span<ulong> native_target_point = new(ptr, curve.NUM_WORDS * 2);
                    VLI_Arithmetic.Set(native_target_point, _public, curve.NUM_WORDS * 2);
                }
            }

            return true;
        }

        /// <summary>
        /// Private key tweak by scalar
        /// </summary>
        /// <param name="result"></param>
        /// <param name="scalar"></param>
        /// <returns></returns>
        public readonly bool KeyTweak(ECCurve curve, ref ECPrivateKey result, ReadOnlySpan<byte> scalar)
        {
            if (!IsValid)
            {
                return false;
            }

            Span<ulong> _result = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            Span<ulong> _scalar = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];

            VLI_Conversion.BytesToNative(_scalar, scalar, curve.NUM_N_BYTES);

            // Make sure that scalar is in the range [1, n-1]
            if (VLI_Logic.IsZero(_scalar, curve.NUM_N_WORDS))
            {
                return false;
            }

            if (VLI_Logic.Cmp(curve.n, _scalar, curve.NUM_N_WORDS) != 1)
            {
                return false;
            }

            // Apply scalar addition
            //   r = (a + scalar) % n
            VLI_Arithmetic.ModAdd(_result, secret_x, _scalar, curve.n, curve.NUM_N_WORDS);


            // Check again that the new private key is in the range [1, n-1].
            if (VLI_Logic.IsZero(_result, curve.NUM_N_WORDS))
            {
                return false;
            }

            if (VLI_Logic.Cmp(curve.n, _result, curve.NUM_N_WORDS) != 1)
            {
                return false;
            }

            // Copy resulting key data
            _result.CopyTo(result.secret_x);

            return true;
        }

        /// <summary>
        /// Generate an ECDSA signature for a given hash value, with the user-provided provided K
        /// </summary>
        /// <param name="r">Will be filled in with the signature value</param>
        /// <param name="s">Will be filled in with the signature value</param>
        /// <param name="private_key">Your private key</param>
        /// <param name="message_hash">The hash of the message to sign</param>
        /// <param name="K">Random secret</param>
        /// <param name="K_shadow">A "shadow" of the random secret</param>
        /// <returns></returns>
        private readonly bool SignWithK(Span<ulong> r, Span<ulong> s, in ReadOnlySpan<byte> message_hash, in ReadOnlySpan<ulong> K, in ReadOnlySpan<ulong> K_shadow)
        {
            Span<ulong> p = stackalloc ulong[VLI_Common.ECC_MAX_WORDS * 2];
            Span<ulong> tmp = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            VLI_Common.Picker<ulong> k2 = new(tmp, s);

            int num_words = curve.NUM_WORDS;
            int num_bytes = curve.NUM_BYTES;
            int num_n_words = curve.NUM_N_WORDS;
            int num_n_bits = curve.NUM_N_BITS;

            ulong carry;

            // Make a local copy of K for in-place modification
            Span<ulong> k = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            VLI_Arithmetic.Set(k, K, num_words);

            // Make sure 0 < k < curve_n 
            if (VLI_Logic.IsZero(k, num_words) || VLI_Logic.Cmp(curve.n, k, num_n_words) != 1)
            {
                return false;
            }

            carry = ECCUtil.RegularizeK(curve, k, tmp, s);
            ECCPoint.PointMul(curve, p, curve.G, k2[Convert.ToUInt64(!Convert.ToBoolean(carry))], num_n_bits + 1);
            if (VLI_Logic.IsZero(p, num_words))
            {
                return false;
            }

            // Prevent side channel analysis of VLI_Arithmetic.ModInv() to determine
            //   bits of k / the private key by premultiplying by a random number
            VLI_Arithmetic.Set(tmp, K_shadow, num_n_words);
            VLI_Arithmetic.ModMult(k, k, tmp, curve.n, num_n_words); // k' = rand * k
            VLI_Arithmetic.ModInv(k, k, curve.n, num_n_words);       // k = 1 / k'
            VLI_Arithmetic.ModMult(k, k, tmp, curve.n, num_n_words); // k = 1 / k

            VLI_Arithmetic.Set(r, p, num_words); // store r
            VLI_Arithmetic.Set(tmp, secret_x, curve.NUM_N_WORDS); // tmp = private key

            s[num_n_words - 1] = 0;
            VLI_Arithmetic.Set(s, p, num_words);
            VLI_Arithmetic.ModMult(s, tmp, s, curve.n, num_n_words); // s = r*d

            ECCUtil.BitsToInt(curve, tmp, message_hash, message_hash.Length);
            VLI_Arithmetic.ModAdd(s, tmp, s, curve.n, num_n_words); // s = e + r*d 
            VLI_Arithmetic.ModMult(s, s, k, curve.n, num_n_words);  // s = (e + r*d) / k 
            if (VLI_Logic.NumBits(s, num_n_words) > num_bytes * 8)
            {
                return false;
            }

            if (VLI_Logic.Cmp(s, curve.half_n, num_words) == 1)
            {
                // Apply Low-S rule to signature
                VLI_Arithmetic.Sub(s, curve.n, s, num_words); // s = n - s 
            }

            return true;
        }

        /// <summary>
        /// Generate an ECDSA signature for a given hash value, using a deterministic algorithm
        /// 
        /// Usage: Compute a hash of the data you wish to sign and pass it to this function along with your private key and entropy bytes. The entropy bytes argument may be set to empty array if you don't need this feature.
        /// </summary>
        /// <param name="r">Will be filled in with the signature value</param>
        /// <param name="s">Will be filled in with the signature value</param>
        /// <param name="message_hash">The hash of the message to sign</param>
        /// <param name="entropy">Additional entropy for K generation</param>
        /// <returns></returns>
        private readonly bool SignDeterministic<HMAC_IMPL>(Span<ulong> r, Span<ulong> s, in ReadOnlySpan<byte> message_hash, in ReadOnlySpan<byte> entropy) where HMAC_IMPL : unmanaged, IMac
        {
            // Secret K will be written here
            Span<ulong> K = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            Span<ulong> K_shadow = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];

            // Will retry until succeed
            for (long i = 1; i != long.MaxValue; ++i)
            {
                GenerateK<HMAC_IMPL>(ref K, message_hash, entropy, i);
                GenerateK<HMAC_IMPL>(ref K_shadow, message_hash, entropy, -i);

                // Try to sign
                if (SignWithK(r, s, message_hash, K, K_shadow))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Generate an ECDSA signature for a given hash value, using a deterministic algorithm
        /// 
        /// Usage: Compute a hash of the data you wish to sign and pass it to this function along with your private key and entropy bytes. The entropy bytes argument may be set to empty array if you don't need this feature.
        /// </summary>
        /// <param name="signature">Will be filled in with the signature value</param>
        /// <param name="private_key">Your private key</param>
        /// <param name="message_hash">The hash of the message to sign</param>
        /// <param name="entropy">Additional entropy for K generation</param>
        /// <returns></returns>
        public readonly bool Sign<HMAC_IMPL>(ref DERSignature signature, in ReadOnlySpan<byte> message_hash, in ReadOnlySpan<byte> entropy) where HMAC_IMPL : unmanaged, IMac
        {
            return SignDeterministic<HMAC_IMPL>(signature.r, signature.s, message_hash, entropy);
        }

        /// <summary>
        /// Generate an ECDSA signature for a given hash value, using a deterministic algorithm
        /// 
        /// Usage: Compute a hash of the data you wish to sign and pass it to this function along with your private key and entropy bytes. The entropy bytes argument may be set to empty array if you don't need this feature.
        /// </summary>
        /// <param name="signature">Will be filled in with the signature value</param>
        /// <param name="private_key">Your private key</param>
        /// <param name="message_hash">The hash of the message to sign</param>
        /// <param name="entropy">Additional entropy for K generation</param>
        /// <returns></returns>
        public readonly bool Sign<HMAC_IMPL>(ref CompactSignature signature, ReadOnlySpan<byte> message_hash, ReadOnlySpan<byte> entropy) where HMAC_IMPL : unmanaged, IMac
        {
            return SignDeterministic<HMAC_IMPL>(signature.r, signature.s, message_hash, entropy);
        }

        /// <summary>
        /// Generate deterministic K value for signing
        /// </summary>
        /// <param name="secret"></param>
        /// <param name="private_key"></param>
        /// <param name="message_hash"></param>
        /// <param name="entropy"></param>
        /// <param name="sequence"></param>
        private readonly void GenerateK<HMAC_IMPL>(ref Span<ulong> result, in ReadOnlySpan<byte> message_hash, in ReadOnlySpan<byte> entropy, long sequence) where HMAC_IMPL : unmanaged, IMac
        {
            // See 3..2 of the RFC 6979 to get what is going on here
            // We're not following it to the letter, but our algorithm is very similar

            HMAC_IMPL hmac = new();
            Span<byte> secret_scalar = stackalloc byte[curve.NUM_N_BYTES];
            Span<byte> separator_00 = stackalloc byte[1] { 0x00 };
            Span<byte> separator_01 = stackalloc byte[1] { 0x01 };
            Span<byte> sequence_data = stackalloc byte[sizeof(long)];
            Span<byte> secret_data = MemoryMarshal.Cast<ulong, byte>(result);

            // Serialize secret key into big endian for hashing
            VLI_Conversion.NativeToBytes(secret_scalar, curve.NUM_N_BYTES, secret_x);

            // Convert sequence to bytes
            MemoryMarshal.Cast<byte, long>(sequence_data)[0] = sequence;

            // Allocate buffer for HMAC results
            Span<byte> K = stackalloc byte[hmac.HashSz];
            Span<byte> V = stackalloc byte[hmac.HashSz];

            // B
            K.Fill(0); // K = 00 00 00 ..

            // C
            V.Fill(0x01); // V = 01 01 01 ..

            // D
            hmac.Init(K); // K = HMAC_K(V || 00 || entropy || 00 || sequence || 00 || secret_scalar || message_hash)
            hmac.Update(V);
            hmac.Update(separator_00);
            hmac.Update(entropy);
            hmac.Update(separator_00);
            hmac.Update(sequence_data);
            hmac.Update(separator_00);
            hmac.Update(secret_scalar);
            hmac.Update(message_hash);
            hmac.Digest(K);

            // E
            hmac.Init(K); // V = HMAC_K(V)
            hmac.Update(V);
            hmac.Digest(V);

            // F
            hmac.Init(K); // K = HMAC_K(V || 01 || entropy || 01 || sequence || 01 || secret_scalar || message_hash)
            hmac.Update(V);
            hmac.Update(separator_01);
            hmac.Update(entropy);
            hmac.Update(separator_01);
            hmac.Update(sequence_data);
            hmac.Update(separator_01);
            hmac.Update(secret_scalar);
            hmac.Update(message_hash);
            hmac.Digest(K);

            // G
            hmac.Init(K); // V = HMAC_K(V)
            hmac.Update(V);
            hmac.Digest(V);

            // H
            int secret_byte_index = 0;
            while (true)
            {
                // H2
                hmac.Init(K); // V = HMAC_K(V)
                hmac.Update(V);
                hmac.Digest(V);

                // T = T || V
                Span<byte> src = V.Slice(0, Math.Min(V.Length, secret_data.Length - secret_byte_index));
                Span<byte> target = secret_data.Slice(secret_byte_index);
                src.CopyTo(target);
                secret_byte_index += src.Length;

                if (secret_byte_index >= curve.NUM_N_BYTES)
                {
                    if (IsValidPrivateKey(secret_data, curve))
                    {
                        return;
                    }

                    // Doesn't meet the curve criteria,
                    // start filling from zero
                    secret_data.Clear();
                    secret_byte_index = 0;
                }

                // H3
                hmac.Init(K);  // K = HMAC_K(V || 00 || entropy || 00 || sequence)
                hmac.Update(V);
                hmac.Update(separator_00);
                hmac.Update(entropy);
                hmac.Update(separator_00);
                hmac.Update(sequence_data);
                hmac.Digest(K);

                hmac.Init(K); // V = HMAC_K(V)
                hmac.Update(V);
                hmac.Digest(V);
            }
        }
    }
}

