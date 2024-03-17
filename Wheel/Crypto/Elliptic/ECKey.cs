using System.Runtime.InteropServices;
using Wheel.Crypto.Elliptic.Internal;
using Wheel.Crypto.Elliptic.Internal.VeryLongInt;
using Wheel.Crypto.Hashing.HMAC;

namespace Wheel.Crypto.Elliptic
{
    public static class ECKey
    {
        /// <summary>
        /// Compute the corresponding public key for a private key.
        /// </summary>
        /// <param name="public_key">Will be filled in with the corresponding public key</param>
        /// <param name="private_key"> The private key to compute the public key for</param>
        /// <returns>True if the key was computed successfully, False if an error occurred.</returns>
        public static bool ComputePublicKey(ECCurve curve, Span<byte> public_key, ReadOnlySpan<byte> private_key)
        {
            Span<ulong> _private = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            Span<ulong> _public = stackalloc ulong[VLI_Common.ECC_MAX_WORDS * 2];

            VLI_Conversion.BytesToNative(_private, private_key, curve.NUM_N_BYTES);

            /* Make sure the private key is in the range [1, n-1]. */
            if (VLI_Logic.IsZero(_private, curve.NUM_N_WORDS))
            {
                return false;
            }

            if (VLI_Logic.Cmp(curve.n, _private, curve.NUM_N_WORDS) != 1)
            {
                return false;
            }

            /* Compute public key. */
            if (!ECCPoint.ComputePublicPoint(curve, _public, _private))
            {
                return false;
            }

            VLI_Conversion.NativeToBytes(public_key, curve.NUM_BYTES, _public);
            VLI_Conversion.NativeToBytes(public_key.Slice(curve.NUM_BYTES), curve.NUM_BYTES, _public.Slice(curve.NUM_WORDS));
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
        public static bool IsValidPublicKey(ECCurve curve, ReadOnlySpan<byte> public_key)
        {
            Span<ulong> native_point = stackalloc ulong[2 * VLI_Common.ECC_MAX_WORDS];

            VLI_Conversion.BytesToNative(native_point, public_key, curve.NUM_BYTES);
            VLI_Conversion.BytesToNative(native_point.Slice(curve.NUM_WORDS), public_key.Slice(curve.NUM_BYTES), curve.NUM_BYTES);

            return ECCPoint.IsValid(curve, native_point);
        }

        /// <summary>
        /// Check to see if a private key is valid.
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
        /// Compress a public key.
        /// </summary>
        /// <param name="public_key">The public key to compress.</param>
        /// <param name="compressed">
        /// Will be filled in with the compressed public key. Must be at least
        /// (curve size + 1) bytes long; for example, if the curve is secp256r1,
        /// compressed must be 33 bytes long.
        /// </param>
        public static void Compress(ECCurve curve, ReadOnlySpan<byte> public_key, Span<byte> compressed)
        {
            for (int i = 0; i < curve.NUM_BYTES; ++i)
            {
                compressed[i + 1] = public_key[i];
            }
            compressed[0] = (byte)(2 + (public_key[curve.NUM_BYTES * 2 - 1] & 0x01));
        }

        /// <summary>
        /// Decompress a compressed public key.
        /// </summary>
        /// <param name="compressed">The compressed public key.</param>
        /// <param name="public_key">Will be filled in with the decompressed public key.</param>
        public static void Decompress(ECCurve curve, ReadOnlySpan<byte> compressed, Span<byte> public_key)
        {
            Span<ulong> point = stackalloc ulong[2 * VLI_Common.ECC_MAX_WORDS];
            Span<ulong> y = point.Slice(curve.NUM_WORDS);

            VLI_Conversion.BytesToNative(point, compressed.Slice(1), curve.NUM_BYTES);
            curve.XSide(y, point);
            ECCUtil.ModSQRT(y, curve);

            if ((y[0] & 0x01) != ((ulong)compressed[0] & 0x01))
            {
                VLI_Arithmetic.Sub(y, curve.p, y, curve.NUM_WORDS);
            }

            VLI_Conversion.NativeToBytes(public_key, curve.NUM_BYTES, point);
            VLI_Conversion.NativeToBytes(public_key.Slice(curve.NUM_BYTES), curve.NUM_BYTES, y);
        }

        /// <summary>
        /// Private key tweak by scalar
        /// </summary>
        /// <param name="result"></param>
        /// <param name="private_key"></param>
        /// <param name="scalar"></param>
        /// <returns></returns>
        public static bool PrivateKeyTweak(ECCurve curve, Span<byte> result, ReadOnlySpan<byte> private_key, ReadOnlySpan<byte> scalar)
        {
            Span<ulong> _private = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            Span<ulong> _result = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            Span<ulong> _scalar = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];

            VLI_Conversion.BytesToNative(_private, private_key, curve.NUM_N_BYTES);
            VLI_Conversion.BytesToNative(_scalar, scalar, curve.NUM_N_BYTES);

            // Make sure the private key is in the range [1, n-1].
            if (VLI_Logic.IsZero(_private, curve.NUM_N_WORDS))
            {
                return false;
            }

            if (VLI_Logic.Cmp(curve.n, _private, curve.NUM_N_WORDS) != 1)
            {
                return false;
            }

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
            VLI_Arithmetic.ModAdd(_result, _private, _scalar, curve.n, curve.NUM_N_WORDS);

            /* Check again that the new private key is in the range [1, n-1]. */
            if (VLI_Logic.IsZero(_result, curve.NUM_N_WORDS))
            {
                return false;
            }

            if (VLI_Logic.Cmp(curve.n, _result, curve.NUM_N_WORDS) != 1)
            {
                return false;
            }

            VLI_Conversion.NativeToBytes(result, curve.NUM_BYTES, _result);

            return true;
        }

        /// <summary>
        /// EC public key tweak by scalar
        /// </summary>
        /// <param name="result"></param>
        /// <param name="public_key"></param>
        /// <param name="scalar"></param>
        /// <returns></returns>
        public static bool PublicKeyTweak(ECCurve curve, Span<byte> result, ReadOnlySpan<byte> public_key, ReadOnlySpan<byte> scalar)
        {
            Span<ulong> _public = stackalloc ulong[VLI_Common.ECC_MAX_WORDS * 2];
            Span<ulong> _result = stackalloc ulong[VLI_Common.ECC_MAX_WORDS * 2];
            Span<ulong> _s_mul_G = stackalloc ulong[VLI_Common.ECC_MAX_WORDS * 2];
            Span<ulong> _scalar = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];

            VLI_Conversion.BytesToNative(_public, public_key, curve.NUM_BYTES);
            VLI_Conversion.BytesToNative(_public.Slice(curve.NUM_WORDS), public_key.Slice(curve.NUM_BYTES), curve.NUM_BYTES);
            VLI_Conversion.BytesToNative(_scalar, scalar, curve.NUM_N_BYTES);

            // Make sure that public key is valid
            if (!ECCPoint.IsValid(curve, _public))
            {
                return false;
            }

            // Public key is computed by multiplication i.e. scalar*G is what we need
            if (!ECCPoint.ComputePublicPoint(curve, _s_mul_G, _scalar))
            {
                return false;
            }

            // R = A + scalar*G
            ECCPoint.PointAdd(curve, _result, _public, _s_mul_G);

            // Ensure that new public key is valid as well
            if (!ECCPoint.IsValid(curve, _result))
            {
                return false;
            }

            VLI_Conversion.NativeToBytes(result, curve.NUM_BYTES, _result);
            VLI_Conversion.NativeToBytes(result.Slice(curve.NUM_BYTES), curve.NUM_BYTES, _result.Slice(curve.NUM_WORDS));

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
        private static bool SignWithK(ECCurve curve, Span<ulong> r, Span<ulong> s, ReadOnlySpan<byte> private_key, ReadOnlySpan<byte> message_hash, ReadOnlySpan<ulong> K, ReadOnlySpan<ulong> K_shadow)
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
            VLI_Conversion.BytesToNative(tmp, private_key, curve.NUM_N_BYTES); // tmp = d

            s[num_n_words - 1] = 0;
            VLI_Arithmetic.Set(s, p, num_words);
            VLI_Arithmetic.ModMult(s, tmp, s, curve.n, num_n_words); // s = r*d

            BitsToInt(curve, tmp, message_hash, message_hash.Length);
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
        /// <param name="private_key">Your private key</param>
        /// <param name="message_hash">The hash of the message to sign</param>
        /// <param name="entropy">Additional entropy for K generation</param>
        /// <returns></returns>
        private static bool SignDeterministic<HMAC_IMPL>(ECCurve curve, Span<ulong> r, Span<ulong> s, ReadOnlySpan<byte> private_key, ReadOnlySpan<byte> message_hash, ReadOnlySpan<byte> entropy) where HMAC_IMPL : unmanaged, IMac
        {
            // Secret K will be written here
            Span<ulong> K = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            Span<ulong> K_shadow = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];

            // Will retry until succeed
            for (long i = 1; i != long.MaxValue; ++i)
            {
                GenerateK<HMAC_IMPL>(curve, K, private_key, message_hash, entropy, i);
                GenerateK<HMAC_IMPL>(curve, K_shadow, private_key, message_hash, entropy, -i);

                // Try to sign
                if (SignWithK(curve, r, s, private_key, message_hash, K, K_shadow))
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
        public static bool Sign<HMAC_IMPL>(ECCurve curve, DERSignature signature, ReadOnlySpan<byte> private_key, ReadOnlySpan<byte> message_hash, ReadOnlySpan<byte> entropy) where HMAC_IMPL : unmanaged, IMac
        {
            return SignDeterministic<HMAC_IMPL>(curve, signature.r, signature.s, private_key, message_hash, entropy);
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
        public static bool Sign<HMAC_IMPL>(ECCurve curve, CompactSignature signature, ReadOnlySpan<byte> private_key, ReadOnlySpan<byte> message_hash, ReadOnlySpan<byte> entropy) where HMAC_IMPL : unmanaged, IMac
        {
            return SignDeterministic<HMAC_IMPL>(curve, signature.r, signature.s, private_key, message_hash, entropy);
        }

        /// <summary>
        /// Generate deterministic K value for signing
        /// </summary>
        /// <param name="secret"></param>
        /// <param name="private_key"></param>
        /// <param name="message_hash"></param>
        /// <param name="entropy"></param>
        /// <param name="sequence"></param>
        private static void GenerateK<HMAC_IMPL>(ECCurve curve, Span<ulong> secret, ReadOnlySpan<byte> private_key, ReadOnlySpan<byte> message_hash, ReadOnlySpan<byte> entropy, long sequence) where HMAC_IMPL : unmanaged, IMac
        {
            // See 3..2 of the RFC 6979 to get what is going on here
            // We're not following it to the letter, but our algorithm is very similar

            HMAC_IMPL hmac = new();
            Span<byte> separator_00 = stackalloc byte[1] { 0x00 };
            Span<byte> separator_01 = stackalloc byte[1] { 0x01 };
            Span<byte> sequence_data = stackalloc byte[sizeof(long)];
            Span<byte> secret_data = MemoryMarshal.Cast<ulong, byte>(secret);

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
            hmac.Init(K); // K = HMAC_K(V || 00 || entropy || 00 || sequence || 00 || private_key || message_hash)
            hmac.Update(V);
            hmac.Update(separator_00);
            hmac.Update(entropy);
            hmac.Update(separator_00);
            hmac.Update(sequence_data);
            hmac.Update(separator_00);
            hmac.Update(private_key);
            hmac.Update(message_hash);
            hmac.Digest(K);

            // E
            hmac.Init(K); // V = HMAC_K(V)
            hmac.Update(V);
            hmac.Digest(V);

            // F
            hmac.Init(K); // K = HMAC_K(V || 01 || entropy || 01 || sequence || 01 || private_key || message_hash)
            hmac.Update(V);
            hmac.Update(separator_01);
            hmac.Update(entropy);
            hmac.Update(separator_01);
            hmac.Update(sequence_data);
            hmac.Update(separator_01);
            hmac.Update(private_key);
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

        /// <summary>
        /// Verify an ECDSA signature.
        /// Usage: Compute the hash of the signed data using the same hash as the signer and
        /// pass it to this function along with the signer's public key and the signature values (r and s).
        /// </summary>
        /// <param name="curve"></param>
        /// <param name="r"></param>
        /// <param name="s"></param>
        /// <param name="public_key"></param>
        /// <param name="message_hash"></param>
        /// <returns></returns>
        public static bool VerifySignature(ECCurve curve, ReadOnlySpan<ulong> r, ReadOnlySpan<ulong> s, ReadOnlySpan<byte> public_key, ReadOnlySpan<byte> message_hash)
        {
            Span<ulong> u1 = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            Span<ulong> u2 = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            Span<ulong> z = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            Span<ulong> sum = stackalloc ulong[VLI_Common.ECC_MAX_WORDS * 2];

            Span<ulong> rx = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            Span<ulong> ry = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            Span<ulong> tx = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            Span<ulong> ty = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            Span<ulong> tz = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];

            Span<ulong> _public = stackalloc ulong[VLI_Common.ECC_MAX_WORDS * 2];

            int num_bytes = curve.NUM_BYTES;
            int num_words = curve.NUM_WORDS;
            int num_n_words = curve.NUM_N_WORDS;

            VLI_Conversion.BytesToNative(_public, public_key, num_bytes);
            VLI_Conversion.BytesToNative(_public.Slice(num_words), public_key.Slice(num_bytes), num_bytes);

            // r, s must not be 0
            if (VLI_Logic.IsZero(r, num_words) || VLI_Logic.IsZero(s, num_words))
            {
                return false;
            }

            // r, s must be < n.
            if (VLI_Logic.CmpUnsafe(curve.n, r, num_n_words) != 1 || VLI_Logic.CmpUnsafe(curve.n, s, num_n_words) != 1)
            {
                return false;
            }

            // Calculate u1 and u2.
            VLI_Arithmetic.ModInv(z, s, curve.n, num_n_words); // z = 1/s
            u1[num_n_words - 1] = 0;
            BitsToInt(curve, u1, message_hash, message_hash.Length);
            VLI_Arithmetic.ModMult(u1, u1, z, curve.n, num_n_words); // u1 = e/s
            VLI_Arithmetic.ModMult(u2, r, z, curve.n, num_n_words); // u2 = r/s

            // Calculate sum = G + Q.
            VLI_Arithmetic.Set(sum, _public, num_words);
            VLI_Arithmetic.Set(sum.Slice(num_words), _public.Slice(num_words), num_words);
            VLI_Arithmetic.Set(tx, curve.G, num_words);
            VLI_Arithmetic.Set(ty, curve.G.Slice(num_words), num_words);
            VLI_Arithmetic.ModSub(z, sum, tx, curve.p, num_words); // z = x2 - x1
            ECCUtil.XYcZ_Add(curve, tx, ty, sum, sum.Slice(num_words));
            VLI_Arithmetic.ModInv(z, z, curve.p, num_words); // z = 1/z
            ECCUtil.ApplyZ(curve, sum, sum.Slice(num_words), z);

            /* Use Shamir's trick to calculate u1*G + u2*Q */
            VLI_Common.QuadPicker points = new(null, curve.G, _public, sum);
            int num_bits = int.Max(VLI_Logic.NumBits(u1, num_n_words), VLI_Logic.NumBits(u2, num_n_words));

            ReadOnlySpan<ulong> point = points[Convert.ToUInt64(VLI_Logic.TestBit(u1, num_bits - 1)) | (Convert.ToUInt64(VLI_Logic.TestBit(u2, num_bits - 1)) << 1)];
            VLI_Arithmetic.Set(rx, point, num_words);
            VLI_Arithmetic.Set(ry, point.Slice(num_words), num_words);
            VLI_Arithmetic.Clear(z, num_words);
            z[0] = 1;

            for (int i = num_bits - 2; i >= 0; --i)
            {
                curve.DoubleJacobian(rx, ry, z);

                ulong index = Convert.ToUInt64(VLI_Logic.TestBit(u1, i)) | (Convert.ToUInt64(VLI_Logic.TestBit(u2, i)) << 1);
                point = points[index];
                if (!point.IsEmpty)
                {
                    VLI_Arithmetic.Set(tx, point, num_words);
                    VLI_Arithmetic.Set(ty, point.Slice(num_words), num_words);
                    ECCUtil.ApplyZ(curve, tx, ty, z);
                    VLI_Arithmetic.ModSub(tz, rx, tx, curve.p, num_words); // Z = x2 - x1
                    ECCUtil.XYcZ_Add(curve, tx, ty, rx, ry);
                    curve.ModMult(z, z, tz);
                }
            }

            VLI_Arithmetic.ModInv(z, z, curve.p, num_words); // Z = 1/Z
            ECCUtil.ApplyZ(curve, rx, ry, z);

            // v = x1 (mod n)
            if (VLI_Logic.CmpUnsafe(curve.n, rx, num_n_words) != 1)
            {
                VLI_Arithmetic.Sub(rx, rx, curve.n, num_n_words);
            }

            // Accept only if v == r.
            return VLI_Logic.Equal(rx, r, num_words);
        }

        /// <summary>
        /// Verify a compact ECDSA signature.
        /// Usage: Compute the hash of the signed data using the same hash as the signer and
        /// pass it to this function along with the signer's public key and the signature values (r and s).
        /// </summary>
        /// <param name="signature">The compact signature object</param>
        /// <param name="public_key">The signer's public key</param>
        /// <param name="message_hash">The hash of the signed data</param>
        /// <returns></returns>
        public static bool VerifySignature(ECCurve curve, CompactSignature signature, ReadOnlySpan<byte> public_key, ReadOnlySpan<byte> message_hash)
        {
            return VerifySignature(curve, signature.r, signature.s, public_key, message_hash);
        }

        /// <summary>
        /// Verify a DER formatted ECDSA signature.
        /// Usage: Compute the hash of the signed data using the same hash as the signer and
        /// pass it to this function along with the signer's public key and the signature values (r and s).
        /// </summary>
        /// <param name="signature">The compact signature object</param>
        /// <param name="public_key">The signer's public key</param>
        /// <param name="message_hash">The hash of the signed data</param>
        /// <returns></returns>
        public static bool VerifySignature(ECCurve curve, DERSignature signature, ReadOnlySpan<byte> public_key, ReadOnlySpan<byte> message_hash)
        {
            return VerifySignature(curve, signature.r, signature.s, public_key, message_hash);
        }

        private static void BitsToInt(ECCurve curve, Span<ulong> native, ReadOnlySpan<byte> bits, int bits_size)
        {
            int num_n_bytes = curve.NUM_N_BYTES;
            int num_n_words = curve.NUM_WORDS;
            int num_n_bits = curve.NUM_N_BITS;

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
            if (VLI_Logic.CmpUnsafe(curve.n, native, num_n_words) != 1)
            {
                VLI_Arithmetic.Sub(native, native, curve.n, num_n_words);
            }
        }
    }
}
