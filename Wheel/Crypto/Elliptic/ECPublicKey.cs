using System.Security.Cryptography.X509Certificates;
using Wheel.Crypto.Elliptic.Internal;
using Wheel.Crypto.Elliptic.Internal.VeryLongInt;

namespace Wheel.Crypto.Elliptic
{
	public ref struct ECPublicKey
	{
        /// <summary>
        /// The secret key funcions are using slices that are being made from this hidden array.
        /// </summary>
        internal unsafe fixed ulong public_key_data[VLI_Common.ECC_MAX_WORDS * 2];

        /// <summary>
        /// ECC implementation to use
        /// </summary>
        private ECCurve curve { get; }

        /// <summary>
        /// Access to native point data
        /// </summary>
        private Span<ulong> native_point { get; }

        /// <summary>
        /// Construct the empty key
        /// </summary>
        /// <param name="curve">ECC implementation</param>
        public ECPublicKey(ECCurve curve)
		{
            this.curve = curve;
            unsafe
            {
                fixed (ulong* ptr = &public_key_data[0])
                {
                    native_point = new(ptr, curve.NUM_BYTES * 2);
                }
            }
        }

        /// <summary>
        /// Does this instance contain a valid key or not
        /// </summary>
        public readonly bool IsValid
        {
            get => ECCPoint.IsValid(curve, native_point);
        }

        /// <summary>
        /// Erase object state
        /// </summary>
        public unsafe void Reset()
        {
            // Erase current data
            VLI_Arithmetic.Clear(native_point, curve.NUM_WORDS);
        }

        /// <summary>
        /// Dump the native point data
        /// </summary>
        /// <param name="native"></param>
        /// <returns>True if point is valid and copying has been successful</returns>
        public readonly bool UnWrap(ref Span<ulong> native_out)
        {
            if (!IsValid || native_out.Length != curve.NUM_WORDS * 2)
            {
                return false;
            }

            VLI_Arithmetic.Set(native_out, native_point, curve.NUM_WORDS * 2);

            return true;
        }

        /// <summary>
        /// Check to see if a serialized public key is valid.
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
        /// Decode ECC point to initialize the instance with native point data
        /// </summary>
        /// <param name="serialized"></param>
        /// <returns>True if the data is valid and initialization has been successful</returns>
        public bool Parse(in ReadOnlySpan<byte> public_key)
        {
            Reset();

            if (public_key.Length != 2 * curve.NUM_BYTES)
            {
                return false;
            }

            Span<ulong> _public = stackalloc ulong[VLI_Common.ECC_MAX_WORDS * 2];
            VLI_Conversion.BytesToNative(_public, public_key, curve.NUM_BYTES);
            VLI_Conversion.BytesToNative(_public.Slice(curve.NUM_WORDS), public_key.Slice(curve.NUM_BYTES), curve.NUM_BYTES);

            // Make sure that the decoded public key is valid
            if (!ECCPoint.IsValid(curve, _public))
            {
                return false;
            }

            // Set new public key
            VLI_Arithmetic.Set(native_point, _public, curve.NUM_WORDS * 2);

            return true;
        }

        public bool Decompress(in ReadOnlySpan<byte> compressed)
        {
            Reset();

            if (compressed.Length != (1 + curve.NUM_BYTES) || compressed[0] != 0x02 || compressed[0] != 0x03)
            {
                return false;
            }

            Span<ulong> point = stackalloc ulong[2 * VLI_Common.ECC_MAX_WORDS];
            Span<ulong> y = point.Slice(curve.NUM_WORDS);

            VLI_Conversion.BytesToNative(point, compressed.Slice(1), curve.NUM_BYTES);
            curve.XSide(y, point);
            ECCUtil.ModSQRT(y, curve);

            if ((y[0] & 0x01) != ((ulong)compressed[0] & 0x01))
            {
                VLI_Arithmetic.Sub(y, curve.p, y, curve.NUM_WORDS);
            }

            // Make sure that the decoded public key is valid
            if (!ECCPoint.IsValid(curve, point))
            {
                return false;
            }

            // Set new public key
            VLI_Arithmetic.Set(native_point, point, curve.NUM_WORDS * 2);

            return true;
        }

        /// <summary>
        /// Serialize the native key into a pair of big endian numbers
        /// </summary>
        /// <param name="serialized"></param>
        /// <returns>True if successful and this key is valid</returns>
        public readonly bool Serialize(Span<byte> serialized)
        {
            if (!IsValid || serialized.Length != curve.NUM_BYTES * 2)
            {
                return false;
            }

            VLI_Conversion.NativeToBytes(serialized, curve.NUM_BYTES, native_point);
            VLI_Conversion.NativeToBytes(serialized.Slice(curve.NUM_BYTES), curve.NUM_BYTES, native_point.Slice(curve.NUM_WORDS));

            return true;
        }

        /// <summary>
        /// Serialize the native key into a compressed point
        /// </summary>
        /// <param name="serialized"></param>
        /// <returns>True if successful and this key is valid</returns>
        public readonly bool Compress(Span<byte> compressed)
        {
            if (!IsValid || compressed.Length != (curve.NUM_BYTES + 1))
            {
                return false;
            }

            Span<byte> public_key = stackalloc byte[curve.NUM_BYTES * 2];

            // Serialize, then generate compressed version
            if (!Serialize(public_key))
            {
                return false;
            }

            for (int i = 0; i < curve.NUM_BYTES; ++i)
            {
                compressed[i + 1] = public_key[i];
            }
            compressed[0] = (byte)(2 + (public_key[curve.NUM_BYTES * 2 - 1] & 0x01));

            return true;
        }

        /// <summary>
        /// EC public key tweak by scalar
        /// </summary>
        /// <param name="result"></param>
        /// <param name="scalar"></param>
        /// <returns></returns>
        public readonly bool KeyTweak(ref ECPublicKey result, in ReadOnlySpan<byte> scalar)
        {
            // Make sure that public key is valid
            if (!IsValid)
            {
                return false;
            }

            Span<ulong> _result = stackalloc ulong[VLI_Common.ECC_MAX_WORDS * 2];
            Span<ulong> _s_mul_G = stackalloc ulong[VLI_Common.ECC_MAX_WORDS * 2];
            Span<ulong> _scalar = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];

            VLI_Conversion.BytesToNative(_scalar, scalar, curve.NUM_N_BYTES);

            // Public key is computed by multiplication i.e. scalar*G is what we need
            if (!ECCPoint.ComputePublicPoint(curve, _s_mul_G, _scalar))
            {
                return false;
            }

            // R = A + scalar*G
            ECCPoint.PointAdd(curve, _result, native_point, _s_mul_G);

            // Ensure that new public key is valid as well
            if (!ECCPoint.IsValid(curve, _result))
            {
                return false;
            }

            // Copy calculated key
            VLI_Arithmetic.Set(result.native_point, _result, curve.NUM_BYTES * 2);

            return true;
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
        public readonly bool VerifySignature(in ReadOnlySpan<ulong> r, in ReadOnlySpan<ulong> s, in ReadOnlySpan<byte> message_hash)
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

            int num_bytes = curve.NUM_BYTES;
            int num_words = curve.NUM_WORDS;
            int num_n_words = curve.NUM_N_WORDS;

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
            ECCUtil.BitsToInt(curve, u1, message_hash, message_hash.Length);
            VLI_Arithmetic.ModMult(u1, u1, z, curve.n, num_n_words); // u1 = e/s
            VLI_Arithmetic.ModMult(u2, r, z, curve.n, num_n_words); // u2 = r/s

            // Calculate sum = G + Q.
            VLI_Arithmetic.Set(sum, native_point, num_words);
            VLI_Arithmetic.Set(sum.Slice(num_words), native_point.Slice(num_words), num_words);
            VLI_Arithmetic.Set(tx, curve.G, num_words);
            VLI_Arithmetic.Set(ty, curve.G.Slice(num_words), num_words);
            VLI_Arithmetic.ModSub(z, sum, tx, curve.p, num_words); // z = x2 - x1
            ECCUtil.XYcZ_Add(curve, tx, ty, sum, sum.Slice(num_words));
            VLI_Arithmetic.ModInv(z, z, curve.p, num_words); // z = 1/z
            ECCUtil.ApplyZ(curve, sum, sum.Slice(num_words), z);

            /* Use Shamir's trick to calculate u1*G + u2*Q */
            VLI_Common.QuadPicker points = new(null, curve.G, native_point, sum);
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
        /// <param name="message_hash">The hash of the signed data</param>
        /// <returns></returns>
        public readonly bool VerifySignature(CompactSignature signature, ReadOnlySpan<byte> message_hash)
        {
            return VerifySignature(signature.r, signature.s, message_hash);
        }

        /// <summary>
        /// Verify a DER formatted ECDSA signature.
        /// Usage: Compute the hash of the signed data using the same hash as the signer and
        /// pass it to this function along with the signer's public key and the signature values (r and s).
        /// </summary>
        /// <param name="signature">The compact signature object</param>
        /// <param name="message_hash">The hash of the signed data</param>
        /// <returns></returns>
        public readonly bool VerifySignature(DERSignature signature, ReadOnlySpan<byte> message_hash)
        {
            return VerifySignature(signature.r, signature.s, message_hash);
        }
    }
}

