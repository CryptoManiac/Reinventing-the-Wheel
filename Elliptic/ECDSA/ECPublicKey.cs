using Wheel.Crypto.Elliptic.ECDSA.Internal;
using Wheel.Crypto.Elliptic.EllipticCommon;
using Wheel.Crypto.Elliptic.EllipticCommon.VeryLongInt;

namespace Wheel.Crypto.Elliptic.ECDSA
{
	public struct ECPublicKey : IPublicKey
	{
        /// <summary>
        /// The secret key funcions are using slices that are being made from this hidden array.
        /// </summary>
        internal unsafe fixed ulong public_key_data[VLI.ECC_MAX_WORDS * 2];

        /// <summary>
        /// Local copy of EC implementation instance
        /// </summary>
        private readonly ECCurve _curve;

        /// <summary>
        /// ECC implementation to use (exposed to users)
        /// </summary>
        public readonly ICurve curve => _curve;

        /// <summary>
        /// Encoded key size in bytes
        /// </summary>
        public readonly int EncodedSize => GetEncodedSize(_curve);

        /// <summary>
        /// Encoded key size in bytes
        /// </summary>
        public readonly int CompressedSize => GetCompressedSize(_curve);

        /// <summary>
        /// Access to native point data
        /// </summary>
        private readonly unsafe Span<ulong> native_point
        {
            get
            {
                fixed (ulong* ptr = &public_key_data[0])
                {
                    return new Span<ulong>(ptr, _curve.NUM_WORDS * 2);
                }
            }
        }

        /// <summary>
        /// The default constructor should never be called
        /// </summary>
        /// <exception cref="SystemException"></exception>
        public ECPublicKey()
        {
            throw new SystemException("The default constructor should never be called");
        }

        /// <summary>
        /// Construct the empty key
        /// </summary>
        /// <param name="curve">ECC implementation</param>
        public ECPublicKey(in ICurve curve)
		{
            if (curve is not ECCurve)
            {
                // Shouldn't happen in real life
                throw new InvalidOperationException("Invalid curve implementation instance");
            }

            _curve = (ECCurve) curve;

            // Init with zeros
            Reset();
        }

        /// <summary>
        /// Construct the empty key
        /// </summary>
        /// <param name="curve">ECC implementation</param>
        public ECPublicKey(in ICurve curve, ReadOnlySpan<byte> public_key) : this(curve)
        {
            if (!Parse(public_key))
            {
                throw new InvalidDataException("Provided public key is not valid");
            }
        }

        /// <summary>
        /// Construct the key using VLI value
        /// </summary>
        /// <param name="curve">ECC implementation</param>
        public ECPublicKey(in ICurve curve, ReadOnlySpan<ulong> public_point) : this(curve)
        {
            if (!Wrap(public_point))
            {
                throw new InvalidDataException("Provided public point is not valid");
            }
        }

        /// <summary>
        /// Does this instance contain a valid key or not
        /// </summary>
        public readonly bool IsValid
        {
            get => ECCPoint.IsValid(_curve, native_point);
        }

        /// <summary>
        /// Erase object state
        /// </summary>
        public void Reset()
        {
            // Erase current data
            VLI.Clear(native_point, _curve.NUM_WORDS * 2);
        }

        /// <summary>
        /// Dump the native point data
        /// </summary>
        /// <param name="native"></param>
        /// <returns>True if point is valid and copying has been successful</returns>
        public readonly bool UnWrap(Span<ulong> native_out)
        {
            if (!IsValid || native_out.Length != _curve.NUM_WORDS * 2)
            {
                return false;
            }

            VLI.Set(native_out, native_point, _curve.NUM_WORDS * 2);

            return true;
        }

        /// <summary>
        /// Set native point data to given value
        /// </summary>
        /// <param name="native_in"></param>
        /// <returns>True if point is valid and copying has been successful</returns>
        public bool Wrap(ReadOnlySpan<ulong> native_in)
        {
            if (native_in.Length != _curve.NUM_WORDS * 2)
            {
                return false;
            }

            if (!ECCPoint.IsValid(_curve, native_in))
            {
                return false;
            }

            VLI.Set(native_point, native_in, _curve.NUM_WORDS * 2);
            return true;
        }

        /// <summary>
        /// Check to see if a serialized or compressed public key is valid.
        /// Note that you are not required to check for a valid public key before using any other 
        /// functions. However, you may wish to avoid spending CPU time computing a shared secret or
        /// verifying a signature using an invalid public key.
        /// </summary>
        /// <param name="public_key">The public key to check.</param>
        /// <returns>True if key is valid</returns>
        public static bool IsValidPublicKey(ICurve curve, ReadOnlySpan<byte> public_key)
        {
            if (curve is not ECCurve)
            {
                // Shouldn't happen in real life
                throw new InvalidOperationException("Invalid curve implementation instance");
            }

            ECPublicKey pk = new(curve);
            return pk.Parse(public_key) || pk.Decompress(public_key);
        }

        /// <summary>
        /// Size of encoded public key for a given curve
        /// </summary>
        /// <param name="curve"></param>
        /// <returns>Number of bytes</returns>
        public static int GetEncodedSize(ICurve curve)
        {
            return 2 * curve.NUM_N_BYTES;
        }

        /// <summary>
        /// Size of compressed public key for a given curve
        /// </summary>
        /// <param name="curve"></param>
        /// <returns>Number of bytes</returns>
        public static int GetCompressedSize(ICurve curve)
        {
            return 1 + curve.NUM_N_BYTES;
        }

        /// <summary>
        /// Decode ECC point to initialize the instance with native point data
        /// </summary>
        /// <param name="serialized"></param>
        /// <returns>True if the data is valid and initialization has been successful</returns>
        public bool Parse(ReadOnlySpan<byte> serialized)
        {
            Reset();

            if (serialized.Length != 2 * _curve.NUM_N_BYTES)
            {
                return false;
            }

            Span<ulong> _public = stackalloc ulong[VLI.ECC_MAX_WORDS * 2];
            VLI.BytesToNative(_public, serialized, _curve.NUM_N_BYTES);
            VLI.BytesToNative(_public.Slice(_curve.NUM_N_WORDS), serialized.Slice(_curve.NUM_N_BYTES), _curve.NUM_N_BYTES);
            return Wrap(_public);
        }

        public bool Decompress(ReadOnlySpan<byte> compressed)
        {
            Reset();

            if (compressed.Length != (1 + _curve.NUM_BYTES) || compressed[0] != 0x02 || compressed[0] != 0x03)
            {
                return false;
            }

            Span<ulong> point = stackalloc ulong[2 * VLI.ECC_MAX_WORDS];
            Span<ulong> y = point.Slice(_curve.NUM_N_WORDS);

            VLI.BytesToNative(point, compressed.Slice(1), _curve.NUM_N_BYTES);
            _curve.XSide(y, point);
            _curve.ModSQRT(y);

            if ((y[0] & 0x01) != ((ulong)compressed[0] & 0x01))
            {
                VLI.Sub(y, _curve.p, y, _curve.NUM_N_WORDS);
            }

            return Wrap(point);
        }

        /// <summary>
        /// Serialize the native key into a pair of big endian numbers
        /// </summary>
        /// <param name="serialized"></param>
        /// <returns>True if successful and this key is valid</returns>
        public readonly bool Serialize(Span<byte> serialized)
        {
            if (!IsValid || serialized.Length != _curve.NUM_N_BYTES * 2)
            {
                return false;
            }

            VLI.NativeToBytes(serialized, _curve.NUM_N_BYTES, native_point);
            VLI.NativeToBytes(serialized.Slice(_curve.NUM_N_BYTES), _curve.NUM_N_BYTES, native_point.Slice(_curve.NUM_N_WORDS));

            return true;
        }

        /// <summary>
        /// Serialize the native key into a compressed point
        /// </summary>
        /// <param name="compressed"></param>
        /// <returns>True if successful and this key is valid</returns>
        public readonly bool Compress(Span<byte> compressed)
        {
            if (!IsValid || compressed.Length != (_curve.NUM_N_BYTES + 1))
            {
                return false;
            }

            Span<byte> public_key = stackalloc byte[_curve.NUM_N_BYTES * 2];

            // Serialize, then generate compressed version
            if (!Serialize(public_key))
            {
                return false;
            }

            for (int i = 0; i < _curve.NUM_N_BYTES; ++i)
            {
                compressed[i + 1] = public_key[i];
            }
            compressed[0] = (byte)(2 + (public_key[_curve.NUM_N_BYTES * 2 - 1] & 0x01));

            return true;
        }

        /// <summary>
        /// EC public key tweak by scalar
        /// </summary>
        /// <param name="result"></param>
        /// <param name="scalar"></param>
        /// <returns></returns>
        public readonly bool KeyTweak(out IPublicKey result, ReadOnlySpan<byte> scalar)
        {
            result = new ECPublicKey(_curve);

            // Make sure that public key is valid
            if (!IsValid)
            {
                return false;
            }

            Span<ulong> _result = stackalloc ulong[VLI.ECC_MAX_WORDS * 2];
            Span<ulong> _s_mul_G = stackalloc ulong[VLI.ECC_MAX_WORDS * 2];
            Span<ulong> _scalar = stackalloc ulong[VLI.ECC_MAX_WORDS];

            VLI.BytesToNative(_scalar, scalar, _curve.NUM_N_BYTES);

            // Public key is computed by multiplication i.e. scalar*G is what we need
            if (!ECCPoint.ComputePublicPoint(_curve, _s_mul_G, _scalar))
            {
                return false;
            }

            // R = A + scalar*G
            ECCPoint.PointAdd(_curve, _result, native_point, _s_mul_G);

            // Try to wrap the resulting point data
            return result.Wrap(_result);
        }

        /// <summary>
        /// Verify an ECDSA signature.
        /// Usage: Compute the hash of the signed data using the same hash as the signer and
        /// pass it to this function along with the signer's public key and the signature values (r and s).
        /// </summary>
        /// <param name="r"></param>
        /// <param name="s"></param>
        /// <param name="message_hash"></param>
        /// <returns></returns>
        private readonly bool VerifySignature(ReadOnlySpan<ulong> r, ReadOnlySpan<ulong> s, ReadOnlySpan<byte> message_hash)
        {
            Span<ulong> u1 = stackalloc ulong[VLI.ECC_MAX_WORDS];
            Span<ulong> u2 = stackalloc ulong[VLI.ECC_MAX_WORDS];
            Span<ulong> z = stackalloc ulong[VLI.ECC_MAX_WORDS];
            Span<ulong> sum = stackalloc ulong[VLI.ECC_MAX_WORDS * 2];

            Span<ulong> rx = stackalloc ulong[VLI.ECC_MAX_WORDS];
            Span<ulong> ry = stackalloc ulong[VLI.ECC_MAX_WORDS];
            Span<ulong> tx = stackalloc ulong[VLI.ECC_MAX_WORDS];
            Span<ulong> ty = stackalloc ulong[VLI.ECC_MAX_WORDS];
            Span<ulong> tz = stackalloc ulong[VLI.ECC_MAX_WORDS];

            int num_bytes = _curve.NUM_BYTES;
            int num_words = _curve.NUM_WORDS;
            int num_n_words = _curve.NUM_N_WORDS;

            // r, s must not be 0
            if (VLI.IsZero(r, num_words) || VLI.IsZero(s, num_words))
            {
                return false;
            }

            // r, s must be < n.
            if (VLI.VarTimeCmp(_curve.n, r, num_n_words) != 1 || VLI.VarTimeCmp(_curve.n, s, num_n_words) != 1)
            {
                return false;
            }

            // Calculate u1 and u2.
            VLI.ModInv(z, s, _curve.n, num_n_words); // z = 1/s
            u1[num_n_words - 1] = 0;
            ECCUtil.BitsToInt(_curve, u1, message_hash, message_hash.Length);
            VLI.ModMult(u1, u1, z, _curve.n, num_n_words); // u1 = e/s
            VLI.ModMult(u2, r, z, _curve.n, num_n_words); // u2 = r/s

            // Calculate sum = G + Q.
            VLI.Set(sum, native_point, num_words);
            VLI.Set(sum.Slice(num_words), native_point.Slice(num_words), num_words);
            VLI.Set(tx, _curve.G, num_words);
            VLI.Set(ty, _curve.G.Slice(num_words), num_words);
            VLI.ModSub(z, sum, tx, _curve.p, num_words); // z = x2 - x1
            ECCUtil.XYcZ_Add(_curve, tx, ty, sum, sum.Slice(num_words));
            VLI.ModInv(z, z, _curve.p, num_words); // z = 1/z
            ECCUtil.ApplyZ(_curve, sum, sum.Slice(num_words), z);

            /* Use Shamir's trick to calculate u1*G + u2*Q */
            VLI.QuadPicker points = new(null, _curve.G, native_point, sum);
            int num_bits = int.Max(VLI.NumBits(u1, num_n_words), VLI.NumBits(u2, num_n_words));

            ReadOnlySpan<ulong> point = points[Convert.ToUInt64(VLI.TestBit(u1, num_bits - 1)) | (Convert.ToUInt64(VLI.TestBit(u2, num_bits - 1)) << 1)];
            VLI.Set(rx, point, num_words);
            VLI.Set(ry, point.Slice(num_words), num_words);
            VLI.Clear(z, num_words);
            z[0] = 1;

            for (int i = num_bits - 2; i >= 0; --i)
            {
                _curve.DoubleJacobian(rx, ry, z);

                ulong index = Convert.ToUInt64(VLI.TestBit(u1, i)) | (Convert.ToUInt64(VLI.TestBit(u2, i)) << 1);
                point = points[index];
                if (!point.IsEmpty)
                {
                    VLI.Set(tx, point, num_words);
                    VLI.Set(ty, point.Slice(num_words), num_words);
                    ECCUtil.ApplyZ(_curve, tx, ty, z);
                    VLI.ModSub(tz, rx, tx, _curve.p, num_words); // Z = x2 - x1
                    ECCUtil.XYcZ_Add(_curve, tx, ty, rx, ry);
                    _curve.ModMult(z, z, tz);
                }
            }

            VLI.ModInv(z, z, _curve.p, num_words); // Z = 1/Z
            ECCUtil.ApplyZ(_curve, rx, ry, z);

            // v = x1 (mod n)
            if (VLI.VarTimeCmp(_curve.n, rx, num_n_words) != 1)
            {
                VLI.Sub(rx, rx, _curve.n, num_n_words);
            }

            // Accept only if v == r.
            return VLI.Equal(rx, r, num_words);
        }

        /// <summary>
        /// Verify an ECDSA signature.
        /// Usage: Compute the hash of the signed data using the same hash as the signer and
        /// pass it to this function along with the signer's public key and the signature values (r and s).
        /// </summary>
        /// <param name="signature">The signature object</param>
        /// <param name="message_hash">The hash of the signed data</param>
        /// <returns></returns>
        public readonly bool VerifySignature(ISignature signature, ReadOnlySpan<byte> message_hash)
        {
            if (signature.curve is not ECCurve)
            {
                // Shouldn't happen in real life
                throw new InvalidOperationException("Invalid curve implementation instance");
            }

            return (_curve == (ECCurve)signature.curve) && VerifySignature(signature.r, signature.s, message_hash);
        }
    }
}

