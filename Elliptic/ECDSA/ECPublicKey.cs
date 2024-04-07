using System.Runtime.CompilerServices;
using Wheel.Crypto.Elliptic.EllipticCommon;
using Wheel.Crypto.Elliptic.ECDSA.Internal;

namespace Wheel.Crypto.Elliptic.ECDSA;

	public struct ECPublicKey : IPublicKey
	{
    /// <summary>
    /// The secret key funcions are using slices that are being made from this hidden array.
    /// </summary>
    internal unsafe fixed ulong public_key_data[VLI.ECC_MAX_WORDS * 2];

    /// <summary>
    /// Local copy of EC implementation instance
    /// </summary>
    private readonly SECPCurve _curve;

    /// <summary>
    /// ECC implementation to use (exposed to users)
    /// </summary>
    public readonly IGenericCurve curve => _curve;

    /// <summary>
    /// Encoded key size in bytes
    /// </summary>
    public readonly int EncodedSize => GetUncompressedSize(_curve);

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
    public ECPublicKey(in IGenericCurve curve)
		{
        if (curve is not SECPCurve)
        {
            // Shouldn't happen in real life
            throw new InvalidOperationException("Invalid curve implementation instance");
        }

        _curve = (SECPCurve) curve;

        // Init with zeros
        Reset();
    }

    /// <summary>
    /// Construct the empty key
    /// </summary>
    /// <param name="curve">ECC implementation</param>
    public ECPublicKey(in IGenericCurve curve, ReadOnlySpan<byte> public_key) : this(curve)
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
    public ECPublicKey(in IGenericCurve curve, ReadOnlySpan<ulong> public_point) : this(curve)
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
        get => _curve.IsValidPoint(native_point);
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

        if (!_curve.IsValidPoint(native_in))
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
    public static bool IsValidPublicKey(IGenericCurve curve, ReadOnlySpan<byte> public_key)
    {
        if (curve is not SECPCurve)
        {
            // Shouldn't happen in real life
            throw new InvalidOperationException("Invalid curve implementation instance");
        }

        ECPublicKey pk = new(curve);
        return pk.Parse(public_key) || pk.Decompress(public_key);
    }

    /// <summary>
    /// Size of uncompressed public key for a given curve
    /// </summary>
    /// <param name="curve"></param>
    /// <returns>Number of bytes</returns>
    public static int GetUncompressedSize(SECPCurve curve)
    {
        return 2 * curve.NUM_BYTES;
    }

    /// <summary>
    /// Size of compressed public key for a given curve
    /// </summary>
    /// <param name="curve"></param>
    /// <returns>Number of bytes</returns>
    public static int GetCompressedSize(SECPCurve curve)
    {
        return 1 + curve.NUM_BYTES;
    }

    /// <summary>
    /// Decode ECC point to initialize the instance with native point data
    /// </summary>
    /// <param name="serialized"></param>
    /// <returns>True if the data is valid and initialization has been successful</returns>
    [SkipLocalsInit]
    public bool Parse(ReadOnlySpan<byte> serialized)
    {
        Reset();

        if (serialized.Length != 2 * _curve.NUM_BYTES)
        {
            return false;
        }

        Span<ulong> _public = stackalloc ulong[_curve.NUM_WORDS * 2];
        VLI.BytesToNative(_public, serialized, _curve.NUM_BYTES);
        VLI.BytesToNative(_public[_curve.NUM_WORDS..], serialized[_curve.NUM_BYTES..], _curve.NUM_BYTES);
        return Wrap(_public);
    }

    [SkipLocalsInit]
    public bool Decompress(ReadOnlySpan<byte> compressed)
    {
        Reset();

        if (compressed.Length != (1 + _curve.NUM_BYTES) || (compressed[0] != 0x02 && compressed[0] != 0x03))
        {
            return false;
        }

        Span<ulong> point = stackalloc ulong[2 * _curve.NUM_WORDS];
        Span<ulong> y = point[_curve.NUM_WORDS..];

        VLI.BytesToNative(point, compressed[1..], _curve.NUM_BYTES);
        _curve.XSide(y, point);
        _curve.ModSQRT(y);

        if ((y[0] & 0x01) != ((ulong)compressed[0] & 0x01))
        {
            VLI.Sub(y, _curve.P, y, _curve.NUM_WORDS);
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
        if (!IsValid || serialized.Length != _curve.NUM_BYTES * 2)
        {
            return false;
        }

        VLI.NativeToBytes(serialized, _curve.NUM_BYTES, native_point);
        VLI.NativeToBytes(serialized[_curve.NUM_BYTES..], _curve.NUM_BYTES, native_point[_curve.NUM_WORDS..]);

        return true;
    }

    /// <summary>
    /// Serialize the native key into a compressed point
    /// </summary>
    /// <param name="compressed"></param>
    /// <returns>True if successful and this key is valid</returns>
    [SkipLocalsInit]
    public readonly bool Compress(Span<byte> compressed)
    {
        if (!IsValid || compressed.Length != (_curve.NUM_BYTES + 1))
        {
            return false;
        }

        Span<byte> public_key = stackalloc byte[_curve.NUM_BYTES * 2];

        // Serialize, then generate compressed version
        if (!Serialize(public_key))
        {
            return false;
        }

        for (int i = 0; i < _curve.NUM_BYTES; ++i)
        {
            compressed[i + 1] = public_key[i];
        }
        compressed[0] = (byte)(2 + (public_key[_curve.NUM_BYTES * 2 - 1] & 0x01));

        return true;
    }

    /// <summary>
    /// EC public key tweak by scalar
    /// </summary>
    /// <param name="result"></param>
    /// <param name="scalar"></param>
    /// <returns></returns>
    [SkipLocalsInit]
    public readonly bool KeyTweak(out ECPublicKey result, ReadOnlySpan<byte> scalar)
    {
        result = new ECPublicKey(_curve);

        // Make sure that public key is valid
        if (!IsValid)
        {
            return false;
        }

        Span<ulong> _result = stackalloc ulong[_curve.NUM_WORDS * 2];
        Span<ulong> _s_mul_G = stackalloc ulong[_curve.NUM_WORDS * 2];
        Span<ulong> _scalar = stackalloc ulong[_curve.NUM_WORDS];

        VLI.BytesToNative(_scalar, scalar, _curve.NUM_BYTES);

        // Public key is computed by multiplication i.e. scalar*G is what we need
        if (!_curve.ComputePublicPoint(_s_mul_G, _scalar))
        {
            return false;
        }

        // R = A + scalar*G
        _curve.PointAdd(_result, native_point, _s_mul_G);

        // Try to wrap the resulting point data
        return result.Wrap(_result);
    }


    /// <summary>
    /// EC public key tweak by scalar
    /// </summary>
    /// <param name="outKey"></param>
    /// <param name="scalar"></param>
    /// <returns></returns>
    [SkipLocalsInit]
    public readonly bool KeyTweak(out IPublicKey outKey, ReadOnlySpan<byte> scalar)
    {
        bool result = KeyTweak(out ECPublicKey generatedKey, scalar);
        outKey = generatedKey;
        return result;
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
    [SkipLocalsInit]
    private readonly bool VerifySignature(ReadOnlySpan<ulong> r, ReadOnlySpan<ulong> s, ReadOnlySpan<byte> message_hash)
    {
        Span<ulong> u1 = stackalloc ulong[_curve.NUM_WORDS];
        Span<ulong> u2 = stackalloc ulong[_curve.NUM_WORDS];
        Span<ulong> z = stackalloc ulong[_curve.NUM_WORDS];
        Span<ulong> sum = stackalloc ulong[_curve.NUM_WORDS * 2];

        Span<ulong> rx = stackalloc ulong[_curve.NUM_WORDS];
        Span<ulong> ry = stackalloc ulong[_curve.NUM_WORDS];
        Span<ulong> tx = stackalloc ulong[_curve.NUM_WORDS];
        Span<ulong> ty = stackalloc ulong[_curve.NUM_WORDS];
        Span<ulong> tz = stackalloc ulong[_curve.NUM_WORDS];


        // r, s must not be 0
        if (VLI.IsZero_VT(r, _curve.NUM_WORDS) || VLI.IsZero_VT(s, _curve.NUM_WORDS))
        {
            return false;
        }

        // r, s must be < n.
        if (VLI.Cmp_VT(_curve.N, r, _curve.NUM_WORDS) != 1 || VLI.Cmp_VT(_curve.N, s, _curve.NUM_WORDS) != 1)
        {
            return false;
        }

        // Calculate u1 and u2.
        VLI.ModInv(z, s, _curve.N, _curve.NUM_WORDS); // z = 1/s
        u1[_curve.NUM_WORDS - 1] = 0;
        _curve.BitsToInt(u1, message_hash, message_hash.Length);
        VLI.ModMult(u1, u1, z, _curve.N, _curve.NUM_WORDS); // u1 = e/s
        VLI.ModMult(u2, r, z, _curve.N, _curve.NUM_WORDS); // u2 = r/s

        // Calculate sum = G + Q.
        VLI.Set(sum, native_point, _curve.NUM_WORDS);
        VLI.Set(sum[_curve.NUM_WORDS..], native_point[_curve.NUM_WORDS..], _curve.NUM_WORDS);
        VLI.Set(tx, _curve.G, _curve.NUM_WORDS);
        VLI.Set(ty, _curve.G[_curve.NUM_WORDS..], _curve.NUM_WORDS);
        VLI.ModSub(z, sum, tx, _curve.P, _curve.NUM_WORDS); // z = x2 - x1
        _curve.XYcZ_Add(tx, ty, sum, sum[_curve.NUM_WORDS..]);
        VLI.ModInv(z, z, _curve.P, _curve.NUM_WORDS); // z = 1/z
        _curve.ApplyZ(sum, sum[_curve.NUM_WORDS..], z);

        // Use Shamir's trick to calculate u1*G + u2*Q
        VLI.QuadPicker points = new(null, _curve.G, native_point, sum);
        int num_bits = int.Max(VLI.NumBits_VT(u1, _curve.NUM_WORDS), VLI.NumBits_VT(u2, _curve.NUM_WORDS));

        ReadOnlySpan<ulong> point = points[Convert.ToUInt64(VLI.TestBit(u1, num_bits - 1)) | (Convert.ToUInt64(VLI.TestBit(u2, num_bits - 1)) << 1)];
        VLI.Set(rx, point, _curve.NUM_WORDS);
        VLI.Set(ry, point[_curve.NUM_WORDS..], _curve.NUM_WORDS);
        VLI.Set(z, 1, _curve.NUM_WORDS);

        for (int i = num_bits - 2; i >= 0; --i)
        {
            _curve.DoubleJacobian(rx, ry, z);

            ulong index = Convert.ToUInt64(VLI.TestBit(u1, i)) | (Convert.ToUInt64(VLI.TestBit(u2, i)) << 1);
            point = points[index];
            if (!point.IsEmpty)
            {
                VLI.Set(tx, point, _curve.NUM_WORDS);
                VLI.Set(ty, point[_curve.NUM_WORDS..], _curve.NUM_WORDS);
                _curve.ApplyZ(tx, ty, z);
                VLI.ModSub(tz, rx, tx, _curve.P, _curve.NUM_WORDS); // Z = x2 - x1
                _curve.XYcZ_Add(tx, ty, rx, ry);
                _curve.ModMult(z, z, tz);
            }
        }

        VLI.ModInv(z, z, _curve.P, _curve.NUM_WORDS); // Z = 1/Z
        _curve.ApplyZ(rx, ry, z);

        // v = x1 (mod n)
        if (VLI.Cmp_VT(_curve.N, rx, _curve.NUM_WORDS) != 1)
        {
            VLI.Sub(rx, rx, _curve.N, _curve.NUM_WORDS);
        }

        // Accept only if v == r.
        return VLI.Equal_VT(rx, r, _curve.NUM_WORDS);
    }

    /// <summary>
    /// Verify an ECDSA signature.
    /// Usage: Compute the hash of the signed data using the same hash as the signer and
    /// pass it to this function along with the signer's public key and the signature values (r and s).
    /// </summary>
    /// <param name="signature">The signature object</param>
    /// <param name="message_hash">The hash of the signed data</param>
    /// <returns></returns>
    public readonly bool VerifySignature(DERSignature signature, ReadOnlySpan<byte> message_hash)
    {
        return (_curve == (SECPCurve)signature.curve) && VerifySignature(signature.r, signature.s, message_hash);
    }

    /// <summary>
    /// Verify an ECDSA signature.
    /// Usage: Compute the hash of the signed data using the same hash as the signer and
    /// pass it to this function along with the signer's public key and the signature values (r and s).
    /// </summary>
    /// <param name="signature">The signature object</param>
    /// <param name="message_hash">The hash of the signed data</param>
    /// <returns></returns>
    public readonly bool VerifySignature(CompactSignature signature, ReadOnlySpan<byte> message_hash)
    {
        return (_curve == (SECPCurve)signature.curve) && VerifySignature(signature.r, signature.s, message_hash);
    }

    /// <summary>
    /// Verify an ECDSA signature.
    /// Usage: Compute the hash of the signed data using the same hash as the signer and
    /// pass it to this function along with the signer's public key and the signature values (r and s).
    /// </summary>
    /// <param name="signature">The signature object</param>
    /// <param name="message_hash">The hash of the signed data</param>
    /// <returns></returns>
    public readonly bool VerifySignature(IECDSASignature signature, ReadOnlySpan<byte> message_hash)
    {
        return (_curve == (SECPCurve)signature.curve) && VerifySignature(signature.r, signature.s, message_hash);
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
        if (signature is not DERSignature && signature is not CompactSignature)
        {
            throw new InvalidOperationException("Invalid signature implementation instance");
        }

        return VerifySignature(signature, message_hash);
    }
}

