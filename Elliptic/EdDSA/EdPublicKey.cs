using System.Runtime.CompilerServices;
using Wheel.Crypto.Elliptic.EdDSA.Internal;
using Wheel.Crypto.Elliptic.EdDSA.Internal.GroupElement;
using Wheel.Crypto.Elliptic.EllipticCommon;

namespace Wheel.Crypto.Elliptic.EdDSA;

public struct EdPublicKey : IPublicKey
{
    /// <summary>
    /// The secret key funcions are using slices that are being made from this hidden array.
    /// </summary>
    internal unsafe fixed byte public_key_data[32];

    private readonly EdCurve _curve { get; }

    public readonly IGenericCurve curve => _curve;

    /// <summary>
    /// Check the public key coordinate
    /// </summary>
    public readonly bool IsValid
    {
        [SkipLocalsInit]
        get
        {
            GE25519 A;
            return A.ge25519_unpack_negative_vartime(public_point_data);
        }
    }

    /// <summary>
    /// Encoded key size in bytes
    /// </summary>
    public readonly int EncodedSize => GetUncompressedSize(_curve);

    /// <summary>
    /// Encoded key size in bytes
    /// </summary>
    public readonly int CompressedSize => GetCompressedSize(_curve);

    /// <summary>
    /// Access to public point data
    /// </summary>
    private readonly unsafe Span<byte> public_point_data
    {
        get
        {
            fixed (byte* ptr = &public_key_data[0])
            {
                return new Span<byte>(ptr, 32);
            }
        }
    }

    /// <summary>
    /// The default constructor should never be called
    /// </summary>
    /// <exception cref="SystemException"></exception>
    public EdPublicKey()
    {
        throw new SystemException("The default constructor should never be called");
    }

    /// <summary>
    /// Construct the empty key
    /// </summary>
    /// <param name="curve">ECC implementation</param>
    public EdPublicKey(in IGenericCurve curve)
    {
        if (curve is not EdCurve)
        {
            // Shouldn't happen in real life
            throw new InvalidOperationException("Invalid curve implementation instance");
        }

        _curve = (EdCurve)curve;

        // Init with zeros
        Reset();
    }

    /// <summary>
    /// Construct the empty key
    /// </summary>
    /// <param name="curve">ECC implementation</param>
    public EdPublicKey(in IGenericCurve curve, ReadOnlySpan<byte> public_key) : this(curve)
    {
        if (!Parse(public_key))
        {
            throw new InvalidDataException("Provided public key is not valid");
        }
    }

    /// <summary>
    /// EC public key tweak by scalar
    /// </summary>
    /// <param name="result"></param>
    /// <param name="scalar"></param>
    /// <returns></returns>
    [SkipLocalsInit]
    public readonly bool KeyTweak(out EdPublicKey result, ReadOnlySpan<byte> scalar)
    {
        result = new EdPublicKey(_curve);

        GE25519 R, P, Q;

        if (!P.ge25519_unpack_negative_vartime(public_point_data))
        {
            return false;
        }
        if (!Q.ge25519_unpack_negative_vartime(scalar))
        {
            return false;
        }

        R.ge25519_add(P, Q);

        Span<byte> res = stackalloc byte[32];
        R.ge25519_pack(res);

        res[31] ^= 0x80;
        return result.Parse(res);
    }

    /// <summary>
    /// EC public key tweak by scalar
    /// </summary>
    /// <param name="outKey"></param>
    /// <param name="scalar"></param>
    /// <returns></returns>
    public readonly bool KeyTweak(out IPublicKey outKey, ReadOnlySpan<byte> scalar)
    {
        bool result = KeyTweak(out EdPublicKey generatedKey, scalar);
        outKey = generatedKey;
        return result;
    }

    public bool Parse(ReadOnlySpan<byte> public_key)
    {
        if (public_key.Length < public_point_data.Length)
        {
            return false;
        }

        public_key[..32].CopyTo(public_point_data);
        return IsValid;
    }

    public void Reset()
    {
        public_point_data.Clear();
    }

    /// <summary>
    /// Copy the key value into byte array
    /// </summary>
    /// <param name="serialized"></param>
    /// <returns>True if successful and this key is valid</returns>
    public readonly bool Serialize(Span<byte> serialized)
    {
        if (serialized.Length < public_point_data.Length || !IsValid)
        {
            return false;
        }

        public_point_data.CopyTo(serialized[..32]);
        return true;
    }

    /// <summary>
    /// Synonymous for Serialize()
    /// </summary>
    /// <param name="compressed"></param>
    /// <returns></returns>
    public readonly bool Compress(Span<byte> compressed) => Serialize(compressed);

    /// <summary>
    /// Size of uncompressed public key for a given curve
    /// </summary>
    /// <param name="curve"></param>
    /// <returns>Number of bytes</returns>
    public static int GetUncompressedSize(EdCurve curve)
    {
        return 32;
    }

    /// <summary>
    /// Size of compressed public key for a given curve
    /// </summary>
    /// <param name="curve"></param>
    /// <returns>Number of bytes</returns>
    public static int GetCompressedSize(EdCurve curve)
    {
        return 32;
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
        if (curve is not EdCurve)
        {
            // Shouldn't happen in real life
            throw new InvalidOperationException("Invalid curve implementation instance");
        }

        EdPublicKey pk = new(curve);
        return pk.Parse(public_key);
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
    private readonly bool VerifySignature(ReadOnlySpan<byte> r, ReadOnlySpan<byte> s, ReadOnlySpan<byte> message_hash)
    {
        if (Convert.ToBoolean(s[31] & 224))
        {
            return false;
        }

        GE25519 R, A;

        if (!A.ge25519_unpack_negative_vartime(public_point_data))
        {
            return false;
        }

        Span<ulong> hram = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> S = stackalloc ulong[ModM.ModM_WORDS];
        Span<byte> checkR = stackalloc byte[32];

        Span<byte> hash = stackalloc byte[64];
        _curve.GetHRAM(hash, r, public_point_data, message_hash);
        ModM.expand256(hram, hash, 64);

        // S
        ModM.expand256(S, s, 32);

        // SB - H(R,A,m)A
        GEMath.ge25519_double_scalarmult_vartime(ref R, A, hram, S);
        R.ge25519_pack(checkR);

        // check that R = SB - H(R,A,m)A
        return Curve25519.ed25519_verify(r, checkR, 32);
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
        return (_curve == (EdCurve)signature.curve) && VerifySignature(signature.r, signature.s, message_hash);
    }

    /// <summary>
    /// Verify an ECDSA signature.
    /// Usage: Compute the hash of the signed data using the same hash as the signer and
    /// pass it to this function along with the signer's public key and the signature values (r and s).
    /// </summary>
    /// <param name="signature">The signature object</param>
    /// <param name="message_hash">The hash of the signed data</param>
    /// <returns></returns>
    public readonly bool VerifySignature(IEdSignature signature, ReadOnlySpan<byte> message_hash)
    {
        return (_curve == (EdCurve)signature.curve) && VerifySignature(signature.r, signature.s, message_hash);
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
        if (signature is CompactSignature compact)
        {
            return VerifySignature(compact.r, compact.s, message_hash);
        }

        if (signature is DERSignature der)
        {
            return VerifySignature(der.r, der.s, message_hash);
        }

        throw new InvalidOperationException("Invalid signature implementation instance");
    }
}

