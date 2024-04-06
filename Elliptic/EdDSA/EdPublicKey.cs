using Wheel.Crypto.Elliptic.EdDSA.Internal;
using Wheel.Crypto.Elliptic.EdDSA.Internal.Curve25519;
using Wheel.Crypto.Elliptic.EdDSA.Internal.GroupElement;
using Wheel.Crypto.Elliptic.EllipticCommon;
using Wheel.Hashing;

namespace Wheel.Crypto.Elliptic.EdDSA;

public struct EdPublicKey : IPublicKey
{
    /// <summary>
    /// The secret key funcions are using slices that are being made from this hidden array.
    /// </summary>
    internal unsafe fixed byte public_key_data[32];

    private readonly EdCurve _curve { get; }

    public readonly ICurve curve => _curve;

    /// <summary>
    /// Check the public key coordinate
    /// </summary>
    public readonly bool IsValid
    {
        get
        {
            GE25519 A;
            return GEMath.ge25519_unpack_negative_vartime(ref A, data);
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
    private readonly unsafe Span<byte> data
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
    public EdPublicKey(in ICurve curve)
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
    public EdPublicKey(in ICurve curve, ReadOnlySpan<byte> public_key) : this(curve)
    {
        if (!Parse(public_key))
        {
            throw new InvalidDataException("Provided public key is not valid");
        }
    }

    public bool KeyTweak(out IPublicKey result, ReadOnlySpan<byte> scalar)
    {
        throw new NotImplementedException();
    }

    public bool Parse(ReadOnlySpan<byte> public_key)
    {
        if (public_key.Length != data.Length)
        {
            return false;
        }

        public_key[..32].CopyTo(data);
        return true;
    }

    public void Reset()
    {
        data.Clear();
    }

    public readonly bool Serialize(Span<byte> public_key)
    {
        if (public_key.Length != data.Length)
        {
            return false;
        }

        data.CopyTo(public_key[..32]);
        return true;
    }

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
    /// Verify an ECDSA signature.
    /// Usage: Compute the hash of the signed data using the same hash as the signer and
    /// pass it to this function along with the signer's public key and the signature values (r and s).
    /// </summary>
    /// <param name="r"></param>
    /// <param name="s"></param>
    /// <param name="message_hash"></param>
    /// <returns></returns>
    private readonly bool VerifySignature(ReadOnlySpan<byte> r, ReadOnlySpan<byte> s, ReadOnlySpan<byte> message_hash)
    {
        if (Convert.ToBoolean(s[31] & 224) || IsValid)
        {
            return false;
        }

        GE25519 R, A;
        Span<ulong> hram = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> S = stackalloc ulong[ModM.ModM_WORDS];
        Span<byte> checkR = stackalloc byte[32];

        IHasher hasher = _curve.makeHasher();
        Span<byte> hash = stackalloc byte[hasher.HashSz];
        hasher.Update(r);
        hasher.Update(data);
        hasher.Update(message_hash);
        hasher.Digest(hash);

        ModM.expand256(hram, hash, 64);

        // S
        ModM.expand256(S, s, 32);

        // SB - H(R,A,m)A
        GEMath.ge25519_double_scalarmult_vartime(ref R, A, hram, S);
        GEMath.ge25519_pack(checkR, R);

        // check that R = SB - H(R,A,m)A
        return Logic.ed25519_verify(r, checkR, 32);
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

