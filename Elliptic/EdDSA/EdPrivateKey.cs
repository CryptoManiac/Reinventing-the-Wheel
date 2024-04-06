using Wheel.Crypto.Elliptic.EdDSA.Internal;
using Wheel.Crypto.Elliptic.EdDSA.Internal.GroupElement;
using Wheel.Crypto.Elliptic.EllipticCommon;
using Wheel.Hashing;
using Wheel.Hashing.HMAC;

namespace Wheel.Crypto.Elliptic.EdDSA;

public struct EdPrivateKey : IPrivateKey
{
    /// <summary>
    /// The secret key funcions are using slices that are being made from this hidden array.
    /// </summary>
    internal unsafe fixed byte private_key_data[32];

    /// <summary>
    /// Local copy of EC implementation instance
    /// </summary>
    private readonly EdCurve _curve;

    /// <summary>
    /// ECC implementation to use (exposed to users)
    /// </summary>
    public readonly ICurve curve => _curve;

    /// <summary>
    /// Encoded key size in bytes
    /// </summary>
    public readonly int EncodedSize => GetEncodedSize(_curve);

    /// <summary>
    /// Access to public point data
    /// </summary>
    private readonly unsafe Span<byte> secret_scalar_data
    {
        get
        {
            fixed (byte* ptr = &private_key_data[0])
            {
                return new Span<byte>(ptr, 32);
            }
        }
    }

    /// <summary>
    /// Check the private key format
    /// </summary>
    public readonly bool IsValid
    {
        get
        {
            Span<byte> keyCheck = stackalloc byte[32];
            secret_scalar_data.CopyTo(keyCheck);

            keyCheck[0] &= 248;
            keyCheck[31] &= 127;
            keyCheck[31] |= 64;

            bool isValid = keyCheck.SequenceEqual(secret_scalar_data);
            keyCheck.Clear();

            return isValid;
        }
    }

    /// <summary>
    /// Size of encoded private key for a given curve
    /// </summary>
    /// <param name="curve"></param>
    /// <returns>Number of bytes</returns>
    public static int GetEncodedSize(EdCurve curve)
    {
        return 32;
    }

    /// <summary>
    /// The default constructor should never be called
    /// </summary>
    /// <exception cref="SystemException"></exception>
    public EdPrivateKey()
    {
        throw new SystemException("The default constructor should never be called");
    }

    /// <summary>
    /// Construct the empty key
    /// </summary>
    /// <param name="_curve">ECC implementation</param>
    public EdPrivateKey(in ICurve curve)
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
    /// Construct the the new private key instance from the given serialized scalar
    /// </summary>
    /// <param name="_curve">ECC implementation</param>
    public EdPrivateKey(in ICurve curve, ReadOnlySpan<byte> scalar) : this(curve)
    {
        if (!Parse(scalar))
        {
            throw new InvalidDataException("Provided scalar is not valid");
        }
    }

    /// <summary>
    /// Check to see if a serialized private key is valid.
    /// Note that you are not required to check for a valid private key before using any other functions.
    /// </summary>
    /// <param name="private_key">The private key to check.</param>
    /// <returns>True if the private key is valid.</returns>
    public static bool IsValidPrivateKey(ICurve curve, ReadOnlySpan<byte> private_key)
    {
        if (curve is not EdCurve)
        {
            // Shouldn't happen in real life
            throw new InvalidOperationException("Invalid curve implementation instance");
        }

        EdPrivateKey pk = new(curve);
        return pk.Parse(private_key);
    }


    public readonly bool CalculateKeyHash<HASHER_IMPL>(Span<byte> secret_hash) where HASHER_IMPL : unmanaged, IHasher
    {
        HASHER_IMPL hasher = new();
        if (secret_hash.Length == hasher.HashSz)
        {
            hasher.Update(secret_scalar_data);
            hasher.Digest(secret_hash);
            return true;
        }
        return false;
    }

    public readonly bool ComputePublicKey(out EdPublicKey public_key)
    {
        public_key = new(_curve);

        if (!IsValid)
        {
            return false;
        }

        GE25519 public_point;
        Span<ulong> secret_scalar = stackalloc ulong[ModM.ModM_WORDS];
        Span<byte> public_data = stackalloc byte[32];

        /* A = aB */
        ModM.expand256(secret_scalar, secret_scalar_data, 32);
        GEMath.ge25519_scalarmult_base_niels(ref public_point, GEMath.tables.NIELS_Base_Multiples, secret_scalar);
        GEMath.ge25519_pack(public_data, public_point);

        return public_key.Parse(public_data);
    }

    public readonly bool ComputePublicKey(out IPublicKey public_key)
    {
        return ComputePublicKey(out public_key);
    }

    /// <summary>
    /// Compute a shared secret given your secret key and someone else's public key.
    ///
    /// Note: It is recommended that you hash the result of Derive() before using it for
    /// symmetric encryption or HMAC.
    /// </summary>
    /// <param name="public_key">The public key of the remote party.</param>
    /// <param name="shared">Will be filled in with the encapsulated shared secret.</param>
    /// <returns>True if the shared secret was generated successfully, False if an error occurred.</returns>
    public readonly bool ECDH(in EdPublicKey public_key, out EdPrivateKey shared)
    {
        if (_curve != (EdCurve)public_key.curve)
        {
            // It doesn't make any sense to use points on non-matching curves
            // This shouldn't ever happen in real life
            throw new InvalidOperationException("Curve configuration mismatch");
        }

        // Start with empty key
        shared = new(_curve);

        Span<byte> public_bytes = stackalloc byte[32];
        Span<byte> shared_bytes = stackalloc byte[32];
        if (!public_key.Serialize(public_bytes))
        {
            // Doesn't make any sense to
            // use uninitialized keys
            return false;
        }

        GE25519 public_point, shared_point;
        Span<ulong> secret_scalar = stackalloc ulong[ModM.ModM_WORDS];
        ModM.expand256(secret_scalar, secret_scalar_data, 32);

        if (!GEMath.ge25519_unpack_negative_vartime(ref public_point, public_bytes))
        {
            return false;
        }

        // Calculate new secret, then trim it and place into shared key instance
        GEMath.ge25519_scalarmult_vartime(ref shared_point, public_point, secret_scalar);

        GEMath.ge25519_pack(shared_bytes, shared_point);

        shared_bytes[0] &= 248;
        shared_bytes[31] &= 63;
        shared_bytes[31] |= 64;

        bool result = shared.Parse(shared_bytes);
        shared_bytes.Clear();
        return result;
    }

    public readonly bool ECDH(in IPublicKey public_key, out IPrivateKey shared)
    {
        throw new NotImplementedException();
    }

    public readonly bool KeyTweak(out IPrivateKey result, ReadOnlySpan<byte> scalar)
    {
        result = new EdPrivateKey(_curve);

        if (!IsValid)
        {
            return false;
        }

        Span<ulong> sum = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> added = stackalloc ulong[ModM.ModM_WORDS];
        Span<byte> tweaked = stackalloc byte[32];

        ModM.expand256(sum, secret_scalar_data, 32);
        ModM.expand256(added, scalar, 32);
        ModM.add256(sum, sum, added);
        ModM.contract256(tweaked, sum);

        result.Parse(tweaked);
        tweaked.Clear();
        return result.IsValid;
    }

    public bool Parse(ReadOnlySpan<byte> private_key)
    {
        if (private_key.Length != secret_scalar_data.Length)
        {
            return false;
        }

        private_key.CopyTo(secret_scalar_data);
        return IsValid;
    }

    public void Reset()
    {
        secret_scalar_data.Clear();
    }

    public readonly bool Serialize(Span<byte> secret_scalar)
    {
        if (secret_scalar.Length != secret_scalar_data.Length || !IsValid)
        {
            return false;
        }

        secret_scalar_data.CopyTo(secret_scalar[..32]);
        return true;
    }

    private readonly bool SignDeterministic<HMAC_IMPL>(Span<byte> sig_r, Span<byte> sig_s, ReadOnlySpan<byte> message_hash) where HMAC_IMPL : unmanaged, IMac
    {
        // Public key is used for r,s calculation
        Span<byte> public_data = stackalloc byte[32];
        if (!ComputePublicKey(out EdPublicKey pk) || !pk.Serialize(public_data))
        {
            return false;
        }

        Span<ulong> r = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> S = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> a = stackalloc ulong[ModM.ModM_WORDS];

        GE25519 R;

        // r = DRNG(secret, message_hash, message_hash_len)
        Span<byte> rnd = stackalloc byte[64];
        _curve.GenerateDeterministicNonce<HMAC_IMPL>(rnd, secret_scalar_data, message_hash, 0);
        ModM.expand256(r, rnd, 64);

        // R = rB
        GEMath.ge25519_scalarmult_base_niels(ref R, GEMath.tables.NIELS_Base_Multiples, r);
        GEMath.ge25519_pack(sig_r, R);

        // S = H(R,A,m)..
        Span<byte> hram = stackalloc byte[64];
        IHasher hasher = _curve.makeHasher();
        hasher.Update(sig_r);
        hasher.Update(public_data);
        hasher.Update(message_hash);
        hasher.Digest(hram);
        ModM.expand256(S, hram, 64);

        // S = H(R,A,m)a
        ModM.expand256(a, secret_scalar_data, 32);
        ModM.mul256(S, S, a);

        // S = (r + H(R,A,m)a)
        ModM.add256(S, S, r);

        // S = (r + H(R,A,m)a) mod L
        ModM.contract256(sig_s, S);

        return true;
    }

    private readonly bool Sign<HMAC_IMPL>(Span<byte> sig_r, Span<byte> sig_s, ReadOnlySpan<byte> message_hash) where HMAC_IMPL : unmanaged, IMac
    {
        // Public key is used for r,s calculation
        Span<byte> public_data = stackalloc byte[32];
        if (!ComputePublicKey(out EdPublicKey pk) || !pk.Serialize(public_data))
        {
            return false;
        }

        Span<ulong> r = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> S = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> a = stackalloc ulong[ModM.ModM_WORDS];

        GE25519 R;

        // rnd = DRNG(secret, message_hash, message_hash_len)
        // r = RNG(rnd, message_hash)
        Span<byte> rnd = stackalloc byte[64];
        _curve.GenerateRandomNonce(rnd, message_hash);
        ModM.expand256(r, rnd, 64);

        // R = rB
        GEMath.ge25519_scalarmult_base_niels(ref R, GEMath.tables.NIELS_Base_Multiples, r);
        GEMath.ge25519_pack(sig_r, R);

        // S = H(R,A,m)..
        Span<byte> hram = stackalloc byte[64];
        IHasher hasher = _curve.makeHasher();
        hasher.Update(sig_r);
        hasher.Update(public_data);
        hasher.Update(message_hash);
        hasher.Digest(hram);
        ModM.expand256(S, hram, 64);

        // S = H(R,A,m)a
        ModM.expand256(a, secret_scalar_data, 32);
        ModM.mul256(S, S, a);

        // S = (r + H(R,A,m)a)
        ModM.add256(S, S, r);

        // S = (r + H(R,A,m)a) mod L
        ModM.contract256(sig_s, S);

        return true;
    }

    /// <summary>
    /// Generate an ECDSA signature for a given hash value, using a deterministic algorithm
    /// 
    /// Usage: Compute a hash of the data you wish to sign and pass it to this function.
    /// </summary>
    /// <param name="signature">Will be filled in with the signature value. Curve settings will be overwritten.</param>
    /// <param name="message_hash">The hash of the message to sign</param>
    /// <returns></returns>
    public readonly bool SignDeterministic<HMAC_IMPL>(out DERSignature signature, ReadOnlySpan<byte> message_hash) where HMAC_IMPL : unmanaged, IMac
    {
        signature = new(_curve);
        return SignDeterministic<HMAC_IMPL>(signature.r, signature.s, message_hash);
    }

    /// <summary>
    /// Generate an ECDSA signature for a given hash value, using a deterministic algorithm
    /// 
    /// Usage: Compute a hash of the data you wish to sign and pass it to this function.
    /// </summary>
    /// <param name="signature">Will be filled in with the signature value. Curve settings will be overwritten.</param>
    /// <param name="message_hash">The hash of the message to sign</param>
    /// <returns></returns>
    public readonly bool SignDeterministic<HMAC_IMPL>(out CompactSignature signature, ReadOnlySpan<byte> message_hash) where HMAC_IMPL : unmanaged, IMac
    {
        signature = new(_curve);
        return SignDeterministic<HMAC_IMPL>(signature.r, signature.s, message_hash);
    }

    /// <summary>
    /// Generate an ECDSA signature for a given hash value, using a non-deterministic algorithm
    /// 
    /// Usage: Compute a hash of the data you wish to sign and pass it to this function.
    /// </summary>
    /// <param name="signature">Will be filled in with the signature value. Curve settings will be overwritten.</param>
    /// <param name="message_hash">The hash of the message to sign</param>
    /// <returns></returns>
    public readonly bool SignDeterministic<HMAC_IMPL>(out ISignature signature, ReadOnlySpan<byte> message_hash) where HMAC_IMPL : unmanaged, IMac
    {
        bool result = SignDeterministic<HMAC_IMPL>(out DERSignature generatedSig, message_hash);
        signature = generatedSig;
        return result;
    }

    /// <summary>
    /// Generate an ECDSA signature for a given hash value, using a non-deterministic algorithm
    /// 
    /// Usage: Compute a hash of the data you wish to sign and pass it to this function.
    /// </summary>
    /// <param name="signature">Will be filled in with the signature value. Curve settings will be overwritten.</param>
    /// <param name="message_hash">The hash of the message to sign</param>
    /// <returns></returns>
    public readonly bool Sign<HMAC_IMPL>(out DERSignature signature, ReadOnlySpan<byte> message_hash) where HMAC_IMPL : unmanaged, IMac
    {
        signature = new(_curve);
        return Sign<HMAC_IMPL>(signature.r, signature.s, message_hash);
    }

    /// <summary>
    /// Generate an ECDSA signature for a given hash value, using a non-deterministic algorithm
    /// 
    /// Usage: Compute a hash of the data you wish to sign and pass it to this function.
    /// </summary>
    /// <param name="signature">Will be filled in with the signature value. Curve settings will be overwritten.</param>
    /// <param name="message_hash">The hash of the message to sign</param>
    /// <returns></returns>
    public readonly bool Sign<HMAC_IMPL>(out CompactSignature signature, ReadOnlySpan<byte> message_hash) where HMAC_IMPL : unmanaged, IMac
    {
        signature = new(_curve);
        return Sign<HMAC_IMPL>(signature.r, signature.s, message_hash);
    }

    /// <summary>
    /// Generate an ECDSA signature for a given hash value, using a non-deterministic algorithm
    /// 
    /// Usage: Compute a hash of the data you wish to sign and pass it to this function.
    /// </summary>
    /// <param name="signature">Will be filled in with the signature value. Curve settings will be overwritten.</param>
    /// <param name="message_hash">The hash of the message to sign</param>
    /// <returns></returns>
    public readonly bool Sign<HMAC_IMPL>(out ISignature signature, ReadOnlySpan<byte> message_hash) where HMAC_IMPL : unmanaged, IMac
    {
        bool result = Sign<HMAC_IMPL>(out CompactSignature generatedSig, message_hash);
        signature = generatedSig;
        return result;
    }
}

