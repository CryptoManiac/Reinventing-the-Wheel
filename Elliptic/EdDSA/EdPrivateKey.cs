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
    private readonly unsafe Span<byte> data
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
            Span<byte> keyCopy = stackalloc byte[32];
            data.CopyTo(keyCopy);

            keyCopy[0] &= 248;
            keyCopy[31] &= 127;
            keyCopy[31] |= 64;

            bool isValid = keyCopy.SequenceEqual(data);
            keyCopy.Clear();

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

        if (private_key.Length != 32)
        {
            return false;
        }

        Span<byte> keyCopy = stackalloc byte[32];
        private_key.CopyTo(keyCopy);

        keyCopy[0] &= 248;
        keyCopy[31] &= 127;
        keyCopy[31] |= 64;

        bool isValid = keyCopy.SequenceEqual(private_key);
        keyCopy.Clear();

        return isValid;
    }


    public readonly bool CalculateKeyHash<HASHER_IMPL>(Span<byte> secret_hash) where HASHER_IMPL : unmanaged, IHasher
    {
        HASHER_IMPL hasher = new();
        if (secret_hash.Length == hasher.HashSz)
        {
            hasher.Update(data);
            hasher.Digest(secret_hash);
            return true;
        }
        return false;
    }

    public readonly bool ComputePublicKey(out EdPublicKey public_key)
    {
        GE25519 A;
        Span<ulong> a = stackalloc ulong[ModM.ModM_WORDS];
        Span<byte> public_bytes = stackalloc byte[32];

        /* A = aB */
        ModM.expand256(a, data, 32);
        GEMath.ge25519_scalarmult_base_niels(ref A, GEMath.tables.NIELS_Base_Multiples, a);
        GEMath.ge25519_pack(public_bytes, A);

        public_key = new(_curve);
        return public_key.Parse(public_bytes);
    }

    public readonly bool ComputePublicKey(out IPublicKey public_key)
    {
        return ComputePublicKey(out public_key);
    }

    public readonly bool ECDH(in IPublicKey public_key, out IPrivateKey shared)
    {
        throw new NotImplementedException();
    }

    public readonly bool KeyTweak(out IPrivateKey result, ReadOnlySpan<byte> scalar)
    {
        throw new NotImplementedException();
    }

    public bool Parse(ReadOnlySpan<byte> private_key)
    {
        if (private_key.Length != data.Length)
        {
            return false;
        }

        private_key[..32].CopyTo(data);
        return true;
    }

    public void Reset()
    {
        data.Clear();
    }

    public readonly bool Serialize(Span<byte> secret_scalar)
    {
        if (secret_scalar.Length != data.Length)
        {
            return false;
        }

        data.CopyTo(secret_scalar[..32]);
        return true;
    }

    private readonly bool SignDeterministic<HMAC_IMPL>(Span<byte> sig_r, Span<byte> sig_s, ReadOnlySpan<byte> message_hash) where HMAC_IMPL : unmanaged, IMac
    {
        Span<ulong> r = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> S = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> a = stackalloc ulong[ModM.ModM_WORDS];

        GE25519 R;

        // r = DRNG(secret, message_hash, message_hash_len)
        Span<byte> rnd = stackalloc byte[64];
        _curve.GenerateDeterministicSecret<HMAC_IMPL>(rnd, data, message_hash, message_hash.Length);
        ModM.expand256(r, rnd, 64);

        // R = rB
        GEMath.ge25519_scalarmult_base_niels(ref R, GEMath.tables.NIELS_Base_Multiples, r);
        GEMath.ge25519_pack(sig_r, R);

        // S = H(R,A,m)..
        Span<byte> hram = stackalloc byte[64];
        IHasher hasher = _curve.makeHasher();
        hasher.Update(sig_r);
        hasher.Update(data);
        hasher.Update(message_hash);
        hasher.Digest(hram);
        ModM.expand256(S, hram, 64);

        // S = H(R,A,m)a
        ModM.expand256(a, data, 32);
        ModM.mul256(S, S, a);

        // S = (r + H(R,A,m)a)
        ModM.add256(S, S, r);

        // S = (r + H(R,A,m)a) mod L
        ModM.contract256(sig_s, S);

        return true;
    }

    private readonly bool Sign<HMAC_IMPL>(Span<byte> sig_r, Span<byte> sig_s, ReadOnlySpan<byte> message_hash) where HMAC_IMPL : unmanaged, IMac
    {
        Span<ulong> r = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> S = stackalloc ulong[ModM.ModM_WORDS];
        Span<ulong> a = stackalloc ulong[ModM.ModM_WORDS];

        GE25519 R;

        // rnd = DRNG(secret, message_hash, message_hash_len)
        // r = RNG(rnd, message_hash)
        Span<byte> rnd = stackalloc byte[64];
        _curve.GenerateDeterministicSecret<HMAC_IMPL>(rnd, data, message_hash, message_hash.Length);
        _curve.GenerateRandomSecret(rnd, rnd);
        ModM.expand256(r, rnd, 64);

        // R = rB
        GEMath.ge25519_scalarmult_base_niels(ref R, GEMath.tables.NIELS_Base_Multiples, r);
        GEMath.ge25519_pack(sig_r, R);

        // S = H(R,A,m)..
        Span<byte> hram = stackalloc byte[64];
        IHasher hasher = _curve.makeHasher();
        hasher.Update(sig_r);
        hasher.Update(data);
        hasher.Update(message_hash);
        hasher.Digest(hram);
        ModM.expand256(S, hram, 64);

        // S = H(R,A,m)a
        ModM.expand256(a, data, 32);
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

