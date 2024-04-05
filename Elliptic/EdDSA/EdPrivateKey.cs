using Wheel.Crypto.Elliptic.EllipticCommon;
using Wheel.Hashing;
using Wheel.Hashing.HMAC;

namespace Wheel.Crypto.Elliptic.EdDSA;

public struct EdPrivateKey : IPrivateKey
{
    public readonly ICurve curve => throw new NotImplementedException();

    public readonly bool IsValid => throw new NotImplementedException();

    public readonly int EncodedSize => throw new NotImplementedException();

    public readonly bool CalculateKeyHash<HASHER_IMPL>(Span<byte> secret_hash) where HASHER_IMPL : unmanaged, IHasher
    {
        throw new NotImplementedException();
    }

    public readonly bool ComputePublicKey(out IPublicKey public_key)
    {
        throw new NotImplementedException();
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
        throw new NotImplementedException();
    }

    public void Reset()
    {
        throw new NotImplementedException();
    }

    public readonly bool Serialize(Span<byte> secret_scalar)
    {
        throw new NotImplementedException();
    }

    public readonly bool Sign<HMAC_IMPL>(out ISignature signature, ReadOnlySpan<byte> message_hash) where HMAC_IMPL : unmanaged, IMac
    {
        throw new NotImplementedException();
    }

    public readonly bool SignDeterministic<HMAC_IMPL>(out ISignature signature, ReadOnlySpan<byte> message_hash) where HMAC_IMPL : unmanaged, IMac
    {
        throw new NotImplementedException();
    }
}

