using Wheel.Crypto.Elliptic.EllipticCommon;

namespace Wheel.Crypto.Elliptic.EdDSA;

public struct EdPublicKey : IPublicKey
{
    public readonly ICurve curve => throw new NotImplementedException();

    public readonly bool IsValid => throw new NotImplementedException();

    public readonly int EncodedSize => throw new NotImplementedException();

    public bool KeyTweak(out IPublicKey result, ReadOnlySpan<byte> scalar)
    {
        throw new NotImplementedException();
    }

    public bool Parse(ReadOnlySpan<byte> public_key)
    {
        throw new NotImplementedException();
    }

    public void Reset()
    {
        throw new NotImplementedException();
    }

    public bool Serialize(Span<byte> public_point)
    {
        throw new NotImplementedException();
    }

    public bool VerifySignature(ISignature signature, ReadOnlySpan<byte> message_hash)
    {
        throw new NotImplementedException();
    }
}

