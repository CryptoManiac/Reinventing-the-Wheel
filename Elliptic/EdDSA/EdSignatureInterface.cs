using Wheel.Crypto.Elliptic.EllipticCommon;

namespace Wheel.Crypto.Elliptic.EdDSA;

public struct IEdSignature : ISignature
{
    ICurve ISignature.curve => throw new NotImplementedException();

    int ISignature.EncodedSize => throw new NotImplementedException();

    int ISignature.Encode(Span<byte> encoded)
    {
        throw new NotImplementedException();
    }

    bool ISignature.Parse(ReadOnlySpan<byte> encoded)
    {
        throw new NotImplementedException();
    }
}

