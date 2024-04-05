using Wheel.Crypto.Elliptic.EllipticCommon;
using Wheel.Hashing.HMAC;

namespace Wheel.Crypto.Elliptic.EdDSA;

public struct EdCurve : ICurve
{
    public readonly ulong randomId => throw new NotImplementedException();

    public readonly int NUM_N_BITS => throw new NotImplementedException();

    public readonly int NUM_WORDS => throw new NotImplementedException();

    public readonly int NUM_BYTES => throw new NotImplementedException();

    public readonly int PrivateKeySize => throw new NotImplementedException();

    public readonly int UncompressedPublicKeySize => throw new NotImplementedException();

    public readonly int CompressedPublicKeySize => throw new NotImplementedException();

    public readonly int DERSignatureSize => throw new NotImplementedException();

    public readonly int CompactSignatureSize => throw new NotImplementedException();

    public void GenerateDeterministicSecret<HMAC_IMPL>(Span<byte> result, ReadOnlySpan<byte> seed, ReadOnlySpan<byte> personalization, int sequence) where HMAC_IMPL : unmanaged, IMac
    {
        throw new NotImplementedException();
    }

    public void GenerateRandomSecret(Span<byte> result, ReadOnlySpan<byte> entropy)
    {
        throw new NotImplementedException();
    }

    public bool IsValidPrivateKey(ReadOnlySpan<byte> data)
    {
        throw new NotImplementedException();
    }

    public bool IsValidPublicKey(ReadOnlySpan<byte> data)
    {
        throw new NotImplementedException();
    }
}

