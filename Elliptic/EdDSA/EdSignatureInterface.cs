using Wheel.Crypto.Elliptic.EllipticCommon;

namespace Wheel.Crypto.Elliptic.EdDSA;

public interface IEdSignature : ISignature
{
    /// <summary>
    /// ECC implementation to use
    /// </summary>
    public new ICurve curve { get; }

    /// <summary>
    /// Encoded data size in bytes
    /// </summary>
    public new int EncodedSize { get; }

    /// R part of the signature
    /// </summary>
    public Span<byte> r { get; }

    /// <summary>
    /// S part of the signature
    /// </summary>
    public Span<byte> s { get; }

    /// <summary>
    /// Write signature data in current format
    /// </summary>
    /// <param name="encoded"></param>
    /// <returns>Number of bytes written/to write</returns>
    public new int Encode(Span<byte> encoded);

    /// <summary>
    /// Parse input and construct signature from its contents
    /// </summary>
    /// <param name="encoded"></param>
    /// <returns>True on success</returns>
    public new bool Parse(ReadOnlySpan<byte> encoded);
}

