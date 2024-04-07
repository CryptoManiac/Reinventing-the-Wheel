namespace Wheel.Crypto.Elliptic.EllipticCommon;

public interface ISignature
{
    /// <summary>
    /// ECC implementation to use
    /// </summary>
    public IGenericCurve curve { get; }

    /// <summary>
    /// Encoded data size in bytes
    /// </summary>
    public int EncodedSize { get; }
    
    /// <summary>
    /// Write signature data in current format
    /// </summary>
    /// <param name="encoded"></param>
    /// <returns>Number of bytes written/to write</returns>
    public int Encode(Span<byte> encoded);

    /// <summary>
    /// Parse input and construct signature from its contents
    /// </summary>
    /// <param name="encoded"></param>
    /// <returns>True on success</returns>
    public bool Parse(ReadOnlySpan<byte> encoded);
}

