using Wheel.Crypto.Elliptic.EllipticCommon;

namespace Wheel.Crypto.Elliptic.EdDSA;

public struct CompactSignature : IEdSignature
{
    /// <summary>
    /// ECC implementation to use
    /// </summary>
    private readonly EdCurve _curve { get; }

    /// <summary>
    /// Public property for unification purposes
    /// </summary>
    public readonly ICurve curve => _curve;

    /// <summary>
    /// Encoded data size in bytes
    /// </summary>
    public readonly int EncodedSize => GetEncodedSize(_curve);

    /// <summary>
    /// Size of encoded signature for a given curve
    /// </summary>
    /// <param name="curve"></param>
    /// <returns></returns>
    public static int GetEncodedSize(EdCurve curve)
    {
        return 64;
    }

    /// <summary>
    /// The r and s are sliced from this hidden array.
    /// </summary>
    private unsafe fixed byte signature_data[64];

    /// <summary>
    /// R part of the signature
    /// </summary>
    public readonly unsafe Span<byte> r
    {
        get
        {
            fixed (byte* ptr = &signature_data[0])
            {
                return new Span<byte>(ptr, 32);
            }
        }
    }

    /// <summary>
    /// S part of the signature
    /// </summary>
    public readonly unsafe Span<byte> s
    {
        get
        {
            fixed (byte* ptr = &signature_data[32])
            {
                return new Span<byte>(ptr, 32);
            }
        }
    }

    public CompactSignature()
    {
        throw new SystemException("The default constructor should never be called");
    }

    /// <summary>
    /// Construct the empty signature for given curve
    /// </summary>
    /// <param name="curve">ECC implementation</param>
    public CompactSignature(EdCurve curve)
    {
        _curve = curve;
        r.Clear();
        s.Clear();
    }

    /// <summary>
    /// Create instance and parse provided data
    /// </summary>
    /// <param name="curve">ECC implementation</param>
    public CompactSignature(EdCurve curve, ReadOnlySpan<byte> bytes) : this(curve)
    {
        if (!Parse(bytes))
        {
            throw new InvalidDataException("Provided DER signature is not valid");
        }
    }

    public int Encode(Span<byte> encoded)
    {
        if (encoded.Length != 64)
        {
            return 64;
        }

        r.CopyTo(encoded[..32]);
        s.CopyTo(encoded[32..]);

        return 64;
    }

    public bool Parse(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != 64)
        {
            return false;
        }

        encoded[..32].CopyTo(r);
        encoded[32..].CopyTo(s);

        return true;
    }
}

