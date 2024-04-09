using Wheel.Crypto.Elliptic.EllipticCommon;

namespace Wheel.Crypto.EllipticCommon;

public struct CompactSignature<CurveImpl> : ISignature where CurveImpl : unmanaged, IGenericCurve
{
    /// <summary>
    /// ECC implementation to use
    /// </summary>
    private readonly CurveImpl _curve { get; }

    /// <summary>
    /// Public property for unification purposes
    /// </summary>
    public readonly IGenericCurve curve => _curve;

    /// <summary>
    /// Encoded data size in bytes
    /// </summary>
    public readonly int EncodedSize => GetEncodedSize(_curve);

    /// <summary>
    /// Size of encoded signature for a given curve
    /// </summary>
    /// <param name="curve"></param>
    /// <returns></returns>
    public static int GetEncodedSize(CurveImpl curve)
    {
        return curve.NUM_BYTES;
    }

    /// <summary>
    /// The r and s are sliced from this hidden array.
    /// </summary>
    private unsafe fixed byte signature_data[132]; // Enough for a pair of the 66 byte values for SECP521R1 

    /// <summary>
    /// R part of the signature
    /// </summary>
    public readonly unsafe Span<byte> r
    {
        get
        {
            fixed (byte* ptr = &signature_data[0])
            {
                return new Span<byte>(ptr, curve.NUM_BYTES);
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
            fixed (byte* ptr = &signature_data[curve.NUM_BYTES])
            {
                return new Span<byte>(ptr, curve.NUM_BYTES);
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
    public CompactSignature(CurveImpl curve)
    {
        _curve = curve;
        r.Clear();
        s.Clear();
    }

    /// <summary>
    /// Create instance and parse provided data
    /// </summary>
    /// <param name="curve">ECC implementation</param>
    public CompactSignature(CurveImpl curve, ReadOnlySpan<byte> bytes) : this(curve)
    {
        if (!Parse(bytes))
        {
            throw new InvalidDataException("Provided DER signature is not valid");
        }
    }

    public int Encode(Span<byte> encoded)
    {
        if (encoded.Length < 2 * curve.NUM_BYTES)
        {
            return 2 * curve.NUM_BYTES;
        }

        r.CopyTo(encoded[.. curve.NUM_BYTES]);
        s.CopyTo(encoded[curve.NUM_BYTES..]);

        return 2 * curve.NUM_BYTES;
    }

    public bool Parse(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != 2 * curve.NUM_BYTES)
        {
            return false;
        }

        encoded[..curve.NUM_BYTES].CopyTo(r);
        encoded[curve.NUM_BYTES ..].CopyTo(s);

        return true;
    }
}

