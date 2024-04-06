namespace Wheel.Crypto.Elliptic.EdDSA.Internal.GroupElement;

internal struct GE25519_NIELS_Packed
{
    public const int TypeByteSz = 96;
    private unsafe fixed byte __packed__[TypeByteSz];

    public GE25519_NIELS_Packed(ReadOnlySpan<byte> data)
    {
        data[..TypeByteSz].CopyTo(ALL);
    }

    public static implicit operator GE25519_NIELS_Packed(ReadOnlySpan<byte> data)
    {
        return new(data);
    }

    public static implicit operator GE25519_NIELS_Packed(Span<byte> data)
    {
        return new(data);
    }

    public unsafe readonly Span<byte> ALL
    {
        get
        {
            fixed (byte* ptr = &__packed__[0])
            {
                return new(ptr, TypeByteSz);
            }
        }
    }

    public readonly Span<byte> YsubX => ALL[ .. 32];
    public readonly Span<byte> XaddY => ALL[32 .. 64];
    public readonly Span<byte> T2D => ALL[64 .. 96];
}

internal struct ReadOnlyGE25519_NIELS_Packed
{
    public const int TypeByteSz = 96;
    private unsafe fixed byte __packed__[TypeByteSz];

    public ReadOnlyGE25519_NIELS_Packed(ReadOnlySpan<byte> data)
    {
        data[..TypeByteSz].CopyTo(ALL);
    }

    public static implicit operator ReadOnlyGE25519_NIELS_Packed(ReadOnlySpan<byte> data)
    {
        return new(data);
    }

    public static implicit operator ReadOnlySpan<byte>(ReadOnlyGE25519_NIELS_Packed packed)
    {
        return packed.ALL;
    }

    public static implicit operator ReadOnlyGE25519_NIELS_Packed(GE25519_NIELS_Packed packed)
    {
        return new(packed.ALL);
    }

    private unsafe readonly Span<byte> ALL
    {
        get
        {
            fixed (byte* ptr = &__packed__[0])
            {
                return new(ptr, TypeByteSz);
            }
        }
    }

    public readonly ReadOnlySpan<byte> YsubX => ALL[..32];
    public readonly ReadOnlySpan<byte> XaddY => ALL[32..64];
    public readonly ReadOnlySpan<byte> T2D => ALL[64..96];
}

