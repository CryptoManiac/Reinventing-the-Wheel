namespace Wheel.Crypto.Elliptic.EdDSA.Internal.GroupElement;

internal struct GE25519_NIELS_Packed
{
    public const int TypeByteSz = 96;
    private unsafe fixed byte __packed__[TypeByteSz];

    public GE25519_NIELS_Packed()
    {
        throw new InvalidOperationException("Constructor shouldn't be called");
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
