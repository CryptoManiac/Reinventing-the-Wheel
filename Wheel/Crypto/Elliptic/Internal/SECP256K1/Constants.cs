using Wheel.Crypto.Elliptic.Internal.VeryLongInt;

namespace Wheel.Crypto.Elliptic.Internal.SECP256K1
{
    /// <summary>
    /// Properties and methods every EC implementation must provide
    /// </summary>
    internal interface ICurve
    {
        public int NUM_WORDS { get; }
        public int NUM_BYTES { get; }
        public int NUM_BITS { get; }
        public int NUM_N_WORDS { get; }
        public int NUM_N_BYTES { get; }
        public int NUM_N_BITS { get; }

        public ReadOnlySpan<ulong> p { get; }
        public ReadOnlySpan<ulong> n { get; }
        public ReadOnlySpan<ulong> half_n { get; }
        public ReadOnlySpan<ulong> G { get; }
        public ReadOnlySpan<ulong> b { get; }

        public void ModSQRT(Span<ulong> a);
        public void XSide(Span<ulong> result, ReadOnlySpan<ulong> x);
        public void MMod(Span<ulong> result, Span<ulong> product);
    }

    /// <summary>
    /// SECP256K1 curve constants
    /// </summary>
    internal static class Constants
    {
        public const int NUM_WORDS = VLI_Common.ECC_MAX_WORDS;
        public const int NUM_BYTES = VLI_Common.ECC_MAX_WORDS * VLI_Common.WORD_SIZE;
        public const int NUM_N_WORDS = VLI_Common.ECC_MAX_WORDS;
        public const int NUM_N_BITS = VLI_Common.ECC_MAX_WORDS * VLI_Common.WORD_BITS;
        public const int NUM_N_BYTES = VLI_Common.ECC_MAX_WORDS * VLI_Common.WORD_BITS / 8;

        public static readonly ulong[] p = new ulong[] {
            0xFFFFFFFEFFFFFC2F,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF
        };
        public static readonly ulong[] n = new ulong[] {
            0xBFD25E8CD0364141,
            0xBAAEDCE6AF48A03B,
            0xFFFFFFFFFFFFFFFE,
            0xFFFFFFFFFFFFFFFF
        };
        public static readonly ulong[] half_n = new ulong[] {
            0xdfe92f46681b20a0,
            0x5d576e7357a4501d,
            0xFFFFFFFFFFFFFFFE,
            0xFFFFFFFFFFFFFFFF
        };
        public static readonly ulong[] G = new ulong[] {
            0x59F2815B16F81798,
            0x029BFCDB2DCE28D9,
            0x55A06295CE870B07,
            0x79BE667EF9DCBBAC,

            0x9C47D08FFB10D4B8,
            0xFD17B448A6855419,
            0x5DA4FBFC0E1108A8,
            0x483ADA7726A3C465
        };
        public static readonly ulong[] b = new ulong[] {
            0x0000000000000007,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000
        };
    }
}
