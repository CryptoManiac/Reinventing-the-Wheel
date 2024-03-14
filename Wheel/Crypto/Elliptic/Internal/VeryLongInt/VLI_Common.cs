namespace Wheel.Crypto.Elliptic.Internal.VeryLongInt
{
	internal static class VLI_Common
	{
        /// In our implementation, we're set on using the ulong type as a machine word
        /// This means that the word is 8 bytes (64 bits) long
        public const ulong HIGH_BIT_SET = 0x8000000000000000;
        public const ulong LOW_BIT_SET = 1;
        public const int WORD_BITS_MASK = 0x03F;
        public const int WORD_SIZE = sizeof(ulong);
        public const int WORD_BITS = WORD_SIZE * 8;
        public const int ECC_MAX_WORDS = 32 / WORD_SIZE; // For SECP256K1
        public const int WORD_BITS_SHIFT = 6;

        public static int BITS_TO_WORDS(int num_bits) => (num_bits + ((WORD_SIZE * 8) - 1)) / (WORD_SIZE * 8);
        public static int BITS_TO_BYTES(int num_bits) => (num_bits + 7) / 8;

        /// <summary>
        /// Choose between two spans by either zero or non-zero index
        /// </summary>
        /// <typeparam name="T">Index type (comparable value)</typeparam>
        public ref struct Picker<T> where T : IComparable
        {
            readonly Span<ulong> s0;
            readonly Span<ulong> s1;
            public Picker(Span<ulong> s0, Span<ulong> s1)
            {
                this.s0 = s0;
                this.s1 = s1;
            }
            public Span<ulong> this[T index]
            {
                readonly get => index.CompareTo(0) == 0 ? s0 : s1;
                set => throw new InvalidOperationException("Not supported");
            }
        }
    }
}

