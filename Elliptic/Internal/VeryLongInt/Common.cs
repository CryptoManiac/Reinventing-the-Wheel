namespace Wheel.Crypto.Elliptic.Internal.VeryLongInt
{
	internal static partial class VLI {
        /// In our implementation, we're set on using the ulong type as a machine word
        /// This means that the word is 8 bytes (64 bits) long
        public const ulong HIGH_BIT_SET = 0x8000000000000000;
        public const ulong LOW_BIT_SET = 1;
        public const int WORD_BITS_MASK = 0x03F;
        public const int WORD_SIZE = sizeof(ulong);
        public const int WORD_BITS = WORD_SIZE * 8;
        public const int ECC_MAX_WORDS = 32 / WORD_SIZE; // For SECP256K1
        public const int WORD_BITS_SHIFT = 6;

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
                readonly get => index.CompareTo(UInt64.MinValue) == 0 ? s0 : s1;
                set => throw new InvalidOperationException("Not supported");
            }
        }

        /// <summary>
        /// Choose between two spans by either zero or non-zero index
        /// </summary>
        /// <typeparam name="T">Index type (comparable value)</typeparam>
        public ref struct QuadPicker
        {
            readonly ReadOnlySpan<ulong> s0;
            readonly ReadOnlySpan<ulong> s1;
            readonly ReadOnlySpan<ulong> s2;
            readonly ReadOnlySpan<ulong> s3;
            public QuadPicker(ReadOnlySpan<ulong> s0, ReadOnlySpan<ulong> s1, ReadOnlySpan<ulong> s2, ReadOnlySpan<ulong> s3)
            {
                this.s0 = s0;
                this.s1 = s1;
                this.s2 = s2;
                this.s3 = s3;
            }
            public ReadOnlySpan<ulong> this[ulong index]
            {
                readonly get
                {
                    switch(index)
                    {
                        case 0: return s0;
                        case 1: return s1;
                        case 2: return s2;
                        case 3: return s3;
                        default:
                            throw new InvalidOperationException("Index must be within [0 .. 3] bounds");
                    }
                }
                set => throw new InvalidOperationException("Not supported");
            }
        }
    }
}

