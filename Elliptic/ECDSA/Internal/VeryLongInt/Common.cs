namespace Wheel.Crypto.Elliptic.ECDSA.Internal;

internal static partial class VLI
{
    /// In our implementation, we're set on using the ulong type as a machine word
    /// This means that the word is 8 bytes (64 bits) long
    public const ulong HIGH_BIT_SET = 0x8000000000000000;
    public const ulong LOW_BIT_SET = 1;
    public const int WORD_BITS_MASK = 0x03F;
    public const int WORD_SIZE = sizeof(ulong);
    public const int WORD_BITS = WORD_SIZE * 8;
    public const int ECC_MAX_WORDS = 72 / WORD_SIZE; // For SECP521R1
    public const int WORD_BITS_SHIFT = 6;

    /// <summary>
    /// Choose between four memory spans by index without branching
    /// </summary>
    public ref struct QuadPicker
    {
        #region Pointers to the sequences
        unsafe readonly ulong* s0;
        unsafe readonly ulong* s1;
        unsafe readonly ulong* s2;
        unsafe readonly ulong* s3;
        #endregion

        /// <summary>
        /// Element size array
        /// </summary>
        unsafe fixed int sizes[4];

        public unsafe QuadPicker(ReadOnlySpan<ulong> s0, ReadOnlySpan<ulong> s1, ReadOnlySpan<ulong> s2, ReadOnlySpan<ulong> s3)
        {
            // Get wrapped addresses
            //  This structure is kept on stack and not moved so this is safe thing to do.
            //  WARNING: DON'T anything like that for other scenarios.

            #region Hacky address magic
            fixed (void* ptr = s0)
            {
                this.s0 = (ulong*)ptr;
            }

            fixed (void* ptr = s1)
            {
                this.s1 = (ulong*)ptr;
            }

            fixed (void* ptr = s2)
            {
                this.s2 = (ulong*)ptr;
            }

            fixed (void* ptr = s3)
            {
                this.s3 = (ulong*)ptr;
            }
            #endregion

            // Save sequence sizes
            //  Will be needed in getter to reconstruct spans
            sizes[0] = s0.Length;
            sizes[1] = s1.Length;
            sizes[2] = s2.Length;
            sizes[3] = s3.Length;
        }
        public unsafe readonly ReadOnlySpan<ulong> this[ulong index]
        {
            get
            {
                ulong** ptrs = stackalloc ulong*[4] { s0, s1, s2, s3 };
                return new(ptrs[index % 4], sizes[index % 4]);
            }
        }
    }
}

