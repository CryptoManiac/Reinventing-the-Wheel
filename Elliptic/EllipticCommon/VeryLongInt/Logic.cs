namespace Wheel.Crypto.Elliptic.EllipticCommon.VeryLongInt
{
    /// <summary>
    /// Logical operations with very long integers (aka VLI)
    /// </summary>
	public static partial class VLI
	{
        /// <summary>
        /// Returns true for even integers
        /// </summary>
        /// <param name="words"></param>
        /// <returns></returns>
        public static bool IsEven(ReadOnlySpan<ulong> words)
        {
            return 0 == (words[0] & 1u);
        }

        /// <summary>
        /// Constant-time comparison to zero
        /// </summary>
        /// <param name="words">Long integer words</param>
        /// <returns>True if zero</returns>
        public static bool IsZero(ReadOnlySpan<ulong> words, int num_words)
        {
            ulong bits = 0;
            for (int i = 0; i < num_words; ++i)
            {
                bits |= words[i];
            }
            return !Convert.ToBoolean(bits);
        }

        /// <summary>
        /// Check that specific bit is set
        /// </summary>
        /// <param name="words">Long integer words</param>
        /// <param name="bit"></param>
        /// <returns>True if bit 'bit' is set</returns>
        public static bool TestBit(ReadOnlySpan<ulong> words, int bit)
        {
            return Convert.ToBoolean(words[bit >> WORD_BITS_SHIFT] & (LOW_BIT_SET << (bit & WORD_BITS_MASK)));
        }

        /// <summary>
        /// Counts the number of used words, in constant time
        /// </summary>
        /// <param name="words"></param>
        /// <returns></returns>
        private static int NumDigits(ReadOnlySpan<ulong> words, int max_words)
        {
            // Constant-time check for number of used words:
            //  Iterate through all words regardless of their value
            int used_words = 0;
            for (int i = max_words; i > 0; --i)
            {
                // Mask will be 0xffffffff only when used_words is not set,
                //  it will be zero otherwise
                uint mask = (uint)-Convert.ToInt32(!Convert.ToBoolean(used_words));

                // If used_words is zero then the 0xffffffff mask will allow addition
                //  of current index to used_words. This operation will "add" zero otherwise.
                used_words += (int)(i & mask);
            }

            return used_words;
        }

        /// <summary>
        /// Counts the number of bits required to represent the number, in constant time
        /// </summary>
        /// <param name="words"></param>
        /// <returns></returns>
        public static int NumBits(ReadOnlySpan<ulong> words, int max_words)
        {
            int num_digits = NumDigits(words, max_words);

            // If the number of used words is zero then the mask will be zero, resulting
            //  with getting the first element of word array, which is zero itself.
            int zeroOrIndex = (int)((num_digits - 1) & (uint)-Convert.ToInt32(0 != num_digits));
            ulong digit = words[zeroOrIndex];

            // Constant-time bitcoint: iterate through
            //  all bits regardless of their value
            int i = 0;
            for (int k = 0; k < WORD_BITS; ++k)
            {
                // Increment by one and shift by one if the word
                // is zero, perform the no-ops otherwise
                int oneIfHaveBits = Convert.ToInt32(Convert.ToBoolean(digit));
                i += oneIfHaveBits;
                digit >>= oneIfHaveBits;
            }

            return (zeroOrIndex << WORD_BITS_SHIFT) + i;
        }

        /// <summary>
        /// Constant-time comparison
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <returns>True if left == right</returns>
        public static bool Equal(ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, int num_words)
        {
            ulong diff = 0;
            for (int i = 0; i != num_words; ++i)
            {
                diff |= left[i] ^ right[i];
            }
            return !Convert.ToBoolean(diff);
        }

        /// <summary>
        /// Returns sign of left - right, in constant time.
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <param name="num_words"></param>
        /// <returns></returns>
        public static int ConstTimeCmp(ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, int num_words)
        {
            Span<ulong> tmp = stackalloc ulong[num_words];
            bool neg = Convert.ToBoolean(Sub(tmp, left, right, num_words));
            bool equal = IsZero(tmp, num_words);
            return (Convert.ToInt32(!equal) - 2 * Convert.ToInt32(neg));
        }

        /// <summary>
        /// Returns sign of left - right. Variable time.
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <param name="num_words"></param>
        /// <returns></returns>
        public static int VarTimeCmp(ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, int num_words) {
            for (int i = num_words - 1; i >= 0; --i) {
                if (left[i] > right[i]) {
                    return 1;
                } else if (left[i] < right[i]) {
                    return -1;
                }
            }
            return 0;
        }
    }
}

