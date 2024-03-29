namespace Wheel.Crypto.Elliptic.Internal.VeryLongInt
{
    /// <summary>
    /// Logical operations with very long integers (aka VLI)
    /// </summary>
	internal static partial class VLI
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
        /// Counts the number of words in 
        /// </summary>
        /// <param name="words"></param>
        /// <returns></returns>
        private static int NumDigits(ReadOnlySpan<ulong> words, int max_words)
        {
            int i;
            // Search from the end until we find a non-zero digit.
            // We do it in reverse because we expect that most digits will be nonzero.
            for (i = max_words - 1; i >= 0 && words[i] == 0; --i) ;
            return i + 1;
        }

        /// <summary>
        /// Counts the number of bits required to represent 
        /// </summary>
        /// <param name="words"></param>
        /// <returns></returns>
        public static int NumBits(ReadOnlySpan<ulong> words, int max_words)
        {
            int num_digits = NumDigits(words, max_words);
            if (num_digits == 0)
            {
                return 0;
            }

            ulong digit = words[num_digits - 1];
            int i;
            for (i = 0; digit != 0; ++i)
            {
                digit >>= 1;
            }

            return ((num_digits - 1) << WORD_BITS_SHIFT) + i;
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
            Span<ulong> tmp = stackalloc ulong[ECC_MAX_WORDS];
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

