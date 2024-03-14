namespace Wheel.Crypto.Elliptic.Internal.VeryLongInt
{
    /// <summary>
    /// Logical operations with very long integers (aka VLI)
    /// </summary>
	internal static class VLI_Logic
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
        /// Returns 1 if the provided number has non-zero bits set
        /// </summary>
        /// <param name="n"></param>
        /// <returns></returns>
        private static int OneOrZero(ulong n)
        {
            return (int) (1 - (((n - 1) >> (sizeof(ulong) - 1)) & 1));
        }

        /// <summary>
        /// Constant-time comparison to zero
        /// </summary>
        /// <param name="words">Long integer words</param>
        /// <returns>True if zero</returns>
        public static bool IsZero(ReadOnlySpan<ulong> words, int num_words)
        {
            return GetBits(words, num_words) == 0;
        }

        /// <summary>
        /// Accumulate and return non-zero bits
        /// </summary>
        /// <param name="words"></param>
        /// <param name="num_words"></param>
        /// <returns></returns>
        private static ulong GetBits(ReadOnlySpan<ulong> words, int num_words)
        {
            ulong bits = 0;
            for (int i = 0; i < num_words; ++i)
            {
                bits |= words[i];
            }
            return bits;
        }

        /// <summary>
        /// Check that specific bit is set
        /// </summary>
        /// <param name="words">Long integer words</param>
        /// <param name="bit"></param>
        /// <returns>True if bit 'bit' is set</returns>
        public static bool TestBit(ReadOnlySpan<ulong> words, int bit)
        {
            return 0 != (words[bit >> VLI_Common.WORD_BITS_SHIFT] & (VLI_Common.LOW_BIT_SET << (bit & VLI_Common.WORD_BITS_MASK)));
        }

        /// <summary>
        /// Counts the number of words in vli.
        /// </summary>
        /// <param name="words"></param>
        /// <returns></returns>
        private static int NumDigits(ReadOnlySpan<ulong> words, int max_words)
        {
            int i;
            // Search from the end until we find a non-zero digit.
            // We do it in reverse because we expect that most digits will be nonzero.
            for (i = max_words - 1; i >= 0 && words[i] == 0; --i) ;
            return (i + 1);
        }

        /// <summary>
        /// Counts the number of bits required to represent vli.
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

            return ((num_digits - 1) << VLI_Common.WORD_BITS_SHIFT) + i;
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
            return (diff == 0);
        }

        /// <summary>
        /// Returns sign of left - right, in constant time.
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <param name="num_words"></param>
        /// <returns></returns>
        public static int Cmp(ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, int num_words)
        {
            Span<ulong> tmp = stackalloc ulong[VLI_Common.ECC_MAX_WORDS];
            ulong borrow = VLI_Arithmetic.Sub(tmp, left, right, num_words);
            ulong bits = GetBits(tmp, num_words);
            return OneOrZero(bits) - 2 * OneOrZero(borrow);
        }

        /// <summary>
        /// Returns sign of left - right. Variable time.
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <param name="num_words"></param>
        /// <returns></returns>
        public static int CmpUnsafe(ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, int num_words) {
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

