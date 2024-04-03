using System.Runtime.CompilerServices;

namespace Wheel.Crypto.Elliptic.EllipticCommon.VeryLongInt
{
    /// <summary>
    /// Variable time logical operations with very long integers (aka VLI)
    /// </summary>
	public static partial class VLI
    {
        /// <summary>
        /// Counts the number of bits required to represent the number, variable time version
        /// </summary>
        /// <param name="words"></param>
        /// <returns></returns>
        public static int NumBits_VT(ReadOnlySpan<ulong> words, int num_words)
        {
            // Search from the end until we find a non-zero word.
            //  We do it in reverse because we expect that most digits will be nonzero.
            int i;
            for (i = num_words - 1; i >= 0 && words[i] == 0; --i) ;
            int used_words = i + 1;

            ulong digit = words[used_words - 1];
            int bitcount;
            for (bitcount = 0; digit != 0; ++bitcount)
            {
                digit >>= 1;
            }

            return ((used_words - 1) << WORD_BITS_SHIFT) + bitcount;
        }

        /// <summary>
        /// Returns sign of left - right. Variable time.
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <param name="num_words"></param>
        /// <returns></returns>
        public static int Cmp_VT(ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, int num_words)
        {
            for (int i = num_words - 1; i >= 0; --i)
            {
                if (left[i] > right[i])
                {
                    return 1;
                }
                else if (left[i] < right[i])
                {
                    return -1;
                }
            }
            return 0;
        }
    }
}

