namespace Wheel.Crypto.Elliptic.Internal.VeryLongInt
{
	/// <summary>
	/// Format conversion operations for very long integers (aka VLI)
	/// </summary>
	internal static class VLI_Conversion
	{
		/// <summary>
		/// Write a dump of VLI into the given byte buffer
		/// </summary>
		/// <param name="result"></param>
		/// <param name="words"></param>
		/// <param name="max_words"></param>
		public static void ToBytes(Span<byte> bytes, ReadOnlySpan<ulong> native)
		{
            int num_bytes = bytes.Length;
            for (int i = 0; i < num_bytes; ++i)
            {
                int b = num_bytes - 1 - i;
                bytes[i] = (byte) (native[b / VLI_Common.WORD_SIZE] >> (8 * (b % VLI_Common.WORD_SIZE)));
            }
        }

		/// <summary>
		/// Convert the contents of byte buffer into VLI
		/// </summary>
		/// <param name="native"></param>
		/// <param name="bytes"></param>
		public static void FromBytes(Span<ulong> native, ReadOnlySpan<byte> bytes)
		{
            int num_bytes = bytes.Length;
            VLI_Arithmetic.Clear(native, (num_bytes + (VLI_Common.WORD_SIZE - 1)) / VLI_Common.WORD_SIZE);

            for (int i = 0; i < num_bytes; ++i)
            {
                int b = num_bytes - 1 - i;
                native[b / VLI_Common.WORD_SIZE] |= (ulong)bytes[i] << (8 * (b % VLI_Common.WORD_SIZE));
            }
        }
    }
}

