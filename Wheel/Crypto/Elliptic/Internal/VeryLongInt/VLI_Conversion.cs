namespace Wheel.Crypto.Elliptic.Internal.VeryLongInt
{
	/// <summary>
	/// Format conversion operations for very long integers (aka VLI)
	/// </summary>
	internal static class VLI_Conversion
	{
        /// <summary>
        /// Converts big-endian bytes to an integer in the native format.
        /// </summary>
        /// <param name="native"></param>
        /// <param name="bytes"></param>
        /// <param name="num_bytes"></param>
		public static void BytesToNative(Span<ulong> native, ReadOnlySpan<byte> bytes, int num_bytes)
		{
			VLI_Arithmetic.Clear(native, (num_bytes + (VLI_Common.WORD_SIZE - 1)) / VLI_Common.WORD_SIZE);
            for (int i = 0; i < num_bytes; ++i)
            {
                int b = num_bytes - 1 - i;
                native[b / VLI_Common.WORD_SIZE] |= (ulong)bytes[i] << (8 * (b % VLI_Common.WORD_SIZE));
            }
        }

        /// <summary>
        /// Converts an integer in the native format to big-endian bytes.
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="num_bytes"></param>
        /// <param name="native"></param>
        public static void NativeToBytes(Span<byte> bytes, int num_bytes, ReadOnlySpan<ulong> native) {
            for (int i = 0; i < num_bytes; ++i) {
                int b = num_bytes - 1 - i;
                bytes[i] = (byte) (native[b / VLI_Common.WORD_SIZE] >> (8 * (b % VLI_Common.WORD_SIZE)));
            }
        }
	}
}

