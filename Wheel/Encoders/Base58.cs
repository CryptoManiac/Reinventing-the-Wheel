namespace Wheel.Encoders
{
    /// <summary>
    /// Base58 encoding and decoding engine.
    /// The instances are guaranteed to have a deterministic memory size and executions of their methods are guaranteed to not result in allocation of any heap memory.
    /// Note: Based on this C++ implementation: https://bitcoin.stackexchange.com/a/96359
    /// </summary>
    public struct Base58Codec
    {
        /// <summary>
        /// Base58 alphabet as defined by the Bitcoin
        /// </summary>
        private static readonly char[] StaticBase58Map =
        [
          '1', '2', '3', '4', '5', '6', '7', '8',
          '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
          'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q',
          'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
          'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
          'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p',
          'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
          'y', 'z'
        ];

        /// <summary>
        /// Base58 character mapping table
        /// </summary>
        private static readonly byte[] StaticAlphaMap =
        [
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0xff, 0x11, 0x12, 0x13, 0x14, 0x15, 0xff,
          0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0xff, 0x2c, 0x2d, 0x2e,
          0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0xff, 0xff, 0xff, 0xff, 0xff
        ];

        /// <summary>
        /// On-stack copy of alphabet characters
        /// </summary>
        private unsafe fixed char Base58Map[58];

        /// <summary>
        /// On-stack copy of character mapping
        /// </summary>
        private unsafe fixed byte AlphaMap[256];

        /// <summary>
        /// Construct with a custom Base58 alphabet
        /// </summary>
        /// <param name="alphabet">Alphabet characters</param>
        /// <exception cref="ArgumentException">When the provided alphabet doesn't make any sense</exception>
        public unsafe Base58Codec(ReadOnlySpan<char> alphabet)
        {
            if (!CheckAlphabet(alphabet))
            {
                throw new ArgumentException("Incorrect alphabet");
            }

            if (alphabet.Length != 58)
            {
                throw new ArgumentException("The base58 alphabet is expected to be 58 characters long");
            }

            fixed (char* ptr = &Base58Map[0])
            {
                alphabet.CopyTo(new Span<char>(ptr, 58));
            }

            fixed (byte* ptr = &AlphaMap[0])
            {
                StaticAlphaMap.CopyTo(new Span<byte>(ptr, 256));
            }
        }

        /// <summary>
        /// Alphabet requirements:
        /// * Must not contain any duplicates
        /// * Must not contain any non-ASCII characters
        /// </summary>
        /// <param name="alphabet"></param>
        /// <returns>True if the alphabet is valid</returns>
        public static bool CheckAlphabet(ReadOnlySpan<char> alphabet)
        {
            uint bits = 0;

            foreach (var c in alphabet)
            {
                if (!char.IsAscii(c) || char.IsWhiteSpace(c)) {
                    return false; 
                }

                uint next_bits = bits ^ (bits << c);
                if (next_bits < bits)
                {
                    return false;
                }
                bits = next_bits;
            }

            return true;
        }

        /// <summary>
        /// Construct a new instance of codec by filling the buffers 
        /// </summary>
        public unsafe Base58Codec() : this(StaticBase58Map)
        {
        }

        /// <summary>
        /// Encode the contents of byte buffer and write the resulting characters into provided buffer
        /// </summary>
        /// <param name="result">Character buffer to fill</param>
        /// <param name="data">Data to encode</param>
        /// <returns>Number of written characters, if execution was successful. The required buffer length, if not.</returns>
        public unsafe int Encode(Span<char> result, ReadOnlySpan<byte> data)
        {
            // For the worst case
            Span<byte> b256 = stackalloc byte[(data.Length * 138 / 100) + 1];
            int b256Sz = 1;
            for (int i = 0; i < data.Length; ++i)
            {
                uint carry = data[i];
                for (int j = 0; j < b256Sz; ++j)
                {
                    carry += (uint)(b256[j] << 8);
                    b256[j] = (byte)(carry % 58);
                    carry /= 58;
                }
                for (; Convert.ToBoolean(carry); carry /= 58)
                    b256[b256Sz++] = (byte)(carry % 58);
            }

            int reqSz = data.Length + b256Sz;

            if (result.Length < reqSz)
            {
                // Caller must provide a buffer with the
                // sufficient space for the result characters
                return reqSz;
            }

            int written = 0;

            for (int i = 0; i < (data.Length - 1) && !Convert.ToBoolean(data[i]); ++i)
            {
                result[written++] = Base58Map[0];
            }

            for (int i = 0; i < b256Sz; ++i)
            {
                result[written++] = Base58Map[b256[b256Sz - 1 - i]];
            }

            return written;
        }

        /// <summary>
        /// Decode characters and write the resulting bytes into buffer
        /// </summary>
        /// <param name="result">Byte buffer to fill with the decoded bytes</param>
        /// <param name="encoded">Characters buffer to decode</param>
        /// <returns>Number of written bytes, if execution was successful. The required buffer length, if not.</returns>
        public unsafe int Decode(Span<byte> result, ReadOnlySpan<char> encoded)
        {
            // Bitcoin-consistent behaviour:
            // Skip whitespace characters
            ReadOnlySpan<char> data;
            {
                int idx_end, idx_start;
                for (idx_end = encoded.Length - 1; idx_end > 0 && char.IsWhiteSpace(encoded[idx_end]);) --idx_end;
                for (idx_start = 0; idx_start < encoded.Length && char.IsWhiteSpace(encoded[idx_start]); ++idx_start) ;
                data = encoded.Slice(idx_start, 1 + idx_end - idx_start);
            }

            // For the worst case
            int reqSz = (data.Length * 138 / 100) + 1;

            if (result.Length < reqSz)
            {
                // Caller must provide a buffer with the sufficient space
                //  for the result bytes
                return reqSz;
            }

            int byteSz = 1;
            for (int i = 0; i < data.Length; ++i)
            {
                uint carry = AlphaMap[data[i] & 0x7f];
                for (int j = 0; j < byteSz; j++, carry >>= 8)
                {
                    carry += (uint)(result[j] * 58);
                    result[j] = (byte)carry;
                }
                for (; Convert.ToBoolean(carry); carry >>= 8)
                {
                    result[byteSz++] = (byte)carry;
                }
            }

            int k = 0;
            for (; k < (data.Length - 1) && data[k] == Base58Map[0]; ++k)
            {
                result[byteSz + k] = 0;
            }

            result.Slice(0, byteSz + k).Reverse();
            return byteSz + k;
        }
    }
}
