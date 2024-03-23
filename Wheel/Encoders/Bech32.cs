namespace Wheel.Encoders
{
    public struct Bech32
    {
        public enum DecodingResult
        {
            success,
            buffersTooShort,
            checksumMismatch,
            incorrectChecksumSize,
            incorrectHrpSize,
            invalidCase,
            characterOutOfRange,
            invalidCharacter,
            noChecksumMarker,
            nonPrintableCharacter,
            stringLengthExceeded,
            stringLengthTruncated
        }

        public enum EncodingResult
        {
            success,
            buffersTooShort,
            incorrectHrpSize,
            invalidCharacter,
            stringLengthExceeded
        }

        private static uint BECH32M_CONST = 0x2bc830a3;
        private static uint BECH32_CONST = 1;

        /// <summary>
        /// checksum is always 6 chars long
        /// </summary>
        const int ChecksumSize = 6;

        // human-readable part of a bech32 string can only be between 1 and 83 characters long
        const int MinHRPSize = 1;
        public const int MaxHRPSize = 83;

        // while there are only 32 valid character values in a bech32 string, other characters
        // can be present but will be stripped out. however, all character values must fall
        // within the following range.

        const int MinBECH32Value = 33;  // ascii '!'
        const int MaxBECH32Value = 126; // ascii '~'

        // entire bech32 string can only be a certain size (after invalid characters are stripped out)
        const int MinBECH32Size = 8;  // MinHRPSize + '1' + ChecksumSize
        public const int MaxBECH32Size = 90; // MaxHRPSize + '1' + ChecksumSize

        /// <summary>
        /// Bech32 checksum delimiter
        /// </summary>
        private static char checksumMarker = '1';

        /// <summary>
        /// Bech32 character set for encoding
        /// </summary>
        private static char[] encCharset = [
            'q', 'p', 'z', 'r', 'y', '9', 'x', '8',
            'g', 'f', '2', 't', 'v', 'd', 'w', '0',
            's', '3', 'j', 'n', '5', '4', 'k', 'h',
            'c', 'e', '6', 'm', 'u', 'a', '7', 'l'
        ];

        private static uint[] gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

        /// <summary>
        /// Bech32 character set for decoding
        /// </summary>
        private static sbyte[] decCharset = [
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
            -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
             1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
            -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
             1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
        ];

        private uint checksumConst;

        /// <summary>
        /// Configure new codec instance
        /// </summary>
        /// <param name="bech32M">Use BECH32M variant</param>
        public Bech32(bool bech32M)
        {
            checksumConst = bech32M ? BECH32M_CONST : BECH32_CONST;
        }

        /// <summary>
        /// Configure a legacy codec instance
        /// </summary>
        public Bech32() : this(false)
        {
        }

        /// <summary>
        /// Convert all characters to lower case
        /// </summary>
        /// <param name="str"></param>
        private static void ConvertToLowercase(Span<char> str)
        {
            for (int i = 0; i < str.Length; ++i)
            {
                str[i] = char.ToLower(str[i]);
            }
        }

        /// <summary>
        /// Find the position of checksum marker
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        private static int FindSeparatorPosition(ReadOnlySpan<char> str)
        {
            for (int i = str.Length - 1; i >= 0; --i)
            {
                if (str[i] == checksumMarker)
                {
                    return i;
                }
            }

            return -1;
        }

        /// <summary>
        /// Find the polynomial with value coefficients mod the generator as 30-bit.
        /// </summary>
        /// <param name="values"></param>
        /// <returns></returns>
        private uint polymod(ReadOnlySpan<byte> values)
        {
            uint chk = 1;
            foreach (byte v in values)
            {
                uint top = (chk >> 25);
                chk = (chk & 0x1ffffff) << 5 ^ v;
                for (int i =0; i < 5; ++i)
                {
                    chk ^= ((top >> i) & 1) == 0 ? 0 : gen[i];
                }
            }

            return chk;
        }

        /// <summary>
        /// Expand HRP for checksum calculation
        /// </summary>
        /// <param name="result"></param>
        /// <param name="hrp"></param>
        /// <returns>Required buffer length</returns>
        /// <exception cref="InvalidDataException">HRP must not contain anything but the ASCII alphanumeric characters</exception>
        private int expandHrp(Span<byte> result, ReadOnlySpan<char> hrp)
        {
            int sz = hrp.Length;
            int reqSz = sz * 2 + 1;

            if (reqSz > result.Length)
            {
                // Caller must provide a buffer
                // with sufficient space
                return reqSz;
            }

            for (int i = 0; i < sz; ++i)
            {
                byte c = (byte)(hrp[i]);
                result[i] = (byte)(c >> 5);
                result[i + sz + 1] = (byte)(c & 0x1f);
            }
            result[sz] = 0;
            return reqSz;
        }

        /// <summary>
        /// Concatenate expanded HRP with binary data
        /// </summary>
        /// <param name="result">Result to fill</param>
        /// <param name="hrp"></param>
        /// <param name="data"></param>
        /// <returns>Required buffer size</returns>
        private int concatHRP(Span<byte> result, ReadOnlySpan<char> hrp, ReadOnlySpan<byte> data)
        {
            int hrpSz = expandHrp(null, hrp);
            int reqSz = hrpSz + data.Length;

            if (reqSz > result.Length)
            {
                // Must provide buffer of the required size
                return reqSz;
            }

            expandHrp(result.Slice(0, hrpSz), hrp);
            data.CopyTo(result.Slice(hrpSz));

            return reqSz;
        }

        /// <summary>
        /// Verify checksum for given HRP and data vector
        /// </summary>
        /// <param name="hrp"></param>
        /// <param name="dp"></param>
        /// <returns>True on success</returns>
        private bool verifyChecksum(ReadOnlySpan<char> hrp, ReadOnlySpan<byte> data)
        {
            Span<byte> data_to_check = stackalloc byte[concatHRP(null, hrp, data)];
            concatHRP(data_to_check, hrp, data);
            return polymod(data_to_check) == checksumConst;
        }

        /// <summary>
        /// Calculate checksum for given HRP + data and write them into buffer
        /// </summary>
        /// <param name="result">Buffer to be filled</param>
        /// <param name="hrp"></param>
        /// <param name="data"></param>
        /// <returns>Required buffer size</returns>
        private int createChecksum(Span<byte> result, ReadOnlySpan<char> hrp, ReadOnlySpan<byte> data)
        {
            if (ChecksumSize > result.Length)
            {
                // Must provide buffer of the required size
                return ChecksumSize;
            }
            Span<byte> data_to_check = stackalloc byte[concatHRP(null, hrp, data) + ChecksumSize];
            data_to_check.Clear(); // Init with zeros
            concatHRP(data_to_check.Slice(0, data_to_check.Length - ChecksumSize), hrp, data);
            uint mod = polymod(data_to_check) ^ checksumConst;
            for (int i = 0; i < ChecksumSize; ++i)
            {
                result[i] = (byte)((mod >> (5 * (5 - i))) & 31);
            }
            return ChecksumSize;
        }

        public EncodingResult Encode(Span<char> result, out int reqSz, ReadOnlySpan<char> hrp, ReadOnlySpan<byte> data)
        {
            reqSz = hrp.Length + 1 + data.Length + ChecksumSize;

            if (reqSz > result.Length)
            {
                return EncodingResult.buffersTooShort;
            }

            if (hrp.Length > MaxHRPSize || hrp.Length < MinHRPSize)
            {
                return EncodingResult.incorrectHrpSize;
            }

            if (hrp.Length + 1 + data.Length > MaxBECH32Size)
            {
                return EncodingResult.stringLengthExceeded;
            }

            Span<byte> combined = stackalloc byte[data.Length + ChecksumSize];
            Span<byte> checksum = combined.Slice(combined.Length - ChecksumSize);

            data.CopyTo(combined);
            Span<char> hrp_copy = stackalloc char[hrp.Length];
            hrp.CopyTo(hrp_copy);
            ConvertToLowercase(hrp_copy);
            createChecksum(checksum, hrp_copy, data);

            hrp_copy.CopyTo(result);
            result[hrp.Length] = checksumMarker;

            int codedSz = hrp.Length + 1;
            foreach (var c in combined)
            {
                if (c > encCharset.Length - 1)
                {
                    result.Clear();
                    return EncodingResult.invalidCharacter;
                }
                result[codedSz++] = encCharset[c];
            }

            return EncodingResult.success;
        }

        public DecodingResult Decode(Span<char> hrp, Span<byte> data, out (int, int) reqSz, ReadOnlySpan<char> str)
        {
            reqSz = (0, 0);

            if (str.Length > MaxBECH32Size)
            {
                return DecodingResult.stringLengthExceeded;
            }

            if (str.Length < MinBECH32Size)
            {
                return DecodingResult.stringLengthTruncated;
            }

            bool hasUpper = false;
            bool hasLower = false;

            foreach (char c in str)
            {
                if (c < MinBECH32Value || c > MaxBECH32Value)
                {
                    return DecodingResult.nonPrintableCharacter;
                }

                if (char.IsUpper(c))
                {
                    hasUpper = true;
                }

                if (char.IsLower(c))
                {
                    hasLower = true;
                }
            }

            if (hasLower && hasUpper)
            {
                return DecodingResult.invalidCase;
            }

            int pos = FindSeparatorPosition(str);

            if (-1 == pos)
            {
                return DecodingResult.noChecksumMarker;
            }

            if (pos < MinHRPSize || pos > MaxHRPSize)
            {
                return DecodingResult.incorrectHrpSize;
            }

            if (str.Length < pos + 7)
            {
                return DecodingResult.incorrectChecksumSize;
            }

            int dataSz = str.Length - 1 - pos;

            if (pos > hrp.Length || dataSz > data.Length)
            {
                reqSz = (pos, dataSz);
                return DecodingResult.buffersTooShort;
            }

            Span<byte> values = stackalloc byte[dataSz];
            Span<byte> dp = values.Slice(0, dataSz - ChecksumSize);

            for (int i = 0; i < dataSz; ++i)
            {
                var c = str[i + pos + 1];
                if (c > decCharset.Length - 1)
                {
                    return DecodingResult.characterOutOfRange;
                }
                sbyte d = decCharset[c];
                if (d == -1)
                {
                    return DecodingResult.invalidCharacter;
                }
                values[i] = (byte)d;
            }

            Span<char> hrp_copy = stackalloc char[pos];
            str.Slice(0, pos).CopyTo(hrp_copy);
            ConvertToLowercase(hrp_copy);

            if (!verifyChecksum(hrp_copy, values))
            {
                return DecodingResult.checksumMismatch;
            }

            // Whire result buffers
            str.Slice(0, pos).CopyTo(hrp);
            dp.CopyTo(data);

            reqSz = (hrp_copy.Length, dp.Length);

            return DecodingResult.success;
        }
    }
}
