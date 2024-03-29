using Wheel.Crypto.Symmetric.AES.Internal;

namespace Wheel.Crypto.Symmetric.AES
{
    /// <summary>
    /// Represents the AES data block
    /// </summary>
    public struct AESBlock : IDisposable
    {
        private unsafe fixed byte data[TypeByteSz];
        public const int TypeByteSz = AESCTR.AES_BLOCK_LEN;

        private readonly unsafe Span<byte> bytes
        {
            get
            {
                fixed (void* ptr = &data[0])
                {
                    return new Span<byte>(ptr, AESCTR.AES_BLOCK_LEN);
                }
            }
        }

        /// <summary>
        /// Initialize new block by making a copy of provided data
        /// </summary>
        /// <param name="data">Block data</param>
        public AESBlock(in ReadOnlySpan<byte> data)
        {
            bytes.Clear();
            data.CopyTo(bytes);
        }

        public byte this[int index]
        { 
            readonly get => bytes[index];
            set => bytes[index] = value;
        }

        public unsafe static AESBlock operator ++(AESBlock block)
        {
            // Treat AES counter as a big-endian integer
            for (int i = AESCTR.AES_BLOCK_LEN - 1; i >= 0; --i)
            {
                ref byte curr = ref block.data[i];
                if (0xff == curr)
                {
                    curr = 0x00;
                }
                else
                {
                    ++curr;
                    break;
                }
            }

            return block;
        }

        public unsafe void XorWithIv(in AESBlock Iv)
        {
            // The block in AES is always 128bit no matter the key size
            for (int i = 0; i < TypeByteSz; ++i)
            {
                data[i] ^= Iv.data[i];
            }
        }

        /// <summary>
        /// Converts by making a copy
        /// </summary>
        /// <param name="data"></param>
        public static implicit operator AESBlock(in ReadOnlySpan<byte> data)
        {
            return new AESBlock(data);
        }

        /// <summary>
        /// Fill the padding data for given block
        /// </summary>
        /// <param name="block">Last block to be encrypted</param>
        /// <param name="totalLen">Total length of encypted data (excluding the padding block)</param>
        public static void FillPaddingBlock(ref AESBlock block, int totalLen)
        {
            // Check out this page to understand what is happening here: https://asecuritysite.com/hazmat/hashnew28
            // Choose PKCS7 and 128-bit block size.
            int padLen = TypeByteSz - (totalLen % TypeByteSz);
            block.bytes.Slice(TypeByteSz - padLen).Fill((byte)padLen);
        }

        /// <summary>
        /// Get padding length for decrypted data
        /// </summary>
        /// <param name="block">Last decrypted block</param>
        /// <returns>Padding length (bytes at the end to be ignored after decryption)</returns>
        public unsafe static int GetPaddingLen(in AESBlock block)
        {
            return block.data[TypeByteSz - 1];
        }

        /// <summary>
        /// Get number of required blocks to encrypt the given number of bytes
        /// </summary>
        /// <param name="totalLen"></param>
        /// <returns>Number of data blocks plus padding block</returns>
        public static int GetBlocksWithPadding(int totalLen)
        {
            int padLen = TypeByteSz - (totalLen % TypeByteSz);
            return (totalLen + padLen) / TypeByteSz;
        }

        public void Dispose()
        {
            bytes.Clear();
        }
    }

}
