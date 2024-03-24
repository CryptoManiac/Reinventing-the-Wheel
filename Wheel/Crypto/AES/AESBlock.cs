using Wheel.Crypto.AES.Internal;

namespace Wheel.Crypto.AES
{
    /// <summary>
    /// Represents the AES data block
    /// </summary>
    public struct AESBlock
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
        public AESBlock(ReadOnlySpan<byte> data)
        {
            bytes.Clear();
            data.CopyTo(bytes);
        }

        public byte this[int index]
        {
            get => bytes[index];
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

        public static implicit operator AESBlock(ReadOnlySpan<byte> data)
        {
            return new AESBlock(data);
        }

        public static int GetBlocksWithPadding(ReadOnlySpan<byte> data)
        {
            int wholeBlocks = data.Length / TypeByteSz;
            int extraBlock = Convert.ToInt32(0 < data.Length - wholeBlocks * TypeByteSz);
            return wholeBlocks + extraBlock;
        }
    }

}
