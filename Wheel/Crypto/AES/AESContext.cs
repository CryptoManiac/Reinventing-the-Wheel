using System.Runtime.InteropServices;
using Wheel.Crypto.AES.Internal;

namespace Wheel.Crypto.AES
{
    /// <summary>
    /// AES-CTR encryption/decryption context
    /// </summary>
    public ref struct AESContext
    {
        private AESRoundKey RoundKey;
        private AESBlock IV;

        /// <summary>
        /// Construct and init
        /// </summary>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        public AESContext(in AESKey key, in AESBlock iv) : this()
        {
            Init(key, iv);
        }

        /// <summary>
        /// Initialize symmetric encryption context
        /// </summary>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        public void Init(in AESKey key, in AESBlock iv)
        {
            RoundKey.Expand(key);
            IV = iv;
        }

        /// <summary>
        /// Process a single block
        /// </summary>
        /// <param name="block"></param>
        public void ProcessBlock(ref AESBlock block)
        {
            AESBuffer buffer = stackalloc byte[AESBlock.TypeByteSz];
            buffer.AsBlock = IV;
            buffer.AsState.Cipher(RoundKey);
            IV++;
            block.XorWithIv(buffer.AsBlock);
        }

        /// <summary>
        /// Process multiple blocks
        /// </summary>
        /// <param name="blocks"></param>
        public void ProcessBlocks(Span<AESBlock> blocks)
        {
            AESBuffer buffer = stackalloc byte[AESBlock.TypeByteSz];
            foreach (ref AESBlock block in blocks)
            {
                buffer.AsBlock = IV;
                buffer.AsState.Cipher(RoundKey);
                IV++;
                block.XorWithIv(buffer.AsBlock);
            }
        }
    }
}
