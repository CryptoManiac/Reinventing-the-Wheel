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
        
        public void ProcessBlocks(Span<AESBlock> blocks)
        {
            Span<byte> buffer = stackalloc byte[AESBlock.TypeByteSz];
            ref AESBlock bufferAsBlock = ref MemoryMarshal.Cast<byte, AESBlock>(buffer)[0];
            ref State bufferAsState = ref MemoryMarshal.Cast<byte, State>(buffer)[0];

            foreach (ref AESBlock current in blocks)
            {
                bufferAsBlock = IV;
                bufferAsState.Cipher(RoundKey);
                IV++;
                current.XorWithIv(bufferAsBlock);
            }
        }
    }
}
