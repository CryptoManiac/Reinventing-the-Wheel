using System.Runtime.InteropServices;

namespace Wheel.Crypto.AES.Internal
{
    /// <summary>
    /// View buffer as either block or state
    /// </summary>
    internal ref struct AESBuffer
    {
        private readonly Span<byte> buffer;

        public AESBlock AsBlock
        {
            readonly get => MemoryMarshal.Cast<byte, AESBlock>(buffer)[0];
            set => MemoryMarshal.Cast<byte, AESBlock>(buffer)[0] = value;
        }

        public State AsState
        {
            readonly get => MemoryMarshal.Cast<byte, State>(buffer)[0];
            set => MemoryMarshal.Cast<byte, State>(buffer)[0] = value;
        }

        public AESBuffer(Span<byte> buffer)
        {
            if (buffer.Length != AESBlock.TypeByteSz)
            {
                throw new InvalidOperationException("Insufficient buffer size");
            }

            this.buffer = buffer;
        }

        public static implicit operator AESBuffer(Span<byte> buffer)
        {
            return new AESBuffer(buffer);
        }
    }
}
