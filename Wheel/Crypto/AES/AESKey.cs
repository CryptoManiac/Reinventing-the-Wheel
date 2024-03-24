using Wheel.Crypto.AES.Internal;

namespace Wheel.Crypto.AES
{
    /// <summary>
    /// Encapsulated symmetric encryption key
    /// </summary>
    public ref struct AESKey
    {
        internal unsafe fixed byte data[TypeByteSz];
        public const int TypeByteSz = 4 * AESCTR.Nk;

        /// <summary>
        /// Initialize new key by making a copy of provided bytes
        /// </summary>
        /// <param name="key">Secret data</param>
        public AESKey(ReadOnlySpan<byte> key) 
        {
            bytes.Clear();
            key.CopyTo(bytes);
        }

        private readonly unsafe Span<byte> bytes
        {
            get
            {
                fixed (void* ptr = &data[0])
                {
                    return new Span<byte>(ptr, TypeByteSz);
                }
            }
        }

        internal byte this[int index]
        {
            readonly get => bytes[index];
            set => bytes[index] = value;
        }

        public static implicit operator AESKey(ReadOnlySpan<byte> key)
        {
            return new AESKey(key);
        }
    }
}
