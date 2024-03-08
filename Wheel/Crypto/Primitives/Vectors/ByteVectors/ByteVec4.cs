

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Wheel.Crypto.Primitives.ByteVectors
{
    /// <summary>
    /// 4 bytes long vector which can be represented as either one 32-bit integer or four bytes
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public struct ByteVec4
    {
        /// <summary>
        /// 32-bit integer value
        /// </summary>
        [FieldOffset(0)]
        public uint value;

        public ByteVec4()
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="word">Value to construct from</param>
        public ByteVec4(uint word)
        {
            value = word;
        }

        /// <summary>
        /// Implicit cast operator
        /// </summary>
        /// <param name="word">Value to convert from</param>
        public static implicit operator ByteVec4(uint word)
        {
            return new ByteVec4(word);
        }

        /// <summary>
        /// Set to zero
        /// </summary>
        public void Reset()
        {
            value = 0;
        }

        /// <summary>
        /// Load value from given span
        /// </summary>
        /// <param name="from"></param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public unsafe void Load(Span<byte> from)
        {
            if (4 != from.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(from), from.Length, "Span must be exactly 4 bytes long");
            }

            fixed (byte* target = &b00)
            {
                var to = new Span<byte>(target, 4);
                from.CopyTo(to);
            }
        }

        /// <summary>
        /// Dump vector contents
        /// </summary>
        /// <param name="bytes"></param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public unsafe readonly void Store(Span<byte> to)
        {
            if (to.Length > 4)
            {
                throw new ArgumentOutOfRangeException(nameof(to), to.Length, "Span must not be longer than 4 bytes");
            }

            fixed (byte* source = &b00)
            {
                var from = new Span<byte>(source, to.Length);
                from.CopyTo(to);
            }
        }

        /// <summary>
        /// Return data as a new byte array
        /// </summary>
        public readonly byte[] GetBytes()
        {
            byte[] bytes = new byte[4];
            Store(new Span<byte>(bytes));
            return bytes;
        }

        /// <summary>
        /// Index access to individual byte fields
        /// </summary>
        /// <param name="key">Byte field index [0 .. 3]</param>
        /// <returns>Byte value</returns>
        public byte this[uint key]
        {
            readonly get => GetByte(key);
            set => SetByte(key, value);
        }

        private unsafe readonly byte GetByte(uint index)
        {
            if (index > 3)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 3] range");
            }

            fixed (byte* src = &b00)
            {
                return src[index];
            }
        }

        private unsafe byte SetByte(uint index, byte value)
        {
            if (index > 3)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 3] range");
            }

            fixed (byte* target = &b00)
            {
                return target[index] = value;
            }
        }

        /// <summary>
        /// Test method
        /// </summary>
        public static void Test()
        {
            ByteVec4 bv = new();
            for (byte i = 0; i < 4; i++)
            {
                bv[i] = i;
            }

            for (byte i = 0; i < 4; i++)
            {
                if (i != bv[i]) throw new InvalidDataException("ByteVec4 fail");
            }
        }


        #region Individual byte fields
        [FieldOffset(0)]
        public byte b00 = 0;

        [FieldOffset(1)]
        public byte b01 = 0;

        [FieldOffset(2)]
        public byte b02 = 0;

        [FieldOffset(3)]
        public byte b03 = 0;
        #endregion
    }
}
