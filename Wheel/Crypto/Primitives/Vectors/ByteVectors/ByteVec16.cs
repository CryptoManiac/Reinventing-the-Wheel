using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Crypto.Primitives.WordVectors;

namespace Wheel.Crypto.Primitives.ByteVectors
{
    /// <summary>
    /// 16 bytes long vector which can be represented as either four 32-bit integers or two 64-bit integers
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public struct ByteVec16
    {
        /// <summary>
        /// 128 bit integer value
        /// </summary>
        [FieldOffset(0)]
        public UInt128 value;

        /// <summary>
        /// Same data but as indexed 4 words structure
        /// </summary>
        [FieldOffset(0)]
        public WordVec4 wv4;

        /// <summary>
        /// First double word (64-bit)
        /// </summary>
        [FieldOffset(0)]
        public ByteVec8 bv8_00;

        /// <summary>
        /// Second double word
        /// </summary>
        [FieldOffset(8)]
        public ByteVec8 bv8_01;

        /// <summary>
        /// Same data as a structure of four 32-bit words
        /// </summary>
        [FieldOffset(0)]
        public ByteVec16_Words words;

        public ByteVec16()
        {
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
            if (16 != from.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(from), from.Length, "Span must be exactly 16 bytes long");
            }

            fixed (byte* target = &b00)
            {
                var to = new Span<byte>(target, 16);
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
            if (to.Length > 16)
            {
                throw new ArgumentOutOfRangeException(nameof(to), to.Length, "Span must not be longer than 16 bytes");
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
            byte[] bytes = new byte[16];
            Store(new Span<byte>(bytes));
            return bytes;
        }

        /// <summary>
        /// Index access to individual byte fields
        /// </summary>
        /// <param name="key">Byte field index [0 .. 15]</param>
        /// <returns>Byte value</returns>
        public byte this[uint key]
        {
            readonly get => GetByte(key);
            set => SetByte(key, value);
        }

        private unsafe readonly byte GetByte(uint index)
        {
            if (index > 15)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 15] range");
            }

            fixed (byte* src = &b00)
            {
                return src[index];
            }
        }

        private unsafe byte SetByte(uint index, byte value)
        {
            if (index > 15)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 15] range");
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
            ByteVec16 bv = new();
            for (byte i = 0; i < 16; i++)
            {
                bv[i] = i;
            }

            for (byte i = 0; i < 16; i++)
            {
                if (i != bv[i]) throw new InvalidDataException("ByteVec16 fail");
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

        [FieldOffset(4)]
        public byte b04 = 0;
        [FieldOffset(5)]
        public byte b05 = 0;
        [FieldOffset(6)]
        public byte b06 = 0;
        [FieldOffset(7)]
        public byte b07 = 0;

        [FieldOffset(8)]
        public byte b08 = 0;
        [FieldOffset(9)]
        public byte b09 = 0;
        [FieldOffset(10)]
        public byte b10 = 0;
        [FieldOffset(11)]
        public byte b11 = 0;

        [FieldOffset(12)]
        public byte b12 = 0;
        [FieldOffset(13)]
        public byte b13 = 0;
        [FieldOffset(14)]
        public byte b14 = 0;
        [FieldOffset(15)]
        public byte b15 = 0;
        #endregion

    }

    [StructLayout(LayoutKind.Explicit)]
    public struct ByteVec16_Words
    {
        /// <summary>
        /// First word (32 bit)
        /// </summary>
        [FieldOffset(0)]
        public ByteVec4 w00;

        /// <summary>
        /// Second word
        /// </summary>
        [FieldOffset(4)]
        public ByteVec4 w01;

        /// <summary>
        /// Third word
        /// </summary>
        [FieldOffset(8)]
        public ByteVec4 w02;

        /// <summary>
        /// Four word
        /// </summary>
        [FieldOffset(12)]
        public ByteVec4 w03;
    }
}
