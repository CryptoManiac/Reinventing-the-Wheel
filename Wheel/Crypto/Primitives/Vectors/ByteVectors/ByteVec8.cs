using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Crypto.Primitives.WordVectors;

namespace Wheel.Crypto.Primitives.ByteVectors
{
    /// <summary>
    /// 8 bytes long vector which can be represented as two 32-bit integers, one 64-bit integer or eight bytes
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public struct ByteVec8
    {
        /// <summary>
        /// Same data but as indexed structure of two 32-bt words
        /// </summary>
        [FieldOffset(0)]
        public WordVec2 wv2;

        /// <summary>
        /// 64-bit integer value
        /// </summary>
        [FieldOffset(0)]
        public ulong value;

        /// <summary>
        /// First half as 32-bit integer
        /// </summary>
        [FieldOffset(0)]
        public ByteVec4 bv4_00;

        /// <summary>
        /// Second half as 32-bit integer
        /// </summary>
        [FieldOffset(4)]
        public ByteVec4 bv4_01;

        /// <summary>
        /// Same data as a structure of two 32-bit words
        /// </summary>
        [FieldOffset(0)]
        public ByteVec4_Words words;

        public ByteVec8()
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="word">Value to construct from</param>
        public ByteVec8(ulong doubleWord)
        {
            value = doubleWord;
        }

        /// <summary>
        /// Implicit cast operator
        /// </summary>
        /// <param name="doubleWord">Value to convert from</param>
        public static implicit operator ByteVec8(ulong doubleWord)
        {
            return new ByteVec8(doubleWord);
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
            if (8 != from.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(from), from.Length, "Span must be exactly 8 bytes long");
            }

            fixed (byte* target = &b00)
            {
                var to = new Span<byte>(target, 8);
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
            if (to.Length > 8)
            {
                throw new ArgumentOutOfRangeException(nameof(to), to.Length, "Span must not be longer than 8 bytes");
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
            byte[] bytes = new byte[8];
            Store(new Span<byte>(bytes));
            return bytes;
        }

        /// <summary>
        /// Index access to individual byte fields
        /// </summary>
        /// <param name="key">Byte field index [0 .. 7]</param>
        /// <returns>Byte value</returns>
        public byte this[uint key]
        {
            readonly get => GetByte(key);
            set => SetByte(key, value);
        }

        private unsafe readonly byte GetByte(uint index)
        {
            if (index > 7)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 7] range");
            }

            fixed (byte* src = &b00)
            {
                return src[index];
            }
        }

        private unsafe byte SetByte(uint index, byte value)
        {
            if (index > 7)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 7] range");
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
            ByteVec8 bv = new();
            for (byte i = 0; i < 8; i++)
            {
                bv[i] = i;
            }

            for (byte i = 0; i < 8; i++)
            {
                if (i != bv[i]) throw new InvalidDataException("ByteVec8 fail");
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
        #endregion

    }

    [StructLayout(LayoutKind.Explicit)]
    public struct ByteVec4_Words
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
    }
}
