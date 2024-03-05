

using System;
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
        /// Load value from byte array at given offset
        /// </summary>
        /// <param name="bytes">Byte array</param>
        /// <param name="offset">Offset to read from</param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public void LoadByteArray(in byte[] bytes, int offset = 0)
        {
            if (bytes.Length < 4)
            {
                throw new ArgumentOutOfRangeException(nameof(bytes), bytes.Length, "The provided byte array must be at least 4 bytes long");
            }

            int offsetPlus4 = offset + 4;
            if (bytes.Length < offsetPlus4)
            {
                throw new ArgumentOutOfRangeException(nameof(offsetPlus4), offsetPlus4, "Offset plus 4 must not be greater than byte array length");
            }

            b00 = bytes[0];
            b01 = bytes[1];
            b02 = bytes[2];
            b03 = bytes[3];
        }

        /// <summary>
        /// Write vector contents to byte array
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="offset"></param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public readonly void StoreByteArray(ref byte[] bytes, int offset = 0)
        {
            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(offset), offset, "Offset must be a non-negative value");
            }

            int offsetPlus4 = offset + 4;
            if (bytes.Length < offsetPlus4)
            {
                throw new ArgumentOutOfRangeException(nameof(offsetPlus4), offsetPlus4, "Offset plus 4 must not be greater than byte array length");
            }

            bytes[0] = b00;
            bytes[1] = b01;
            bytes[2] = b02;
            bytes[3] = b03;
        }

        /// <summary>
        /// Index access to individual byte fields
        /// </summary>
        /// <param name="key">Byte field index [0 .. 3]</param>
        /// <returns>Byte value</returns>
        public byte this[int key]
        {
            readonly get => GetByte(key);
            set => SetByte(key, value);
        }

        private readonly byte GetByte(int index)
        {
            switch (index)
            {
                case 0: return b00;
                case 1: return b01;
                case 2: return b02;
                case 3: return b03;
                default:
                    {
                        throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 3] range");
                    }
            }
        }

        private byte SetByte(int index, byte value)
        {
            switch (index)
            {
                case 0: return b00 = value;
                case 1: return b01 = value;
                case 2: return b02 = value;
                case 3: return b03 = value;
                default:
                    {
                        throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 3] range");
                    }
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
        private byte b00 = 0;

        [FieldOffset(1)]
        private byte b01 = 0;

        [FieldOffset(2)]
        private byte b02 = 0;

        [FieldOffset(3)]
        private byte b03 = 0;
        #endregion
    }
}
