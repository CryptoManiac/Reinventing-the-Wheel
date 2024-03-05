using System;
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
            wv2.Reset();
        }

        /// <summary>
        /// Load value from byte array at given offset
        /// </summary>
        /// <param name="bytes">Byte array</param>
        /// <param name="offset">Offset to read from</param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public void LoadByteArray(byte[] bytes, int offset = 0)
        {
            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(offset), offset, "Offset must be a non-negative value");
            }

            int offsetPlus8 = offset + 8;
            if (bytes.Length < offsetPlus8)
            {
                throw new ArgumentOutOfRangeException(nameof(offsetPlus8), offsetPlus8, "Offset plus 8 must not be greater than byte array length");
            }

            b00 = bytes[0];
            b01 = bytes[1];
            b02 = bytes[2];
            b03 = bytes[3];
            b04 = bytes[4];
            b05 = bytes[5];
            b06 = bytes[6];
            b07 = bytes[7];
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

            int offsetPlus8 = offset + 8;
            if (bytes.Length < offsetPlus8)
            {
                throw new ArgumentOutOfRangeException(nameof(offsetPlus8), offsetPlus8, "Offset plus 8 must not be greater than byte array length");
            }

            bytes[0] = b00;
            bytes[1] = b01;
            bytes[2] = b02;
            bytes[3] = b03;
            bytes[4] = b04;
            bytes[5] = b05;
            bytes[6] = b06;
            bytes[7] = b07;
        }

        /// <summary>
        /// Index access to individual byte fields
        /// </summary>
        /// <param name="key">Byte field index [0 .. 7]</param>
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
                case 4: return b04;
                case 5: return b05;
                case 6: return b06;
                case 7: return b07;
                default:
                    {
                        throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 7] range");
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
                case 4: return b04 = value;
                case 5: return b05 = value;
                case 6: return b06 = value;
                case 7: return b07 = value;
                default:
                    {
                        throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 7] range");
                    }
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
        private byte b00 = 0;

        [FieldOffset(1)]
        private byte b01 = 0;

        [FieldOffset(2)]
        private byte b02 = 0;

        [FieldOffset(3)]
        private byte b03 = 0;

        [FieldOffset(4)]
        private byte b04 = 0;

        [FieldOffset(5)]
        private byte b05 = 0;

        [FieldOffset(6)]
        private byte b06 = 0;

        [FieldOffset(7)]
        private byte b07 = 0;
        #endregion

    }
}
