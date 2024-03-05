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

        public ByteVec16()
        {
        }

        /// <summary>
        /// Set to zero
        /// </summary>
        public void Reset()
        {
            wv4.Reset();
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

            int offsetPlus16 = offset + 16;
            if (bytes.Length < offsetPlus16)
            {
                throw new ArgumentOutOfRangeException(nameof(offsetPlus16), offsetPlus16, "Offset plus 16 must not be greater than byte array length");
            }

            b00 = bytes[0];
            b01 = bytes[1];
            b02 = bytes[2];
            b03 = bytes[3];
            b04 = bytes[4];
            b05 = bytes[5];
            b06 = bytes[6];
            b07 = bytes[7];
            b08 = bytes[8];
            b09 = bytes[9];
            b10 = bytes[10];
            b11 = bytes[11];
            b12 = bytes[12];
            b13 = bytes[13];
            b14 = bytes[14];
            b15 = bytes[15];
        }

        /// <summary>
        /// Store data to byte array at given offset
        /// </summary>
        /// <param name="bytes">Output array</param>
        /// <param name="offset">Output offset</param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public readonly void StoreByteArray(ref byte[] bytes, int offset = 0)
        {
            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(offset), offset, "Offset must be a non-negative value");
            }

            int offsetPlus16 = offset + 16;
            if (bytes.Length < offsetPlus16)
            {
                throw new ArgumentOutOfRangeException(nameof(offsetPlus16), offsetPlus16, "Offset plus 16 must not be greater than byte array length");
            }

            bytes[0] = b00;
            bytes[1] = b01;
            bytes[2] = b02;
            bytes[3] = b03;
            bytes[4] = b04;
            bytes[5] = b05;
            bytes[6] = b06;
            bytes[7] = b07;
            bytes[8] = b08;
            bytes[9] = b09;
            bytes[10] = b10;
            bytes[11] = b11;
            bytes[12] = b12;
            bytes[13] = b13;
            bytes[14] = b14;
            bytes[15] = b15;
        }

        /// <summary>
        /// Index access to individual byte fields
        /// </summary>
        /// <param name="key">Byte field index [0 .. 15]</param>
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
                case 8: return b08;
                case 9: return b09;
                case 10: return b10;
                case 11: return b11;
                case 12: return b12;
                case 13: return b13;
                case 14: return b14;
                case 15: return b15;
                default:
                    {
                        throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 15] range");
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
                case 8: return b08 = value;
                case 9: return b09 = value;
                case 10: return b10 = value;
                case 11: return b11 = value;
                case 12: return b12 = value;
                case 13: return b13 = value;
                case 14: return b14 = value;
                case 15: return b15 = value;
                default:
                    {
                        throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 15] range");
                    }
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

        [FieldOffset(8)]
        private byte b08 = 0;
        [FieldOffset(9)]
        private byte b09 = 0;
        [FieldOffset(10)]
        private byte b10 = 0;
        [FieldOffset(11)]
        private byte b11 = 0;

        [FieldOffset(12)]
        private byte b12 = 0;
        [FieldOffset(13)]
        private byte b13 = 0;
        [FieldOffset(14)]
        private byte b14 = 0;
        [FieldOffset(15)]
        private byte b15 = 0;
        #endregion

    }
}
