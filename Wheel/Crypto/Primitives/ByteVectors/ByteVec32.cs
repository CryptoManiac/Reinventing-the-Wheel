using System.Runtime.InteropServices;
using Wheel.Crypto.Primitives.WordVectors;

namespace Wheel.Crypto.Primitives.ByteVectors
{
    /// <summary>
    /// 32 bytes long vector which can be represented as either eight 32-bit integers or four 64-bit integers
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public struct ByteVec32
    {
        /// <summary>
        /// Same value but as indexed structure of eight 32-bit words
        /// </summary>
        [FieldOffset(0)]
        public WordVec8 wv8;

        /// <summary>
        /// Same value but as indexed structure of four 64-bit words
        /// </summary>
        [FieldOffset(0)]
        public DWordVec4 dwv4;

        /// <summary>
        /// First half as 16-byte vector
        /// </summary>
        [FieldOffset(0)]
        public ByteVec16 bv16_00;

        /// <summary>
        /// Second half as 16-byte vector
        /// </summary>
        [FieldOffset(16)]
        public ByteVec16 bv16_01;

        /// <summary>
        /// First double word (64-bit)
        /// </summary>
        [FieldOffset(0)]
        public ByteVec8 dw00;

        /// <summary>
        /// Second double word
        /// </summary>
        [FieldOffset(8)]
        public ByteVec8 dw01;

        /// <summary>
        /// Third double word 
        /// </summary>
        [FieldOffset(16)]
        public ByteVec8 dw02;

        /// <summary>
        /// Fourth double word
        /// </summary>
        [FieldOffset(24)]
        public ByteVec8 dw03;


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

        /// <summary>
        /// Fith word (32 bit)
        /// </summary>
        [FieldOffset(16)]
        public ByteVec4 w04;

        /// <summary>
        /// Sixth word
        /// </summary>
        [FieldOffset(20)]
        public ByteVec4 w05;

        /// <summary>
        /// Seventh word
        /// </summary>
        [FieldOffset(24)]
        public ByteVec4 w06;

        /// <summary>
        /// Eigtht word
        /// </summary>
        [FieldOffset(28)]
        public ByteVec4 w07;

        public ByteVec32()
        {
        }

        /// <summary>
        /// Set to zero
        /// </summary>
        public void Reset()
        {
            wv8.Reset();
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

            int offsetPlus32 = offset + 32;
            if (bytes.Length < offsetPlus32)
            {
                throw new ArgumentOutOfRangeException(nameof(offsetPlus32), offsetPlus32, "Offset plus 32 must not be greater than byte array length");
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
            b16 = bytes[16];
            b17 = bytes[17];
            b18 = bytes[18];
            b19 = bytes[19];
            b20 = bytes[20];
            b21 = bytes[21];
            b22 = bytes[22];
            b23 = bytes[23];
            b24 = bytes[24];
            b25 = bytes[25];
            b26 = bytes[26];
            b27 = bytes[27];
            b28 = bytes[28];
            b29 = bytes[29];
            b30 = bytes[30];
            b31 = bytes[31];
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

            int offsetPlus32 = offset + 32;
            if (bytes.Length < offsetPlus32)
            {
                throw new ArgumentOutOfRangeException(nameof(offsetPlus32), offsetPlus32, "Offset plus 32 must not be greater than byte array length");
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
            bytes[16] = b16;
            bytes[17] = b17;
            bytes[18] = b18;
            bytes[19] = b19;
            bytes[20] = b20;
            bytes[21] = b21;
            bytes[22] = b22;
            bytes[23] = b23;
            bytes[24] = b24;
            bytes[25] = b25;
            bytes[26] = b26;
            bytes[27] = b27;
            bytes[28] = b28;
            bytes[29] = b29;
            bytes[30] = b30;
            bytes[31] = b31;
        }

        /// <summary>
        /// Return data as a new byte array
        /// </summary>
        public readonly byte[] GetBytes()
        {
            byte[] bytes = new byte[32];
            StoreByteArray(ref bytes);
            return bytes;
        }

        /// <summary>
        /// Index access to individual byte fields
        /// </summary>
        /// <param name="key">Byte field index [0 .. 31]</param>
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
                case 16: return b16;
                case 17: return b17;
                case 18: return b18;
                case 19: return b19;
                case 20: return b20;
                case 21: return b21;
                case 22: return b22;
                case 23: return b23;
                case 24: return b24;
                case 25: return b25;
                case 26: return b26;
                case 27: return b27;
                case 28: return b28;
                case 29: return b29;
                case 30: return b30;
                case 31: return b31;
                default:
                    {
                        throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 31] range");
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
                case 16: return b16 = value;
                case 17: return b17 = value;
                case 18: return b18 = value;
                case 19: return b19 = value;
                case 20: return b20 = value;
                case 21: return b21 = value;
                case 22: return b22 = value;
                case 23: return b23 = value;
                case 24: return b24 = value;
                case 25: return b25 = value;
                case 26: return b26 = value;
                case 27: return b27 = value;
                case 28: return b28 = value;
                case 29: return b29 = value;
                case 30: return b30 = value;
                case 31: return b31 = value;
                default:
                    {
                        throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 31] range");
                    }
            }
        }

        /// <summary>
        /// Test method
        /// </summary>
        public static void Test()
        {
            ByteVec32 bv = new();
            for (byte i = 0; i < 32; i++)
            {
                bv[i] = i;
            }

            for (byte i = 0; i < 32; i++)
            {
                if (i != bv[i]) throw new InvalidDataException("ByteVec32 fail");
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

        [FieldOffset(16)]
        private byte b16 = 0;
        [FieldOffset(17)]
        private byte b17 = 0;
        [FieldOffset(18)]
        private byte b18 = 0;
        [FieldOffset(19)]
        private byte b19 = 0;

        [FieldOffset(20)]
        private byte b20 = 0;
        [FieldOffset(21)]
        private byte b21 = 0;
        [FieldOffset(22)]
        private byte b22 = 0;
        [FieldOffset(23)]
        private byte b23 = 0;

        [FieldOffset(24)]
        private byte b24 = 0;
        [FieldOffset(25)]
        private byte b25 = 0;
        [FieldOffset(26)]
        private byte b26 = 0;
        [FieldOffset(27)]
        private byte b27 = 0;

        [FieldOffset(28)]
        private byte b28 = 0;
        [FieldOffset(29)]
        private byte b29 = 0;
        [FieldOffset(30)]
        private byte b30 = 0;
        [FieldOffset(31)]
        private byte b31 = 0;
        #endregion
    }
}
