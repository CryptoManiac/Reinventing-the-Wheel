using System;
using System.Runtime.InteropServices;
using Wheel.Crypto.Primitives.WordVectors;

namespace Wheel.Crypto.Primitives.ByteVectors
{
    /// <summary>
    /// 64 bytes long vector which can be represented as either sixteen 32-bit integers or eight 64-bit integers
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public struct ByteVec64
    {
        /// <summary>
        /// Same data but as indexed 16 words structure
        /// </summary>
        [FieldOffset(0)]
        public WordVec16 wv16;

        /// <summary>
        /// Same data but as indexed 8 double words structure
        /// </summary>
        [FieldOffset(0)]
        public DWordVec8 dwv8;

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
        /// Fifth double word
        /// </summary>
        [FieldOffset(32)]
        public ByteVec8 dw04;

        /// <summary>
        /// Sixth double word
        /// </summary>
        [FieldOffset(40)]
        public ByteVec8 dw05;

        /// <summary>
        /// Seventh double word
        /// </summary>
        [FieldOffset(48)]
        public ByteVec8 dw06;

        /// <summary>
        /// Eighth double word
        /// </summary>
        [FieldOffset(56)]
        public ByteVec8 dw07;

        public ByteVec64()
        {
        }

        /// <summary>
        /// Set to zero
        /// </summary>
        public void Reset()
        {
            wv16.Reset();
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

            int offsetPlus64 = offset + 64;
            if (bytes.Length < offsetPlus64)
            {
                throw new ArgumentOutOfRangeException(nameof(offsetPlus64), offsetPlus64, "Offset plus 64 must not be greater than byte array length");
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
            b32 = bytes[32];
            b33 = bytes[33];
            b34 = bytes[34];
            b35 = bytes[35];
            b36 = bytes[36];
            b37 = bytes[37];
            b38 = bytes[38];
            b39 = bytes[39];
            b40 = bytes[40];
            b41 = bytes[41];
            b42 = bytes[42];
            b43 = bytes[43];
            b44 = bytes[44];
            b45 = bytes[45];
            b46 = bytes[46];
            b47 = bytes[47];
            b48 = bytes[48];
            b49 = bytes[49];
            b50 = bytes[50];
            b51 = bytes[51];
            b52 = bytes[52];
            b53 = bytes[53];
            b54 = bytes[54];
            b55 = bytes[55];
            b56 = bytes[56];
            b57 = bytes[57];
            b58 = bytes[58];
            b59 = bytes[59];
            b60 = bytes[60];
            b61 = bytes[61];
            b62 = bytes[62];
            b63 = bytes[63];
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

            int offsetPlus64 = offset + 64;
            if (bytes.Length < offsetPlus64)
            {
                throw new ArgumentOutOfRangeException(nameof(offsetPlus64), offsetPlus64, "Offset plus 64 must not be greater than byte array length");
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
            bytes[32] = b32;
            bytes[33] = b33;
            bytes[34] = b34;
            bytes[35] = b35;
            bytes[36] = b36;
            bytes[37] = b37;
            bytes[38] = b38;
            bytes[39] = b39;
            bytes[40] = b40;
            bytes[41] = b41;
            bytes[42] = b42;
            bytes[43] = b43;
            bytes[44] = b44;
            bytes[45] = b45;
            bytes[46] = b46;
            bytes[47] = b47;
            bytes[48] = b48;
            bytes[49] = b49;
            bytes[50] = b50;
            bytes[51] = b51;
            bytes[52] = b52;
            bytes[53] = b53;
            bytes[54] = b54;
            bytes[55] = b55;
            bytes[56] = b56;
            bytes[57] = b57;
            bytes[58] = b58;
            bytes[59] = b59;
            bytes[60] = b60;
            bytes[61] = b61;
            bytes[62] = b62;
            bytes[63] = b63;
        }

        /// <summary>
        /// Return data as a new byte array
        /// </summary>
        public readonly byte[] GetBytes()
        {
            byte[] bytes = new byte[64];
            StoreByteArray(ref bytes);
            return bytes;
        }

        /// <summary>
        /// Index access to individual byte fields
        /// </summary>
        /// <param name="key">Byte field index [0 .. 63]</param>
        /// <returns>Byte value</returns>
        public byte this[int key]
        {
            readonly get => GetByte(key);
            set => SetByte(key, value);
        }

        private readonly byte GetByte(int index)
        {
            switch(index)
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
                case 32: return b32;
                case 33: return b33;
                case 34: return b34;
                case 35: return b35;
                case 36: return b36;
                case 37: return b37;
                case 38: return b38;
                case 39: return b39;
                case 40: return b40;
                case 41: return b41;
                case 42: return b42;
                case 43: return b43;
                case 44: return b44;
                case 45: return b45;
                case 46: return b46;
                case 47: return b47;
                case 48: return b48;
                case 49: return b49;
                case 50: return b50;
                case 51: return b51;
                case 52: return b52;
                case 53: return b53;
                case 54: return b54;
                case 55: return b55;
                case 56: return b56;
                case 57: return b57;
                case 58: return b58;
                case 59: return b59;
                case 60: return b60;
                case 61: return b61;
                case 62: return b62;
                case 63: return b63;
                default: {
                        throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 63] range");
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
                case 32: return b32 = value;
                case 33: return b33 = value;
                case 34: return b34 = value;
                case 35: return b35 = value;
                case 36: return b36 = value;
                case 37: return b37 = value;
                case 38: return b38 = value;
                case 39: return b39 = value;
                case 40: return b40 = value;
                case 41: return b41 = value;
                case 42: return b42 = value;
                case 43: return b43 = value;
                case 44: return b44 = value;
                case 45: return b45 = value;
                case 46: return b46 = value;
                case 47: return b47 = value;
                case 48: return b48 = value;
                case 49: return b49 = value;
                case 50: return b50 = value;
                case 51: return b51 = value;
                case 52: return b52 = value;
                case 53: return b53 = value;
                case 54: return b54 = value;
                case 55: return b55 = value;
                case 56: return b56 = value;
                case 57: return b57 = value;
                case 58: return b58 = value;
                case 59: return b59 = value;
                case 60: return b60 = value;
                case 61: return b61 = value;
                case 62: return b62 = value;
                case 63: return b63 = value;
                default: {
                    throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 63] range");
                }
            }
        }

        /// <summary>
        /// Test method
        /// </summary>
        public static void Test()
        {
            ByteVec64 bv = new();
            for (byte i = 0; i < 64; i++)
            {
                bv[i] = i;
            }

            for (byte i = 0; i < 64; i++)
            {
                if (i != bv[i]) throw new InvalidDataException("ByteVec64 fail");
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

        [FieldOffset(32)]
        private byte b32 = 0;
        [FieldOffset(33)]
        private byte b33 = 0;
        [FieldOffset(34)]
        private byte b34 = 0;
        [FieldOffset(35)]
        private byte b35 = 0;

        [FieldOffset(36)]
        private byte b36 = 0;
        [FieldOffset(37)]
        private byte b37 = 0;
        [FieldOffset(38)]
        private byte b38 = 0;
        [FieldOffset(39)]
        private byte b39 = 0;

        [FieldOffset(40)]
        private byte b40 = 0;
        [FieldOffset(41)]
        private byte b41 = 0;
        [FieldOffset(42)]
        private byte b42 = 0;
        [FieldOffset(43)]
        private byte b43 = 0;

        [FieldOffset(44)]
        private byte b44 = 0;
        [FieldOffset(45)]
        private byte b45 = 0;
        [FieldOffset(46)]
        private byte b46 = 0;
        [FieldOffset(47)]
        private byte b47 = 0;

        [FieldOffset(48)]
        private byte b48 = 0;
        [FieldOffset(49)]
        private byte b49 = 0;
        [FieldOffset(50)]
        private byte b50 = 0;
        [FieldOffset(51)]
        private byte b51 = 0;

        [FieldOffset(52)]
        private byte b52 = 0;
        [FieldOffset(53)]
        private byte b53 = 0;
        [FieldOffset(54)]
        private byte b54 = 0;
        [FieldOffset(55)]
        private byte b55 = 0;

        [FieldOffset(56)]
        private byte b56 = 0;
        [FieldOffset(57)]
        private byte b57 = 0;
        [FieldOffset(58)]
        private byte b58 = 0;
        [FieldOffset(59)]
        private byte b59 = 0;

        [FieldOffset(60)]
        private byte b60 = 0;
        [FieldOffset(61)]
        private byte b61 = 0;
        [FieldOffset(62)]
        private byte b62 = 0;
        [FieldOffset(63)]
        private byte b63 = 0;
        #endregion
    }
}
