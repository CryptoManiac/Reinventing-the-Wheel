using System;
using System.Runtime.InteropServices;
using Wheel.Crypto.Primitives.WordVectors;

namespace Wheel.Crypto.Primitives.ByteVectors
{
    /// <summary>
    /// 64 bytes long vector which can be represented as either sixteen 32-bit integers or eight 64-bit integers
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public struct ByteVec128
    {
        /// <summary>
        /// Same data but as indexed 16 double words structure
        /// </summary>
        [FieldOffset(0)]
        public DWordVec16 dwv16;

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

        /// <summary>
        /// Ninth double word
        /// </summary>
        [FieldOffset(64)]
        public ByteVec8 dw08;

        /// <summary>
        /// Tenth double word
        /// </summary>
        [FieldOffset(72)]
        public ByteVec8 dw09;

        /// <summary>
        /// Eleventh double word
        /// </summary>
        [FieldOffset(80)]
        public ByteVec8 dw10;

        /// <summary>
        /// Twelfth double word
        /// </summary>
        [FieldOffset(88)]
        public ByteVec8 dw11;

        /// <summary>
        /// Thirteenth double word
        /// </summary>
        [FieldOffset(96)]
        public ByteVec8 dw12;

        /// <summary>
        /// Fourteenth double word
        /// </summary>
        [FieldOffset(104)]
        public ByteVec8 dw13;

        /// <summary>
        /// Fifteenth double word
        /// </summary>
        [FieldOffset(112)]
        public ByteVec8 dw14;

        /// <summary>
        /// Sixteenth double word
        /// </summary>
        [FieldOffset(120)]
        public ByteVec8 dw15;


        public ByteVec128()
        {
        }

        /// <summary>
        /// Set to zero
        /// </summary>
        public void Reset()
        {
            dwv16.Reset();
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

            int offsetPlus128 = offset + 128;
            if (bytes.Length < offsetPlus128)
            {
                throw new ArgumentOutOfRangeException(nameof(offsetPlus128), offsetPlus128, "Offset plus 128 must not be greater than byte array length");
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

            int offsetPlus128 = offset + 128;
            if (bytes.Length < offsetPlus128)
            {
                throw new ArgumentOutOfRangeException(nameof(offsetPlus128), offsetPlus128, "Offset plus 128 must not be greater than byte array length");
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
            bytes[64] = b64;
            bytes[65] = b65;
            bytes[66] = b66;
            bytes[67] = b67;
            bytes[68] = b68;
            bytes[69] = b69;
            bytes[70] = b70;
            bytes[71] = b71;
            bytes[72] = b72;
            bytes[73] = b73;
            bytes[74] = b74;
            bytes[75] = b75;
            bytes[76] = b76;
            bytes[77] = b77;
            bytes[78] = b78;
            bytes[79] = b79;
            bytes[80] = b80;
            bytes[81] = b81;
            bytes[82] = b82;
            bytes[83] = b83;
            bytes[84] = b84;
            bytes[85] = b85;
            bytes[86] = b86;
            bytes[87] = b87;
            bytes[88] = b88;
            bytes[89] = b89;
            bytes[90] = b90;
            bytes[91] = b91;
            bytes[92] = b92;
            bytes[93] = b93;
            bytes[94] = b94;
            bytes[95] = b95;
            bytes[96] = b96;
            bytes[97] = b97;
            bytes[98] = b98;
            bytes[99] = b99;
            bytes[100] = b100;
            bytes[101] = b101;
            bytes[102] = b102;
            bytes[103] = b103;
            bytes[104] = b104;
            bytes[105] = b105;
            bytes[106] = b106;
            bytes[107] = b107;
            bytes[108] = b108;
            bytes[109] = b109;
            bytes[110] = b110;
            bytes[111] = b111;
            bytes[112] = b112;
            bytes[113] = b113;
            bytes[114] = b114;
            bytes[115] = b115;
            bytes[116] = b116;
            bytes[117] = b117;
            bytes[118] = b118;
            bytes[119] = b119;
            bytes[120] = b120;
            bytes[121] = b121;
            bytes[122] = b122;
            bytes[123] = b123;
            bytes[124] = b124;
            bytes[125] = b125;
            bytes[126] = b126;
            bytes[127] = b127;
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
                case 64: return b64;
                case 65: return b65;
                case 66: return b66;
                case 67: return b67;
                case 68: return b68;
                case 69: return b69;
                case 70: return b70;
                case 71: return b71;
                case 72: return b72;
                case 73: return b73;
                case 74: return b74;
                case 75: return b75;
                case 76: return b76;
                case 77: return b77;
                case 78: return b78;
                case 79: return b79;
                case 80: return b80;
                case 81: return b81;
                case 82: return b82;
                case 83: return b83;
                case 84: return b84;
                case 85: return b85;
                case 86: return b86;
                case 87: return b87;
                case 88: return b88;
                case 89: return b89;
                case 90: return b90;
                case 91: return b91;
                case 92: return b92;
                case 93: return b93;
                case 94: return b94;
                case 95: return b95;
                case 96: return b96;
                case 97: return b97;
                case 98: return b98;
                case 99: return b99;
                case 100: return b100;
                case 101: return b101;
                case 102: return b102;
                case 103: return b103;
                case 104: return b104;
                case 105: return b105;
                case 106: return b106;
                case 107: return b107;
                case 108: return b108;
                case 109: return b109;
                case 110: return b110;
                case 111: return b111;
                case 112: return b112;
                case 113: return b113;
                case 114: return b114;
                case 115: return b115;
                case 116: return b116;
                case 117: return b117;
                case 118: return b118;
                case 119: return b119;
                case 120: return b120;
                case 121: return b121;
                case 122: return b122;
                case 123: return b123;
                case 124: return b124;
                case 125: return b125;
                case 126: return b126;
                case 127: return b127;
                default: {
                        throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 127] range");
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
                case 64: return b64 = value;
                case 65: return b65 = value;
                case 66: return b66 = value;
                case 67: return b67 = value;
                case 68: return b68 = value;
                case 69: return b69 = value;
                case 70: return b70 = value;
                case 71: return b71 = value;
                case 72: return b72 = value;
                case 73: return b73 = value;
                case 74: return b74 = value;
                case 75: return b75 = value;
                case 76: return b76 = value;
                case 77: return b77 = value;
                case 78: return b78 = value;
                case 79: return b79 = value;
                case 80: return b80 = value;
                case 81: return b81 = value;
                case 82: return b82 = value;
                case 83: return b83 = value;
                case 84: return b84 = value;
                case 85: return b85 = value;
                case 86: return b86 = value;
                case 87: return b87 = value;
                case 88: return b88 = value;
                case 89: return b89 = value;
                case 90: return b90 = value;
                case 91: return b91 = value;
                case 92: return b92 = value;
                case 93: return b93 = value;
                case 94: return b94 = value;
                case 95: return b95 = value;
                case 96: return b96 = value;
                case 97: return b97 = value;
                case 98: return b98 = value;
                case 99: return b99 = value;
                case 100: return b100 = value;
                case 101: return b101 = value;
                case 102: return b102 = value;
                case 103: return b103 = value;
                case 104: return b104 = value;
                case 105: return b105 = value;
                case 106: return b106 = value;
                case 107: return b107 = value;
                case 108: return b108 = value;
                case 109: return b109 = value;
                case 110: return b110 = value;
                case 111: return b111 = value;
                case 112: return b112 = value;
                case 113: return b113 = value;
                case 114: return b114 = value;
                case 115: return b115 = value;
                case 116: return b116 = value;
                case 117: return b117 = value;
                case 118: return b118 = value;
                case 119: return b119 = value;
                case 120: return b120 = value;
                case 121: return b121 = value;
                case 122: return b122 = value;
                case 123: return b123 = value;
                case 124: return b124 = value;
                case 125: return b125 = value;
                case 126: return b126 = value;
                case 127: return b127 = value;
                default: {
                    throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 127] range");
                }
            }
        }

        /// <summary>
        /// Test method
        /// </summary>
        public static void Test()
        {
            ByteVec128 bv = new();
            for (byte i = 0; i < 128; i++)
            {
                bv[i] = i;
            }

            for (byte i = 0; i < 128; i++)
            {
                if (i != bv[i]) throw new InvalidDataException("ByteVec128 fail");
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


        [FieldOffset(64)]
        private byte b64 = 0;
        [FieldOffset(65)]
        private byte b65 = 0;
        [FieldOffset(66)]
        private byte b66 = 0;
        [FieldOffset(67)]
        private byte b67 = 0;

        [FieldOffset(68)]
        private byte b68 = 0;
        [FieldOffset(69)]
        private byte b69 = 0;
        [FieldOffset(70)]
        private byte b70 = 0;
        [FieldOffset(71)]
        private byte b71 = 0;

        [FieldOffset(72)]
        private byte b72 = 0;
        [FieldOffset(73)]
        private byte b73 = 0;
        [FieldOffset(74)]
        private byte b74 = 0;
        [FieldOffset(75)]
        private byte b75 = 0;

        [FieldOffset(76)]
        private byte b76 = 0;
        [FieldOffset(77)]
        private byte b77 = 0;
        [FieldOffset(78)]
        private byte b78 = 0;
        [FieldOffset(79)]
        private byte b79 = 0;

        [FieldOffset(80)]
        private byte b80 = 0;
        [FieldOffset(81)]
        private byte b81 = 0;
        [FieldOffset(82)]
        private byte b82 = 0;
        [FieldOffset(83)]
        private byte b83 = 0;

        [FieldOffset(84)]
        private byte b84 = 0;
        [FieldOffset(85)]
        private byte b85 = 0;
        [FieldOffset(86)]
        private byte b86 = 0;
        [FieldOffset(87)]
        private byte b87 = 0;

        [FieldOffset(88)]
        private byte b88 = 0;
        [FieldOffset(89)]
        private byte b89 = 0;
        [FieldOffset(90)]
        private byte b90 = 0;
        [FieldOffset(91)]
        private byte b91 = 0;

        [FieldOffset(92)]
        private byte b92 = 0;
        [FieldOffset(93)]
        private byte b93 = 0;
        [FieldOffset(94)]
        private byte b94 = 0;
        [FieldOffset(95)]
        private byte b95 = 0;

        [FieldOffset(96)]
        private byte b96 = 0;
        [FieldOffset(97)]
        private byte b97 = 0;
        [FieldOffset(98)]
        private byte b98 = 0;
        [FieldOffset(99)]
        private byte b99 = 0;

        [FieldOffset(100)]
        private byte b100 = 0;
        [FieldOffset(101)]
        private byte b101 = 0;
        [FieldOffset(102)]
        private byte b102 = 0;
        [FieldOffset(103)]
        private byte b103 = 0;

        [FieldOffset(104)]
        private byte b104 = 0;
        [FieldOffset(105)]
        private byte b105 = 0;
        [FieldOffset(106)]
        private byte b106 = 0;
        [FieldOffset(107)]
        private byte b107 = 0;

        [FieldOffset(108)]
        private byte b108 = 0;
        [FieldOffset(109)]
        private byte b109 = 0;
        [FieldOffset(110)]
        private byte b110 = 0;
        [FieldOffset(111)]
        private byte b111 = 0;

        [FieldOffset(112)]
        private byte b112 = 0;
        [FieldOffset(113)]
        private byte b113 = 0;
        [FieldOffset(114)]
        private byte b114 = 0;
        [FieldOffset(115)]
        private byte b115 = 0;

        [FieldOffset(116)]
        private byte b116 = 0;
        [FieldOffset(117)]
        private byte b117 = 0;
        [FieldOffset(118)]
        private byte b118 = 0;
        [FieldOffset(119)]
        private byte b119 = 0;

        [FieldOffset(120)]
        private byte b120 = 0;
        [FieldOffset(121)]
        private byte b121 = 0;
        [FieldOffset(122)]
        private byte b122 = 0;
        [FieldOffset(123)]
        private byte b123 = 0;

        [FieldOffset(124)]
        private byte b124 = 0;
        [FieldOffset(125)]
        private byte b125 = 0;
        [FieldOffset(126)]
        private byte b126 = 0;
        [FieldOffset(127)]
        private byte b127 = 0;
        #endregion
    }
}
