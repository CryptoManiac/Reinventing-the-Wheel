using System.Runtime.InteropServices;
using Wheel.Crypto.Miscellaneous.Support;

namespace Wheel.Crypto.Primitives.WordVectors
{
    [StructLayout(LayoutKind.Explicit)]
    public struct DWordVec80
    {
        public DWordVec80()
        {

        }

        public DWordVec80(ulong w00, ulong w01, ulong w02, ulong w03, ulong w04, ulong w05, ulong w06, ulong w07, ulong w08, ulong w09, ulong w10, ulong w11, ulong w12, ulong w13, ulong w14, ulong w15, ulong w16, ulong w17, ulong w18, ulong w19, ulong w20, ulong w21, ulong w22, ulong w23, ulong w24, ulong w25, ulong w26, ulong w27, ulong w28, ulong w29, ulong w30, ulong w31, ulong w32, ulong w33, ulong w34, ulong w35, ulong w36, ulong w37, ulong w38, ulong w39, ulong w40, ulong w41, ulong w42, ulong w43, ulong w44, ulong w45, ulong w46, ulong w47, ulong w48, ulong w49, ulong w50, ulong w51, ulong w52, ulong w53, ulong w54, ulong w55, ulong w56, ulong w57, ulong w58, ulong w59, ulong w60, ulong w61, ulong w62, ulong w63, ulong w64, ulong w65, ulong w66, ulong w67, ulong w68, ulong w69, ulong w70, ulong w71, ulong w72, ulong w73, ulong w74, ulong w75, ulong w76, ulong w77, ulong w78, ulong w79)
        {
            this.w00 = w00;
            this.w01 = w01;
            this.w02 = w02;
            this.w03 = w03;
            this.w04 = w04;
            this.w05 = w05;
            this.w06 = w06;
            this.w07 = w07;
            this.w08 = w08;
            this.w09 = w09;
            this.w10 = w10;
            this.w11 = w11;
            this.w12 = w12;
            this.w13 = w13;
            this.w14 = w14;
            this.w15 = w15;
            this.w16 = w16;
            this.w17 = w17;
            this.w18 = w18;
            this.w19 = w19;
            this.w20 = w20;
            this.w21 = w21;
            this.w22 = w22;
            this.w23 = w23;
            this.w24 = w24;
            this.w25 = w25;
            this.w26 = w26;
            this.w27 = w27;
            this.w28 = w28;
            this.w29 = w29;
            this.w30 = w30;
            this.w31 = w31;
            this.w32 = w32;
            this.w33 = w33;
            this.w34 = w34;
            this.w35 = w35;
            this.w36 = w36;
            this.w37 = w37;
            this.w38 = w38;
            this.w39 = w39;
            this.w40 = w40;
            this.w41 = w41;
            this.w42 = w42;
            this.w43 = w43;
            this.w44 = w44;
            this.w45 = w45;
            this.w46 = w46;
            this.w47 = w47;
            this.w48 = w48;
            this.w49 = w49;
            this.w50 = w50;
            this.w51 = w51;
            this.w52 = w52;
            this.w53 = w53;
            this.w54 = w54;
            this.w55 = w55;
            this.w56 = w56;
            this.w57 = w57;
            this.w58 = w58;
            this.w59 = w59;
            this.w60 = w60;
            this.w61 = w61;
            this.w62 = w62;
            this.w63 = w63;
            this.w64 = w64;
            this.w65 = w65;
            this.w66 = w66;
            this.w67 = w67;
            this.w68 = w68;
            this.w69 = w69;
            this.w70 = w70;
            this.w71 = w71;
            this.w72 = w72;
            this.w73 = w73;
            this.w74 = w74;
            this.w75 = w75;
            this.w76 = w76;
            this.w77 = w77;
            this.w78 = w78;
            this.w79 = w79;
        }

        public void SetWords(ulong w00, ulong w01, ulong w02, ulong w03, ulong w04, ulong w05, ulong w06, ulong w07, ulong w08, ulong w09, ulong w10, ulong w11, ulong w12, ulong w13, ulong w14, ulong w15, ulong w16, ulong w17, ulong w18, ulong w19, ulong w20, ulong w21, ulong w22, ulong w23, ulong w24, ulong w25, ulong w26, ulong w27, ulong w28, ulong w29, ulong w30, ulong w31, ulong w32, ulong w33, ulong w34, ulong w35, ulong w36, ulong w37, ulong w38, ulong w39, ulong w40, ulong w41, ulong w42, ulong w43, ulong w44, ulong w45, ulong w46, ulong w47, ulong w48, ulong w49, ulong w50, ulong w51, ulong w52, ulong w53, ulong w54, ulong w55, ulong w56, ulong w57, ulong w58, ulong w59, ulong w60, ulong w61, ulong w62, ulong w63, ulong w64, ulong w65, ulong w66, ulong w67, ulong w68, ulong w69, ulong w70, ulong w71, ulong w72, ulong w73, ulong w74, ulong w75, ulong w76, ulong w77, ulong w78, ulong w79)
        {
            this.w00 = w00;
            this.w01 = w01;
            this.w02 = w02;
            this.w03 = w03;
            this.w04 = w04;
            this.w05 = w05;
            this.w06 = w06;
            this.w07 = w07;
            this.w08 = w08;
            this.w09 = w09;
            this.w10 = w10;
            this.w11 = w11;
            this.w12 = w12;
            this.w13 = w13;
            this.w14 = w14;
            this.w15 = w15;
            this.w16 = w16;
            this.w17 = w17;
            this.w18 = w18;
            this.w19 = w19;
            this.w20 = w20;
            this.w21 = w21;
            this.w22 = w22;
            this.w23 = w23;
            this.w24 = w24;
            this.w25 = w25;
            this.w26 = w26;
            this.w27 = w27;
            this.w28 = w28;
            this.w29 = w29;
            this.w30 = w30;
            this.w31 = w31;
            this.w32 = w32;
            this.w33 = w33;
            this.w34 = w34;
            this.w35 = w35;
            this.w36 = w36;
            this.w37 = w37;
            this.w38 = w38;
            this.w39 = w39;
            this.w40 = w40;
            this.w41 = w41;
            this.w42 = w42;
            this.w43 = w43;
            this.w44 = w44;
            this.w45 = w45;
            this.w46 = w46;
            this.w47 = w47;
            this.w48 = w48;
            this.w49 = w49;
            this.w50 = w50;
            this.w51 = w51;
            this.w52 = w52;
            this.w53 = w53;
            this.w54 = w54;
            this.w55 = w55;
            this.w56 = w56;
            this.w57 = w57;
            this.w58 = w58;
            this.w59 = w59;
            this.w60 = w60;
            this.w61 = w61;
            this.w62 = w62;
            this.w63 = w63;
            this.w64 = w64;
            this.w65 = w65;
            this.w66 = w66;
            this.w67 = w67;
            this.w68 = w68;
            this.w69 = w69;
            this.w70 = w70;
            this.w71 = w71;
            this.w72 = w72;
            this.w73 = w73;
            this.w74 = w74;
            this.w75 = w75;
            this.w76 = w76;
            this.w77 = w77;
            this.w78 = w78;
            this.w79 = w79;
        }

        /// <summary>
        /// Set to zeros
        /// </summary>
        public void Reset()
        {
            for (int i = 0; i < 80; i++)
            {
                this[i] = 0;
            }
        }

        /// <summary>
        /// Set first 16 words from the provided container
        /// </summary>
        /// <param name="words">Vector to provide 16 double words</param>
        public void Set16Words(DWordVec16 words)
        {
            w00 = words[0];
            w01 = words[1];
            w02 = words[2];
            w03 = words[3];
            w04 = words[4];
            w05 = words[5];
            w06 = words[6];
            w07 = words[7];
            w08 = words[8];
            w09 = words[9];
            w10 = words[10];
            w11 = words[11];
            w12 = words[12];
            w13 = words[13];
            w14 = words[14];
            w15 = words[15];
        }

        /// <summary>
        /// Reverse byte order for the first 16 words
        /// </summary>
        public void Revert16Words()
        {
            w00 = Common.REVERT(w00);
            w01 = Common.REVERT(w01);
            w02 = Common.REVERT(w02);
            w03 = Common.REVERT(w03);
            w04 = Common.REVERT(w04);
            w05 = Common.REVERT(w05);
            w06 = Common.REVERT(w06);
            w07 = Common.REVERT(w07);
            w08 = Common.REVERT(w08);
            w09 = Common.REVERT(w09);
            w10 = Common.REVERT(w10);
            w11 = Common.REVERT(w11);
            w12 = Common.REVERT(w12);
            w13 = Common.REVERT(w13);
            w14 = Common.REVERT(w14);
            w15 = Common.REVERT(w15);
        }

        /// <summary>
        /// Index access to individual word fields
        /// </summary>
        /// <param name="key">Byte field index [0 .. 63]</param>
        /// <returns>Word value</returns>
        public ulong this[int key]
        {
            readonly get => GetWord(key);
            set => SetWord(key, value);
        }

        private readonly ulong GetWord(int index)
        {
            switch (index)
            {
                case 0: return w00;
                case 1: return w01;
                case 2: return w02;
                case 3: return w03;
                case 4: return w04;
                case 5: return w05;
                case 6: return w06;
                case 7: return w07;
                case 8: return w08;
                case 9: return w09;
                case 10: return w10;
                case 11: return w11;
                case 12: return w12;
                case 13: return w13;
                case 14: return w14;
                case 15: return w15;
                case 16: return w16;
                case 17: return w17;
                case 18: return w18;
                case 19: return w19;
                case 20: return w20;
                case 21: return w21;
                case 22: return w22;
                case 23: return w23;
                case 24: return w24;
                case 25: return w25;
                case 26: return w26;
                case 27: return w27;
                case 28: return w28;
                case 29: return w29;
                case 30: return w30;
                case 31: return w31;
                case 32: return w32;
                case 33: return w33;
                case 34: return w34;
                case 35: return w35;
                case 36: return w36;
                case 37: return w37;
                case 38: return w38;
                case 39: return w39;
                case 40: return w40;
                case 41: return w41;
                case 42: return w42;
                case 43: return w43;
                case 44: return w44;
                case 45: return w45;
                case 46: return w46;
                case 47: return w47;
                case 48: return w48;
                case 49: return w49;
                case 50: return w50;
                case 51: return w51;
                case 52: return w52;
                case 53: return w53;
                case 54: return w54;
                case 55: return w55;
                case 56: return w56;
                case 57: return w57;
                case 58: return w58;
                case 59: return w59;
                case 60: return w60;
                case 61: return w61;
                case 62: return w62;
                case 63: return w63;
                case 64: return w64;
                case 65: return w65;
                case 66: return w66;
                case 67: return w67;
                case 68: return w68;
                case 69: return w69;
                case 70: return w70;
                case 71: return w71;
                case 72: return w72;
                case 73: return w73;
                case 74: return w74;
                case 75: return w75;
                case 76: return w76;
                case 77: return w77;
                case 78: return w78;
                case 79: return w79;
                default:
                    {
                        throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 79] range");
                    }
            }
        }

        private ulong SetWord(int index, ulong value)
        {
            switch (index)
            {
                case 0: return w00 = value;
                case 1: return w01 = value;
                case 2: return w02 = value;
                case 3: return w03 = value;
                case 4: return w04 = value;
                case 5: return w05 = value;
                case 6: return w06 = value;
                case 7: return w07 = value;
                case 8: return w08 = value;
                case 9: return w09 = value;
                case 10: return w10 = value;
                case 11: return w11 = value;
                case 12: return w12 = value;
                case 13: return w13 = value;
                case 14: return w14 = value;
                case 15: return w15 = value;
                case 16: return w16 = value;
                case 17: return w17 = value;
                case 18: return w18 = value;
                case 19: return w19 = value;
                case 20: return w20 = value;
                case 21: return w21 = value;
                case 22: return w22 = value;
                case 23: return w23 = value;
                case 24: return w24 = value;
                case 25: return w25 = value;
                case 26: return w26 = value;
                case 27: return w27 = value;
                case 28: return w28 = value;
                case 29: return w29 = value;
                case 30: return w30 = value;
                case 31: return w31 = value;
                case 32: return w32 = value;
                case 33: return w33 = value;
                case 34: return w34 = value;
                case 35: return w35 = value;
                case 36: return w36 = value;
                case 37: return w37 = value;
                case 38: return w38 = value;
                case 39: return w39 = value;
                case 40: return w40 = value;
                case 41: return w41 = value;
                case 42: return w42 = value;
                case 43: return w43 = value;
                case 44: return w44 = value;
                case 45: return w45 = value;
                case 46: return w46 = value;
                case 47: return w47 = value;
                case 48: return w48 = value;
                case 49: return w49 = value;
                case 50: return w50 = value;
                case 51: return w51 = value;
                case 52: return w52 = value;
                case 53: return w53 = value;
                case 54: return w54 = value;
                case 55: return w55 = value;
                case 56: return w56 = value;
                case 57: return w57 = value;
                case 58: return w58 = value;
                case 59: return w59 = value;
                case 60: return w60 = value;
                case 61: return w61 = value;
                case 62: return w62 = value;
                case 63: return w63 = value;
                case 64: return w64 = value;
                case 65: return w65 = value;
                case 66: return w66 = value;
                case 67: return w67 = value;
                case 68: return w68 = value;
                case 69: return w69 = value;
                case 70: return w70 = value;
                case 71: return w71 = value;
                case 72: return w72 = value;
                case 73: return w73 = value;
                case 74: return w74 = value;
                case 75: return w75 = value;
                case 76: return w76 = value;
                case 77: return w77 = value;
                case 78: return w78 = value;
                case 79: return w79 = value;
                default:
                    {
                        throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 79] range");
                    }
            }
        }

        /// <summary>
        /// Test method
        /// </summary>
        public static void Test()
        {
            DWordVec80 wv = new();
            for (ulong i = 0; i < 80; i++)
            {
                wv[(int)i] = i;
            }

            for (ulong i = 0; i < 80; i++)
            {
                if (i != wv[(int)i]) throw new InvalidDataException("DWordVec80 fail");
            }
        }

        #region Individual word fields
        [FieldOffset(0)]
        private ulong w00 = 0;
        [FieldOffset(1 * sizeof(ulong))]
        private ulong w01 = 0;
        [FieldOffset(2 * sizeof(ulong))]
        private ulong w02 = 0;
        [FieldOffset(3 * sizeof(ulong))]
        private ulong w03 = 0;

        [FieldOffset(4 * sizeof(ulong))]
        private ulong w04 = 0;
        [FieldOffset(5 * sizeof(ulong))]
        private ulong w05 = 0;
        [FieldOffset(6 * sizeof(ulong))]
        private ulong w06 = 0;
        [FieldOffset(7 * sizeof(ulong))]
        private ulong w07 = 0;

        [FieldOffset(8 * sizeof(ulong))]
        private ulong w08 = 0;
        [FieldOffset(9 * sizeof(ulong))]
        private ulong w09 = 0;
        [FieldOffset(10 * sizeof(ulong))]
        private ulong w10 = 0;
        [FieldOffset(11 * sizeof(ulong))]
        private ulong w11 = 0;

        [FieldOffset(12 * sizeof(ulong))]
        private ulong w12 = 0;
        [FieldOffset(13 * sizeof(ulong))]
        private ulong w13 = 0;
        [FieldOffset(14 * sizeof(ulong))]
        private ulong w14 = 0;
        [FieldOffset(15 * sizeof(ulong))]
        private ulong w15 = 0;

        [FieldOffset(16 * sizeof(ulong))]
        private ulong w16 = 0;
        [FieldOffset(17 * sizeof(ulong))]
        private ulong w17 = 0;
        [FieldOffset(18 * sizeof(ulong))]
        private ulong w18 = 0;
        [FieldOffset(19 * sizeof(ulong))]
        private ulong w19 = 0;

        [FieldOffset(20 * sizeof(ulong))]
        private ulong w20 = 0;
        [FieldOffset(21 * sizeof(ulong))]
        private ulong w21 = 0;
        [FieldOffset(22 * sizeof(ulong))]
        private ulong w22 = 0;
        [FieldOffset(23 * sizeof(ulong))]
        private ulong w23 = 0;

        [FieldOffset(24 * sizeof(ulong))]
        private ulong w24 = 0;
        [FieldOffset(25 * sizeof(ulong))]
        private ulong w25 = 0;
        [FieldOffset(26 * sizeof(ulong))]
        private ulong w26 = 0;
        [FieldOffset(27 * sizeof(ulong))]
        private ulong w27 = 0;

        [FieldOffset(28 * sizeof(ulong))]
        private ulong w28 = 0;
        [FieldOffset(29 * sizeof(ulong))]
        private ulong w29 = 0;
        [FieldOffset(30 * sizeof(ulong))]
        private ulong w30 = 0;
        [FieldOffset(31 * sizeof(ulong))]
        private ulong w31 = 0;

        [FieldOffset(32 * sizeof(ulong))]
        private ulong w32 = 0;
        [FieldOffset(33 * sizeof(ulong))]
        private ulong w33 = 0;
        [FieldOffset(34 * sizeof(ulong))]
        private ulong w34 = 0;
        [FieldOffset(35 * sizeof(ulong))]
        private ulong w35 = 0;

        [FieldOffset(36 * sizeof(ulong))]
        private ulong w36 = 0;
        [FieldOffset(37 * sizeof(ulong))]
        private ulong w37 = 0;
        [FieldOffset(38 * sizeof(ulong))]
        private ulong w38 = 0;
        [FieldOffset(39 * sizeof(ulong))]
        private ulong w39 = 0;

        [FieldOffset(40 * sizeof(ulong))]
        private ulong w40 = 0;
        [FieldOffset(41 * sizeof(ulong))]
        private ulong w41 = 0;
        [FieldOffset(42 * sizeof(ulong))]
        private ulong w42 = 0;
        [FieldOffset(43 * sizeof(ulong))]
        private ulong w43 = 0;

        [FieldOffset(44 * sizeof(ulong))]
        private ulong w44 = 0;
        [FieldOffset(45 * sizeof(ulong))]
        private ulong w45 = 0;
        [FieldOffset(46 * sizeof(ulong))]
        private ulong w46 = 0;
        [FieldOffset(47 * sizeof(ulong))]
        private ulong w47 = 0;

        [FieldOffset(48 * sizeof(ulong))]
        private ulong w48 = 0;
        [FieldOffset(49 * sizeof(ulong))]
        private ulong w49 = 0;
        [FieldOffset(50 * sizeof(ulong))]
        private ulong w50 = 0;
        [FieldOffset(51 * sizeof(ulong))]
        private ulong w51 = 0;

        [FieldOffset(52 * sizeof(ulong))]
        private ulong w52 = 0;
        [FieldOffset(53 * sizeof(ulong))]
        private ulong w53 = 0;
        [FieldOffset(54 * sizeof(ulong))]
        private ulong w54 = 0;
        [FieldOffset(55 * sizeof(ulong))]
        private ulong w55 = 0;

        [FieldOffset(56 * sizeof(ulong))]
        private ulong w56 = 0;
        [FieldOffset(57 * sizeof(ulong))]
        private ulong w57 = 0;
        [FieldOffset(58 * sizeof(ulong))]
        private ulong w58 = 0;
        [FieldOffset(59 * sizeof(ulong))]
        private ulong w59 = 0;

        [FieldOffset(60 * sizeof(ulong))]
        private ulong w60 = 0;
        [FieldOffset(61 * sizeof(ulong))]
        private ulong w61 = 0;
        [FieldOffset(62 * sizeof(ulong))]
        private ulong w62 = 0;
        [FieldOffset(63 * sizeof(ulong))]
        private ulong w63 = 0;

        [FieldOffset(64 * sizeof(ulong))]
        private ulong w64 = 0;
        [FieldOffset(65 * sizeof(ulong))]
        private ulong w65 = 0;
        [FieldOffset(66 * sizeof(ulong))]
        private ulong w66 = 0;
        [FieldOffset(67 * sizeof(ulong))]
        private ulong w67 = 0;


        [FieldOffset(68 * sizeof(ulong))]
        private ulong w68 = 0;
        [FieldOffset(69 * sizeof(ulong))]
        private ulong w69 = 0;
        [FieldOffset(70 * sizeof(ulong))]
        private ulong w70 = 0;
        [FieldOffset(71 * sizeof(ulong))]
        private ulong w71 = 0;

        [FieldOffset(72 * sizeof(ulong))]
        private ulong w72 = 0;
        [FieldOffset(73 * sizeof(ulong))]
        private ulong w73 = 0;
        [FieldOffset(74 * sizeof(ulong))]
        private ulong w74 = 0;
        [FieldOffset(75 * sizeof(ulong))]
        private ulong w75 = 0;

        [FieldOffset(76 * sizeof(ulong))]
        private ulong w76 = 0;
        [FieldOffset(77 * sizeof(ulong))]
        private ulong w77 = 0;
        [FieldOffset(78 * sizeof(ulong))]
        private ulong w78 = 0;
        [FieldOffset(79 * sizeof(ulong))]
        private ulong w79 = 0;
        #endregion
    }
}
