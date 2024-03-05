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
            unsafe
            {
                fixed(ulong *target = &w00)
                {
                    Buffer.MemoryCopy(&words.w00, target, sizeof(ulong) * 16, sizeof(ulong) * 16);
                }
            }
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
            if (index < 0 || index > 79)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 79] range");
            }

            unsafe
            {
                fixed (ulong* src = &w00)
                {
                    return src[index];
                }
            }
        }

        private ulong SetWord(int index, ulong value)
        {
            if (index < 0 || index > 79)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 79] range");
            }

            unsafe
            {
                fixed (ulong* target = &w00)
                {
                    return target[index] = value;
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
        public ulong w00 = 0;
        [FieldOffset(1 * sizeof(ulong))]
        public ulong w01 = 0;
        [FieldOffset(2 * sizeof(ulong))]
        public ulong w02 = 0;
        [FieldOffset(3 * sizeof(ulong))]
        public ulong w03 = 0;

        [FieldOffset(4 * sizeof(ulong))]
        public ulong w04 = 0;
        [FieldOffset(5 * sizeof(ulong))]
        public ulong w05 = 0;
        [FieldOffset(6 * sizeof(ulong))]
        public ulong w06 = 0;
        [FieldOffset(7 * sizeof(ulong))]
        public ulong w07 = 0;

        [FieldOffset(8 * sizeof(ulong))]
        public ulong w08 = 0;
        [FieldOffset(9 * sizeof(ulong))]
        public ulong w09 = 0;
        [FieldOffset(10 * sizeof(ulong))]
        public ulong w10 = 0;
        [FieldOffset(11 * sizeof(ulong))]
        public ulong w11 = 0;

        [FieldOffset(12 * sizeof(ulong))]
        public ulong w12 = 0;
        [FieldOffset(13 * sizeof(ulong))]
        public ulong w13 = 0;
        [FieldOffset(14 * sizeof(ulong))]
        public ulong w14 = 0;
        [FieldOffset(15 * sizeof(ulong))]
        public ulong w15 = 0;

        [FieldOffset(16 * sizeof(ulong))]
        public ulong w16 = 0;
        [FieldOffset(17 * sizeof(ulong))]
        public ulong w17 = 0;
        [FieldOffset(18 * sizeof(ulong))]
        public ulong w18 = 0;
        [FieldOffset(19 * sizeof(ulong))]
        public ulong w19 = 0;

        [FieldOffset(20 * sizeof(ulong))]
        public ulong w20 = 0;
        [FieldOffset(21 * sizeof(ulong))]
        public ulong w21 = 0;
        [FieldOffset(22 * sizeof(ulong))]
        public ulong w22 = 0;
        [FieldOffset(23 * sizeof(ulong))]
        public ulong w23 = 0;

        [FieldOffset(24 * sizeof(ulong))]
        public ulong w24 = 0;
        [FieldOffset(25 * sizeof(ulong))]
        public ulong w25 = 0;
        [FieldOffset(26 * sizeof(ulong))]
        public ulong w26 = 0;
        [FieldOffset(27 * sizeof(ulong))]
        public ulong w27 = 0;

        [FieldOffset(28 * sizeof(ulong))]
        public ulong w28 = 0;
        [FieldOffset(29 * sizeof(ulong))]
        public ulong w29 = 0;
        [FieldOffset(30 * sizeof(ulong))]
        public ulong w30 = 0;
        [FieldOffset(31 * sizeof(ulong))]
        public ulong w31 = 0;

        [FieldOffset(32 * sizeof(ulong))]
        public ulong w32 = 0;
        [FieldOffset(33 * sizeof(ulong))]
        public ulong w33 = 0;
        [FieldOffset(34 * sizeof(ulong))]
        public ulong w34 = 0;
        [FieldOffset(35 * sizeof(ulong))]
        public ulong w35 = 0;

        [FieldOffset(36 * sizeof(ulong))]
        public ulong w36 = 0;
        [FieldOffset(37 * sizeof(ulong))]
        public ulong w37 = 0;
        [FieldOffset(38 * sizeof(ulong))]
        public ulong w38 = 0;
        [FieldOffset(39 * sizeof(ulong))]
        public ulong w39 = 0;

        [FieldOffset(40 * sizeof(ulong))]
        public ulong w40 = 0;
        [FieldOffset(41 * sizeof(ulong))]
        public ulong w41 = 0;
        [FieldOffset(42 * sizeof(ulong))]
        public ulong w42 = 0;
        [FieldOffset(43 * sizeof(ulong))]
        public ulong w43 = 0;

        [FieldOffset(44 * sizeof(ulong))]
        public ulong w44 = 0;
        [FieldOffset(45 * sizeof(ulong))]
        public ulong w45 = 0;
        [FieldOffset(46 * sizeof(ulong))]
        public ulong w46 = 0;
        [FieldOffset(47 * sizeof(ulong))]
        public ulong w47 = 0;

        [FieldOffset(48 * sizeof(ulong))]
        public ulong w48 = 0;
        [FieldOffset(49 * sizeof(ulong))]
        public ulong w49 = 0;
        [FieldOffset(50 * sizeof(ulong))]
        public ulong w50 = 0;
        [FieldOffset(51 * sizeof(ulong))]
        public ulong w51 = 0;

        [FieldOffset(52 * sizeof(ulong))]
        public ulong w52 = 0;
        [FieldOffset(53 * sizeof(ulong))]
        public ulong w53 = 0;
        [FieldOffset(54 * sizeof(ulong))]
        public ulong w54 = 0;
        [FieldOffset(55 * sizeof(ulong))]
        public ulong w55 = 0;

        [FieldOffset(56 * sizeof(ulong))]
        public ulong w56 = 0;
        [FieldOffset(57 * sizeof(ulong))]
        public ulong w57 = 0;
        [FieldOffset(58 * sizeof(ulong))]
        public ulong w58 = 0;
        [FieldOffset(59 * sizeof(ulong))]
        public ulong w59 = 0;

        [FieldOffset(60 * sizeof(ulong))]
        public ulong w60 = 0;
        [FieldOffset(61 * sizeof(ulong))]
        public ulong w61 = 0;
        [FieldOffset(62 * sizeof(ulong))]
        public ulong w62 = 0;
        [FieldOffset(63 * sizeof(ulong))]
        public ulong w63 = 0;

        [FieldOffset(64 * sizeof(ulong))]
        public ulong w64 = 0;
        [FieldOffset(65 * sizeof(ulong))]
        public ulong w65 = 0;
        [FieldOffset(66 * sizeof(ulong))]
        public ulong w66 = 0;
        [FieldOffset(67 * sizeof(ulong))]
        public ulong w67 = 0;


        [FieldOffset(68 * sizeof(ulong))]
        public ulong w68 = 0;
        [FieldOffset(69 * sizeof(ulong))]
        public ulong w69 = 0;
        [FieldOffset(70 * sizeof(ulong))]
        public ulong w70 = 0;
        [FieldOffset(71 * sizeof(ulong))]
        public ulong w71 = 0;

        [FieldOffset(72 * sizeof(ulong))]
        public ulong w72 = 0;
        [FieldOffset(73 * sizeof(ulong))]
        public ulong w73 = 0;
        [FieldOffset(74 * sizeof(ulong))]
        public ulong w74 = 0;
        [FieldOffset(75 * sizeof(ulong))]
        public ulong w75 = 0;

        [FieldOffset(76 * sizeof(ulong))]
        public ulong w76 = 0;
        [FieldOffset(77 * sizeof(ulong))]
        public ulong w77 = 0;
        [FieldOffset(78 * sizeof(ulong))]
        public ulong w78 = 0;
        [FieldOffset(79 * sizeof(ulong))]
        public ulong w79 = 0;
        #endregion
    }
}
