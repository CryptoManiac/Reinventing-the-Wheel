using System.Runtime.InteropServices;
using Wheel.Crypto.Miscellaneous.Support;

namespace Wheel.Crypto.Primitives.WordVectors
{
    [StructLayout(LayoutKind.Explicit)]
    public struct WordVec64
	{
        public WordVec64()
        {

        }

        public WordVec64(uint w00, uint w01, uint w02, uint w03, uint w04, uint w05, uint w06, uint w07, uint w08, uint w09, uint w10, uint w11, uint w12, uint w13, uint w14, uint w15, uint w16, uint w17, uint w18, uint w19, uint w20, uint w21, uint w22, uint w23, uint w24, uint w25, uint w26, uint w27, uint w28, uint w29, uint w30, uint w31, uint w32, uint w33, uint w34, uint w35, uint w36, uint w37, uint w38, uint w39, uint w40, uint w41, uint w42, uint w43, uint w44, uint w45, uint w46, uint w47, uint w48, uint w49, uint w50, uint w51, uint w52, uint w53, uint w54, uint w55, uint w56, uint w57, uint w58, uint w59, uint w60, uint w61, uint w62, uint w63)
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
        }

        public void SetWords(uint w00, uint w01, uint w02, uint w03, uint w04, uint w05, uint w06, uint w07, uint w08, uint w09, uint w10, uint w11, uint w12, uint w13, uint w14, uint w15, uint w16, uint w17, uint w18, uint w19, uint w20, uint w21, uint w22, uint w23, uint w24, uint w25, uint w26, uint w27, uint w28, uint w29, uint w30, uint w31, uint w32, uint w33, uint w34, uint w35, uint w36, uint w37, uint w38, uint w39, uint w40, uint w41, uint w42, uint w43, uint w44, uint w45, uint w46, uint w47, uint w48, uint w49, uint w50, uint w51, uint w52, uint w53, uint w54, uint w55, uint w56, uint w57, uint w58, uint w59, uint w60, uint w61, uint w62, uint w63)
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
        }

        /// <summary>
        /// Set to zeros
        /// </summary>
        public void Reset()
        {
            for (int i = 0; i < 64; i++)
            {
                this[i] = 0;
            }
        }

        /// <summary>
        /// Set first 16 words from the provided container
        /// </summary>
        /// <param name="words">Vector to provide 16 words</param>
        public void Set16Words(WordVec16 words)
        {
            unsafe
            {
                fixed (uint* target = &w00)
                {
                    Buffer.MemoryCopy(&words.w00, target, sizeof(uint) * 16, sizeof(uint) * 16);
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
        public uint this[int key]
        {
            readonly get => GetWord(key);
            set => SetWord(key, value);
        }

        private readonly uint GetWord(int index)
        {
            if (index < 0 || index > 63)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 63] range");
            }

            unsafe
            {
                fixed (uint* src = &w00)
                {
                    return src[index];
                }
            }
        }

        private uint SetWord(int index, uint value)
        {
            if (index < 0 || index > 63)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 63] range");
            }

            unsafe
            {
                fixed (uint* target = &w00)
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
            WordVec64 wv = new();
            for (uint i = 0; i < 64; i++)
            {
                wv[(int)i] = i;
            }

            for (uint i = 0; i < 64; i++)
            {
                if (i != wv[(int)i]) throw new InvalidDataException("WordVec64 fail");
            }
        }

        #region Individual word fields
        [FieldOffset(0)]
        public uint w00 = 0;
        [FieldOffset(1 * sizeof(uint))]
        public uint w01 = 0;
        [FieldOffset(2 * sizeof(uint))]
        public uint w02 = 0;
        [FieldOffset(3 * sizeof(uint))]
        public uint w03 = 0;

        [FieldOffset(4 * sizeof(uint))]
        public uint w04 = 0;
        [FieldOffset(5 * sizeof(uint))]
        public uint w05 = 0;
        [FieldOffset(6 * sizeof(uint))]
        public uint w06 = 0;
        [FieldOffset(7 * sizeof(uint))]
        public uint w07 = 0;

        [FieldOffset(8 * sizeof(uint))]
        public uint w08 = 0;
        [FieldOffset(9 * sizeof(uint))]
        public uint w09 = 0;
        [FieldOffset(10 * sizeof(uint))]
        public uint w10 = 0;
        [FieldOffset(11 * sizeof(uint))]
        public uint w11 = 0;

        [FieldOffset(12 * sizeof(uint))]
        public uint w12 = 0;
        [FieldOffset(13 * sizeof(uint))]
        public uint w13 = 0;
        [FieldOffset(14 * sizeof(uint))]
        public uint w14 = 0;
        [FieldOffset(15 * sizeof(uint))]
        public uint w15 = 0;

        [FieldOffset(16 * sizeof(uint))]
        public uint w16 = 0;
        [FieldOffset(17 * sizeof(uint))]
        public uint w17 = 0;
        [FieldOffset(18 * sizeof(uint))]
        public uint w18 = 0;
        [FieldOffset(19 * sizeof(uint))]
        public uint w19 = 0;

        [FieldOffset(20 * sizeof(uint))]
        public uint w20 = 0;
        [FieldOffset(21 * sizeof(uint))]
        public uint w21 = 0;
        [FieldOffset(22 * sizeof(uint))]
        public uint w22 = 0;
        [FieldOffset(23 * sizeof(uint))]
        public uint w23 = 0;

        [FieldOffset(24 * sizeof(uint))]
        public uint w24 = 0;
        [FieldOffset(25 * sizeof(uint))]
        public uint w25 = 0;
        [FieldOffset(26 * sizeof(uint))]
        public uint w26 = 0;
        [FieldOffset(27 * sizeof(uint))]
        public uint w27 = 0;

        [FieldOffset(28 * sizeof(uint))]
        public uint w28 = 0;
        [FieldOffset(29 * sizeof(uint))]
        public uint w29 = 0;
        [FieldOffset(30 * sizeof(uint))]
        public uint w30 = 0;
        [FieldOffset(31 * sizeof(uint))]
        public uint w31 = 0;

        [FieldOffset(32 * sizeof(uint))]
        public uint w32 = 0;
        [FieldOffset(33 * sizeof(uint))]
        public uint w33 = 0;
        [FieldOffset(34 * sizeof(uint))]
        public uint w34 = 0;
        [FieldOffset(35 * sizeof(uint))]
        public uint w35 = 0;

        [FieldOffset(36 * sizeof(uint))]
        public uint w36 = 0;
        [FieldOffset(37 * sizeof(uint))]
        public uint w37 = 0;
        [FieldOffset(38 * sizeof(uint))]
        public uint w38 = 0;
        [FieldOffset(39 * sizeof(uint))]
        public uint w39 = 0;

        [FieldOffset(40 * sizeof(uint))]
        public uint w40 = 0;
        [FieldOffset(41 * sizeof(uint))]
        public uint w41 = 0;
        [FieldOffset(42 * sizeof(uint))]
        public uint w42 = 0;
        [FieldOffset(43 * sizeof(uint))]
        public uint w43 = 0;

        [FieldOffset(44 * sizeof(uint))]
        public uint w44 = 0;
        [FieldOffset(45 * sizeof(uint))]
        public uint w45 = 0;
        [FieldOffset(46 * sizeof(uint))]
        public uint w46 = 0;
        [FieldOffset(47 * sizeof(uint))]
        public uint w47 = 0;

        [FieldOffset(48 * sizeof(uint))]
        public uint w48 = 0;
        [FieldOffset(49 * sizeof(uint))]
        public uint w49 = 0;
        [FieldOffset(50 * sizeof(uint))]
        public uint w50 = 0;
        [FieldOffset(51 * sizeof(uint))]
        public uint w51 = 0;

        [FieldOffset(52 * sizeof(uint))]
        public uint w52 = 0;
        [FieldOffset(53 * sizeof(uint))]
        public uint w53 = 0;
        [FieldOffset(54 * sizeof(uint))]
        public uint w54 = 0;
        [FieldOffset(55 * sizeof(uint))]
        public uint w55 = 0;

        [FieldOffset(56 * sizeof(uint))]
        public uint w56 = 0;
        [FieldOffset(57 * sizeof(uint))]
        public uint w57 = 0;
        [FieldOffset(58 * sizeof(uint))]
        public uint w58 = 0;
        [FieldOffset(59 * sizeof(uint))]
        public uint w59 = 0;

        [FieldOffset(60 * sizeof(uint))]
        public uint w60 = 0;
        [FieldOffset(61 * sizeof(uint))]
        public uint w61 = 0;
        [FieldOffset(62 * sizeof(uint))]
        public uint w62 = 0;
        [FieldOffset(63 * sizeof(uint))]
        public uint w63 = 0;
        #endregion
    }
}
