using System.Runtime.CompilerServices;
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

        public DWordVec80(params ulong[] words)
        {
            SetWords(words);
        }

        public void SetWords(params ulong[] words)
        {
            if (words.Length != 80)
            {
                throw new ArgumentException("Must provide 80 words exactly", nameof(words));
            }

            unsafe
            {
                fixed (ulong* src = &words[0])
                {
                    fixed (ulong* target = &w00)
                    {
                        Buffer.MemoryCopy(src, target, sizeof(ulong) * 80, sizeof(ulong) * 80);
                    }
                }
            }
        }

        /// <summary>
        /// Set to zero
        /// </summary>
        public void Reset()
        {
            unsafe
            {
                fixed (ulong* ptr = &w00)
                {
                    Unsafe.InitBlockUnaligned(ptr, 0, sizeof(ulong) * 80);
                }
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
