using System.Runtime.InteropServices;
using Wheel.Crypto.Miscellaneous.Support;

namespace Wheel.Crypto.Primitives.WordVectors
{
    [StructLayout(LayoutKind.Explicit)]
    public struct DWordVec8
    {
        public DWordVec8()
        {
        }

        public DWordVec8(ulong w00, ulong w01, ulong w02, ulong w03, ulong w04, ulong w05, ulong w06, ulong w07)
        {
            this.w00 = w00;
            this.w01 = w01;
            this.w02 = w02;
            this.w03 = w03;
            this.w04 = w04;
            this.w05 = w05;
            this.w06 = w06;
            this.w07 = w07;
        }

        public void SetWords(DWordVec8 wv8)
        {
            w00 = wv8.w00;
            w01 = wv8.w01;
            w02 = wv8.w02;
            w03 = wv8.w03;
            w04 = wv8.w04;
            w05 = wv8.w05;
            w06 = wv8.w06;
            w07 = wv8.w07;
        }

        public void SetWords(ulong[] words)
        {
            if (words.Length != 8)
            {
                throw new ArgumentException("Array must be 8 items long", nameof(words));
            }

            w00 = words[0];
            w01 = words[1];
            w02 = words[2];
            w03 = words[3];
            w04 = words[4];
            w05 = words[5];
            w06 = words[6];
            w07 = words[7];
        }

        public void SetWords(ulong w00, ulong w01, ulong w02, ulong w03, ulong w04, ulong w05, ulong w06, ulong w07)
        {
            this.w00 = w00;
            this.w01 = w01;
            this.w02 = w02;
            this.w03 = w03;
            this.w04 = w04;
            this.w05 = w05;
            this.w06 = w06;
            this.w07 = w07;
        }

        public readonly ulong[] GetWords()
        {
            return new ulong[] { w00, w01, w02, w03, w04, w05, w06, w07 };
        }

        public void AddWords(DWordVec8 wv8)
        {
            w00 += wv8.w00;
            w01 += wv8.w01;
            w02 += wv8.w02;
            w03 += wv8.w03;
            w04 += wv8.w04;
            w05 += wv8.w05;
            w06 += wv8.w06;
            w07 += wv8.w07;
        }

        public void AddWords(ulong w00, ulong w01, ulong w02, ulong w03, ulong w04, ulong w05, ulong w06, ulong w07)
        {
            this.w00 += w00;
            this.w01 += w01;
            this.w02 += w02;
            this.w03 += w03;
            this.w04 += w04;
            this.w05 += w05;
            this.w06 += w06;
            this.w07 += w07;
        }

        /// <summary>
        /// Set to zeros
        /// </summary>
        public void Reset()
        {
            for (ulong i = 0; i < 8; i++)
            {
                this[(int)i] = 0;
            }
        }

        /// <summary>
        /// Reverse byte order for all words
        /// </summary>
        public void RevertWords()
        {
            w00 = Common.REVERT(w00);
            w01 = Common.REVERT(w01);
            w02 = Common.REVERT(w02);
            w03 = Common.REVERT(w03);
            w04 = Common.REVERT(w04);
            w05 = Common.REVERT(w05);
            w06 = Common.REVERT(w06);
            w07 = Common.REVERT(w07);
        }

        /// <summary>
        /// Index access to individual word fields
        /// </summary>
        /// <param name="key">Byte field index [0 .. 7]</param>
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
                default:
                    {
                        throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 7] range");
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
            DWordVec8 wv = new();
            for (ulong i = 0; i < 8; i++)
            {
                wv[(int)i] = i;
            }

            for (ulong i = 0; i < 8; i++)
            {
                if (i != wv[(int)i]) throw new InvalidDataException("DWordVec8 fail");
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
        #endregion
    }
}
