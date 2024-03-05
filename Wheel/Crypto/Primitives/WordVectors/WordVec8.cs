using System.Runtime.InteropServices;
using Wheel.Crypto.Miscellaneous.Support;

namespace Wheel.Crypto.Primitives.WordVectors
{
    [StructLayout(LayoutKind.Explicit)]
    public struct WordVec8
	{
        public WordVec8()
        {
        }

        public WordVec8(uint w00, uint w01, uint w02, uint w03, uint w04, uint w05, uint w06, uint w07)
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

        public void SetWords(WordVec8 wv8)
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

        public void SetWords(uint[] words)
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

        public uint[] GetWords()
        {
            return new uint[] { w00, w01, w02, w03, w04, w05, w06, w07 };
        }

        public void SetWords(uint w00, uint w01, uint w02, uint w03, uint w04, uint w05, uint w06, uint w07)
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

        public void AddWords(WordVec8 wv8)
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

        public void AddWords(uint w00, uint w01, uint w02, uint w03, uint w04, uint w05, uint w06, uint w07)
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
            for (int i = 0; i < 8; i++)
            {
                this[i] = 0;
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
        public uint this[int key]
        {
            readonly get => GetWord(key);
            set => SetWord(key, value);
        }

        private readonly uint GetWord(int index)
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

        private uint SetWord(int index, uint value)
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
            WordVec8 wv = new();
            for (uint i = 0; i < 8; i++)
            {
                wv[(int)i] = i;
            }

            for (uint i = 0; i < 8; i++)
            {
                if (i != wv[(int)i]) throw new InvalidDataException("WordVec8 fail");
            }
        }

        #region Individual word fields
        [FieldOffset(0)]
        private uint w00 = 0;
        [FieldOffset(1 * sizeof(uint))]
        private uint w01 = 0;
        [FieldOffset(2 * sizeof(uint))]
        private uint w02 = 0;
        [FieldOffset(3 * sizeof(uint))]
        private uint w03 = 0;

        [FieldOffset(4 * sizeof(uint))]
        private uint w04 = 0;
        [FieldOffset(5 * sizeof(uint))]
        private uint w05 = 0;
        [FieldOffset(6 * sizeof(uint))]
        private uint w06 = 0;
        [FieldOffset(7 * sizeof(uint))]
        private uint w07 = 0;
        #endregion
    }
}
