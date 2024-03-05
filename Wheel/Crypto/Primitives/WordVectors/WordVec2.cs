using System.Runtime.InteropServices;
using Wheel.Crypto.Miscellaneous.Support;

namespace Wheel.Crypto.Primitives.WordVectors
{
    [StructLayout(LayoutKind.Explicit)]
    public struct WordVec2
	{
        public WordVec2()
        {
        }

        public void SetWords(uint w00, uint w01)
        {
            this.w00 = w00;
            this.w01 = w01;
        }

        /// <summary>
        /// Set to zeros
        /// </summary>
        public void Reset()
        {
            w00 = 0;
            w01 = 0;
        }

        /// <summary>
        /// Reverse byte order for all words
        /// </summary>
        public void RevertWords()
        {
            w00 = Common.REVERT(w00);
            w01 = Common.REVERT(w01);
        }

        /// <summary>
        /// Index access to individual word fields
        /// </summary>
        /// <param name="key">Byte field index [0 .. 1]</param>
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
                default:
                    {
                        throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 1] range");
                    }
            }
        }

        private uint SetWord(int index, uint value)
        {
            switch (index)
            {
                case 0: return w00 = value;
                case 1: return w01 = value;
                default:
                    {
                        throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 1] range");
                    }
            }
        }

        /// <summary>
        /// Test method
        /// </summary>
        public static void Test()
        {
            WordVec2 wv = new();
            for (uint i = 0; i < 2; i++)
            {
                wv[(int)i] = i;
            }

            for (uint i = 0; i < 2; i++)
            {
                if (i != wv[(int)i]) throw new InvalidDataException("WordVec2 fail");
            }
        }

        #region Individual word fields
        [FieldOffset(0)]
        private uint w00 = 0;
        [FieldOffset(4)]
        private uint w01 = 0;
        #endregion
    }
}
