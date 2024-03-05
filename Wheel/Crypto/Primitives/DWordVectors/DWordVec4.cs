using System.Runtime.InteropServices;
using Wheel.Crypto.Miscellaneous.Support;

namespace Wheel.Crypto.Primitives.WordVectors
{
    [StructLayout(LayoutKind.Explicit)]
    public struct DWordVec4
    {
        public DWordVec4()
        {
        }

        public void SetWords(ulong w00, ulong w01, ulong w02, ulong w03)
        {
            this.w00 = w00;
            this.w01 = w01;
            this.w02 = w02;
            this.w03 = w03;
        }

        /// <summary>
        /// Set to zeros
        /// </summary>
        public void Reset()
        {
            w00 = 0;
            w01 = 0;
            w02 = 0;
            w03 = 0;
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
        }

        public readonly ulong[] GetWords()
        {
            return new ulong[] { w00, w01, w02, w03 };
        }

        /// <summary>
        /// Index access to individual double word fields
        /// </summary>
        /// <param name="key">Byte field index [0 .. 3]</param>
        /// <returns>Double word value</returns>
        public ulong this[int key]
        {
            readonly get => GetWord(key);
            set => SetWord(key, value);
        }

        private readonly ulong GetWord(int index)
        {
            if (index < 0 || index > 3)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 3] range");
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
            if (index < 0 || index > 3)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 3] range");
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
            DWordVec4 wv = new();
            for (ulong i = 0; i < 4; i++)
            {
                wv[(int)i] = i;
            }

            for (ulong i = 0; i < 4; i++)
            {
                if (i != wv[(int)i]) throw new InvalidDataException("WordVec4 fail");
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
        #endregion
    }
}
