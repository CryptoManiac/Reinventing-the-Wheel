using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Crypto.Miscellaneous.Support;

namespace Wheel.Crypto.Primitives.WordVectors
{
    [StructLayout(LayoutKind.Explicit)]
    public struct WordVec2
	{
        public WordVec2(params uint[] words)
        {
            SetWords(words);
        }

        public void SetWords(WordVec2 wv2)
        {
            unsafe
            {
                fixed (void* target = &this)
                {
                    Buffer.MemoryCopy(&wv2, target, sizeof(uint) * 2, sizeof(uint) * 2);
                }
            }
        }

        public void SetWords(params uint[] words)
        {
            if (words.Length != 2)
            {
                throw new ArgumentException("Must provide 2 words exactly", nameof(words));
            }

            unsafe
            {
                fixed (void* target = &this)
                {
                    fixed (uint* src = &words[0])
                    {
                        Buffer.MemoryCopy(src, target, sizeof(uint) * 2, sizeof(uint) * 2);
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
                fixed (uint* ptr = &w00)
                {
                    Unsafe.InitBlockUnaligned(ptr, 0, sizeof(uint) * 2);
                }
            }
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
            if (index < 0 || index > 1)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 1] range");
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
            if (index < 0 || index > 1)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 1] range");
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
        public uint w00 = 0;
        [FieldOffset(4)]
        public uint w01 = 0;
        #endregion
    }
}
