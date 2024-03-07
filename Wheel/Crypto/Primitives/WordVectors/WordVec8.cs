using System.Runtime.CompilerServices;
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

        public WordVec8(params uint[] words)
        {
            SetWords(words);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe void SetWords(WordVec8 wv8)
        {
            fixed (void* target = &this)
            {
                Buffer.MemoryCopy(&wv8, target, sizeof(uint) * 8, sizeof(uint) * 8);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe void SetWords(params uint[] words)
        {
            if (words.Length != 8)
            {
                throw new ArgumentOutOfRangeException(nameof(words), words.Length, "Must provide 8 words exactly");
            }

            fixed (void* target = &this)
            {
                fixed (void* src = &words[0])
                {
                    Buffer.MemoryCopy(src, target, sizeof(uint) * 8, sizeof(uint) * 8);
                }
            }
        }

        public readonly uint[] GetWords()
        {
            return new uint[] { w00, w01, w02, w03, w04, w05, w06, w07 };
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
        /// Set to zero
        /// </summary>
        public unsafe void Reset()
        {
            fixed (void* ptr = &this)
            {
                Unsafe.InitBlockUnaligned(ptr, 0, sizeof(uint) * 8);
            }
        }

        /// <summary>
        /// Reverse byte order for all words
        /// </summary>
        public unsafe void RevertWords()
        {
            fixed (uint* ptr = &w00)
            {
                Common.REVERT8(ptr);
            }
        }

        /// <summary>
        /// Index access to individual word fields
        /// </summary>
        /// <param name="key">Byte field index [0 .. 7]</param>
        /// <returns>Word value</returns>
        public uint this[int key]
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            readonly get => GetWord(key);
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            set => SetWord(key, value);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe readonly uint GetWord(int index)
        {
            if (index < 0 || index > 7)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 7] range");
            }

            fixed (uint* src = &w00)
            {
                return src[index];
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe uint SetWord(int index, uint value)
        {
            if (index < 0 || index > 7)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 7] range");
            }

            fixed (uint* target = &w00)
            {
                return target[index] = value;
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
        #endregion
    }
}
