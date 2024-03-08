using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Crypto.Miscellaneous.Support;

namespace Wheel.Crypto.Primitives.WordVectors
{
    [StructLayout(LayoutKind.Explicit)]
    public struct WordVec4
	{
        public WordVec4(params uint[] words)
        {
            SetWords(words);
        }

        public unsafe void SetWords(WordVec4 wv4)
        {
            fixed (void* target = &w00)
            {
                Buffer.MemoryCopy(&wv4, target, sizeof(uint) * 4, sizeof(uint) * 4);
            }
        }

        public unsafe void SetWords(params uint[] words)
        {
            if (words.Length != 4)
            {
                throw new ArgumentOutOfRangeException(nameof(words), words.Length, "Must provide 4 words exactly");
            }

            fixed (void* target = &this)
            {
                fixed (void* src = &words[0])
                {
                    Buffer.MemoryCopy(src, target, sizeof(uint) * 4, sizeof(uint) * 4);
                }
            }
        }

        public unsafe void GetWords(Span<uint> to)
        {
            fixed (void* ptr = &this)
            {
                new Span<uint>(ptr, 4).CopyTo(to);
            }
        }

        /// <summary>
        /// Set to zero
        /// </summary>
        public unsafe void Reset()
        {
            fixed (void* ptr = &this)
            {
                Unsafe.InitBlockUnaligned(ptr, 0, sizeof(uint) * 4);
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
        }

        /// <summary>
        /// Index access to individual word fields
        /// </summary>
        /// <param name="key">Byte field index [0 .. 3]</param>
        /// <returns>Word value</returns>
        public uint this[uint key]
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            readonly get => GetWord(key);
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            set => SetWord(key, value);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe readonly uint GetWord(uint index)
        {
            if (index > 3)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 3] range");
            }

            fixed (uint* src = &w00)
            {
                return src[index];
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe uint SetWord(uint index, uint value)
        {
            if (index > 3)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 3] range");
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
            WordVec4 wv = new();
            for (uint i = 0; i < 4; i++)
            {
                wv[i] = i;
            }

            for (uint i = 0; i < 4; i++)
            {
                if (i != wv[i]) throw new InvalidDataException("WordVec4 fail");
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
        #endregion
    }
}
