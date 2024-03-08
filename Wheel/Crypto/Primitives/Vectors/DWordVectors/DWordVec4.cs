using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Crypto.Miscellaneous.Support;

namespace Wheel.Crypto.Primitives.DWordVectors
{
    [StructLayout(LayoutKind.Explicit)]
    public struct DWordVec4
    {
        public DWordVec4()
        {

        }

        public DWordVec4(params ulong[] words)
        {
            SetWords(words);
        }

        public unsafe void SetWords(DWordVec4 wv4)
        {
            fixed (void* target = &this)
            {
                Buffer.MemoryCopy(&wv4, target, sizeof(ulong) * 4, sizeof(ulong) * 4);
            }
        }

        public unsafe void SetWords(params ulong[] words)
        {
            if (words.Length != 4)
            {
                throw new ArgumentOutOfRangeException(nameof(words), words.Length, "Must provide 4 words exactly");
            }

            fixed (void* src = &words[0])
            {
                fixed (void* target = &this)
                {
                    Buffer.MemoryCopy(src, target, sizeof(ulong) * 4, sizeof(ulong) * 4);
                }
            }
        }

        public unsafe void GetWords(Span<ulong> to)
        {
            fixed (void* ptr = &this)
            {
                new Span<ulong>(ptr, sizeof(ulong) * 4).CopyTo(to);
            }
        }

        /// <summary>
        /// Set to zero
        /// </summary>
        public unsafe void Reset()
        {
            fixed (void* ptr = &this)
            {
                Unsafe.InitBlockUnaligned(ptr, 0, sizeof(ulong) * 4);
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
        /// Index access to individual double word fields
        /// </summary>
        /// <param name="key">Byte field index [0 .. 3]</param>
        /// <returns>Double word value</returns>
        public ulong this[uint key]
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            readonly get => GetWord(key);
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            set => SetWord(key, value);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe readonly ulong GetWord(uint index)
        {
            if (index > 3)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 3] range");
            }

            fixed (ulong* src = &w00)
            {
                return src[index];
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe ulong SetWord(uint index, ulong value)
        {
            if (index > 3)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 3] range");
            }

            fixed (ulong* target = &w00)
            {
                return target[index] = value;
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
                wv[(uint)i] = i;
            }

            for (ulong i = 0; i < 4; i++)
            {
                if (i != wv[(uint)i]) throw new InvalidDataException("WordVec4 fail");
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
