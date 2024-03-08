using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Crypto.Miscellaneous.Support;

namespace Wheel.Crypto.Primitives.DWordVectors
{
    [StructLayout(LayoutKind.Explicit)]
    public struct DWordVec16
    {
        public DWordVec16()
        {

        }

        public DWordVec16(params ulong[] words)
        {
            SetWords(words);
        }

        public unsafe void SetWords(DWordVec16 wv16)
        {
            fixed (void* target = &this)
            {
                Buffer.MemoryCopy(&wv16, target, sizeof(ulong) * 16, sizeof(ulong) * 16);
            }
        }

        public unsafe void SetWords(params ulong[] words)
        {
            if (words.Length != 16)
            {
                throw new ArgumentOutOfRangeException(nameof(words), words.Length, "Must provide 16 words exactly");
            }

            fixed (void* src = &words[0])
            {
                fixed (void* target = &this)
                {
                    Buffer.MemoryCopy(src, target, sizeof(ulong) * 16, sizeof(ulong) * 16);
                }
            }
        }

        public void AddWords(DWordVec16 wv8)
        {
            this.w00 += wv8.w00;
            this.w01 += wv8.w01;
            this.w02 += wv8.w02;
            this.w03 += wv8.w03;
            this.w04 += wv8.w04;
            this.w05 += wv8.w05;
            this.w06 += wv8.w06;
            this.w07 += wv8.w07;
        }

        public void AddWords(ulong w00, ulong w01, ulong w02, ulong w03, ulong w04, ulong w05, ulong w06, ulong w07, ulong w08, ulong w09, ulong w10, ulong w11, ulong w12, ulong w13, ulong w14, ulong w15)
        {
            this.w00 += w00;
            this.w01 += w01;
            this.w02 += w02;
            this.w03 += w03;
            this.w04 += w04;
            this.w05 += w05;
            this.w06 += w06;
            this.w07 += w07;
            this.w08 += w08;
            this.w09 += w09;
            this.w10 += w10;
            this.w11 += w11;
            this.w12 += w12;
            this.w13 += w13;
            this.w14 += w14;
            this.w15 += w15;
        }

        public readonly ulong[] GetWords()
        {
            return new ulong[] { w00, w01, w02, w03, w04, w05, w06, w07, w08, w09, w10, w11, w12, w13, w14, w15 };
        }

        /// <summary>
        /// Set to zero
        /// </summary>
        public unsafe void Reset()
        {
            fixed (void* ptr = &this)
            {
                Unsafe.InitBlockUnaligned(ptr, 0, sizeof(ulong) * 16);
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
        /// <param name="key">Byte field index [0 .. 7]</param>
        /// <returns>Word value</returns>
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
            if (index > 15)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 15] range");
            }

            fixed (ulong* src = &w00)
            {
                return src[index];
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe ulong SetWord(uint index, ulong value)
        {
            if (index > 15)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 15] range");
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
            DWordVec16 wv = new();
            for (ulong i = 0; i < 8; i++)
            {
                wv[(uint)i] = i;
            }

            for (ulong i = 0; i < 8; i++)
            {
                if (i != wv[(uint)i]) throw new InvalidDataException("DWordVec16 fail");
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
        #endregion
    }
}
