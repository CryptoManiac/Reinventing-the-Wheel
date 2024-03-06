using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Crypto.Miscellaneous.Support;

namespace Wheel.Crypto.Primitives.WordVectors
{
    [StructLayout(LayoutKind.Explicit)]
    public struct WordVec64
	{
        public WordVec64()
        {

        }

        public WordVec64(params uint[] words)
        {
            SetWords(words);
        }

        public void SetWords(params uint[] words)
        {
            if (words.Length != 64)
            {
                throw new ArgumentOutOfRangeException(nameof(words), words.Length, "Must provide 64 words exactly");
            }

            unsafe
            {
                fixed (uint* src = &words[0])
                {
                    fixed (void* target = &this)
                    {
                        Buffer.MemoryCopy(src, target, sizeof(uint) * 64, sizeof(uint) * 64);
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
                fixed (void* ptr = &this)
                {
                    Unsafe.InitBlockUnaligned(ptr, 0, sizeof(uint) * 64);
                }
            }
        }

        /// <summary>
        /// Set first 16 words from the provided container
        /// </summary>
        /// <param name="words">Vector to provide 16 words</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Set16Words(WordVec16 words)
        {
            unsafe
            {
                fixed (void* target = &this)
                {
                    Buffer.MemoryCopy(&words, target, sizeof(uint) * 16, sizeof(uint) * 16);
                }
            }
        }

        /// <summary>
        /// Reverse byte order for the first 16 words
        /// </summary>
        public void Revert16Words()
        {
            unsafe
            {
                fixed (uint* ptr = &w00) {
                    Common.REVERT16(ptr);
                }
            }
        }

        /// <summary>
        /// Index access to individual word fields
        /// </summary>
        /// <param name="key">Byte field index [0 .. 63]</param>
        /// <returns>Word value</returns>
        public uint this[int key]
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            readonly get => GetWord(key);
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            set => SetWord(key, value);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private readonly uint GetWord(int index)
        {
            if (index < 0 || index > 63)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 63] range");
            }

            unsafe
            {
                fixed (uint* src = &w00)
                {
                    return src[index];
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint SetWord(int index, uint value)
        {
            if (index < 0 || index > 63)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 63] range");
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
            WordVec64 wv = new();
            for (uint i = 0; i < 64; i++)
            {
                wv[(int)i] = i;
            }

            for (uint i = 0; i < 64; i++)
            {
                if (i != wv[(int)i]) throw new InvalidDataException("WordVec64 fail");
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

        [FieldOffset(8 * sizeof(uint))]
        public uint w08 = 0;
        [FieldOffset(9 * sizeof(uint))]
        public uint w09 = 0;
        [FieldOffset(10 * sizeof(uint))]
        public uint w10 = 0;
        [FieldOffset(11 * sizeof(uint))]
        public uint w11 = 0;

        [FieldOffset(12 * sizeof(uint))]
        public uint w12 = 0;
        [FieldOffset(13 * sizeof(uint))]
        public uint w13 = 0;
        [FieldOffset(14 * sizeof(uint))]
        public uint w14 = 0;
        [FieldOffset(15 * sizeof(uint))]
        public uint w15 = 0;

        [FieldOffset(16 * sizeof(uint))]
        public uint w16 = 0;
        [FieldOffset(17 * sizeof(uint))]
        public uint w17 = 0;
        [FieldOffset(18 * sizeof(uint))]
        public uint w18 = 0;
        [FieldOffset(19 * sizeof(uint))]
        public uint w19 = 0;

        [FieldOffset(20 * sizeof(uint))]
        public uint w20 = 0;
        [FieldOffset(21 * sizeof(uint))]
        public uint w21 = 0;
        [FieldOffset(22 * sizeof(uint))]
        public uint w22 = 0;
        [FieldOffset(23 * sizeof(uint))]
        public uint w23 = 0;

        [FieldOffset(24 * sizeof(uint))]
        public uint w24 = 0;
        [FieldOffset(25 * sizeof(uint))]
        public uint w25 = 0;
        [FieldOffset(26 * sizeof(uint))]
        public uint w26 = 0;
        [FieldOffset(27 * sizeof(uint))]
        public uint w27 = 0;

        [FieldOffset(28 * sizeof(uint))]
        public uint w28 = 0;
        [FieldOffset(29 * sizeof(uint))]
        public uint w29 = 0;
        [FieldOffset(30 * sizeof(uint))]
        public uint w30 = 0;
        [FieldOffset(31 * sizeof(uint))]
        public uint w31 = 0;

        [FieldOffset(32 * sizeof(uint))]
        public uint w32 = 0;
        [FieldOffset(33 * sizeof(uint))]
        public uint w33 = 0;
        [FieldOffset(34 * sizeof(uint))]
        public uint w34 = 0;
        [FieldOffset(35 * sizeof(uint))]
        public uint w35 = 0;

        [FieldOffset(36 * sizeof(uint))]
        public uint w36 = 0;
        [FieldOffset(37 * sizeof(uint))]
        public uint w37 = 0;
        [FieldOffset(38 * sizeof(uint))]
        public uint w38 = 0;
        [FieldOffset(39 * sizeof(uint))]
        public uint w39 = 0;

        [FieldOffset(40 * sizeof(uint))]
        public uint w40 = 0;
        [FieldOffset(41 * sizeof(uint))]
        public uint w41 = 0;
        [FieldOffset(42 * sizeof(uint))]
        public uint w42 = 0;
        [FieldOffset(43 * sizeof(uint))]
        public uint w43 = 0;

        [FieldOffset(44 * sizeof(uint))]
        public uint w44 = 0;
        [FieldOffset(45 * sizeof(uint))]
        public uint w45 = 0;
        [FieldOffset(46 * sizeof(uint))]
        public uint w46 = 0;
        [FieldOffset(47 * sizeof(uint))]
        public uint w47 = 0;

        [FieldOffset(48 * sizeof(uint))]
        public uint w48 = 0;
        [FieldOffset(49 * sizeof(uint))]
        public uint w49 = 0;
        [FieldOffset(50 * sizeof(uint))]
        public uint w50 = 0;
        [FieldOffset(51 * sizeof(uint))]
        public uint w51 = 0;

        [FieldOffset(52 * sizeof(uint))]
        public uint w52 = 0;
        [FieldOffset(53 * sizeof(uint))]
        public uint w53 = 0;
        [FieldOffset(54 * sizeof(uint))]
        public uint w54 = 0;
        [FieldOffset(55 * sizeof(uint))]
        public uint w55 = 0;

        [FieldOffset(56 * sizeof(uint))]
        public uint w56 = 0;
        [FieldOffset(57 * sizeof(uint))]
        public uint w57 = 0;
        [FieldOffset(58 * sizeof(uint))]
        public uint w58 = 0;
        [FieldOffset(59 * sizeof(uint))]
        public uint w59 = 0;

        [FieldOffset(60 * sizeof(uint))]
        public uint w60 = 0;
        [FieldOffset(61 * sizeof(uint))]
        public uint w61 = 0;
        [FieldOffset(62 * sizeof(uint))]
        public uint w62 = 0;
        [FieldOffset(63 * sizeof(uint))]
        public uint w63 = 0;
        #endregion
    }
}
