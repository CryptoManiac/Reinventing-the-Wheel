using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Wheel.Crypto.Primitives.QWordVectors
{
    [StructLayout(LayoutKind.Explicit)]
    public struct QWordVec8
    {
        public QWordVec8()
        {

        }

        public QWordVec8(params UInt128[] words)
        {
            SetWords(words);
        }

        public void SetWords(QWordVec8 wv8)
        {
            unsafe
            {
                fixed (void* target = &this)
                {
                    Buffer.MemoryCopy(&wv8, target, sizeof(UInt128) * 8, sizeof(UInt128) * 8);
                }
            }
        }

        public void SetWords(params UInt128[] words)
        {
            if (words.Length != 8)
            {
                throw new ArgumentOutOfRangeException(nameof(words), words.Length, "Must provide 8 words exactly");
            }

            unsafe
            {
                fixed (UInt128* src = &words[0])
                {
                    fixed (void* target = &this)
                    {
                        Buffer.MemoryCopy(src, target, sizeof(UInt128) * 8, sizeof(UInt128) * 8);
                    }
                }
            }
        }

        public readonly UInt128[] GetWords()
        {
            return new UInt128[] { w00, w01, w02, w03, w04, w05, w06, w07 };
        }

        /// <summary>
        /// Set to zero
        /// </summary>
        public void Reset()
        {
            unsafe
            {
                fixed (UInt128* ptr = &w00)
                {
                    Unsafe.InitBlockUnaligned(ptr, 0, (uint) sizeof(UInt128) * 8);
                }
            }
        }

        /// <summary>
        /// Index access to individual word fields
        /// </summary>
        /// <param name="key">Byte field index [0 .. 7]</param>
        /// <returns>Word value</returns>
        public UInt128 this[int key]
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            readonly get => GetWord(key);
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            set => SetWord(key, value);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private readonly UInt128 GetWord(int index)
        {
            if (index < 0 || index > 7)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 7] range");
            }

            unsafe
            {
                fixed (UInt128* src = &w00)
                {
                    return src[index];
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private UInt128 SetWord(int index, UInt128 value)
        {
            if (index < 0 || index > 7)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 7] range");
            }

            unsafe
            {
                fixed (UInt128* target = &w00)
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
            QWordVec8 wv = new();
            for (ulong i = 0; i < 8; i++)
            {
                wv[(int)i] = i;
            }

            for (ulong i = 0; i < 8; i++)
            {
                if (i != wv[(int)i]) throw new InvalidDataException("QWordVec8 fail");
            }
        }

        #region Individual word fields
        [FieldOffset(0)]
        public UInt128 w00 = 0;
        [FieldOffset(16)]
        public UInt128 w01 = 0;
        [FieldOffset(32)]
        public UInt128 w02 = 0;
        [FieldOffset(48)]
        public UInt128 w03 = 0;

        [FieldOffset(64)]
        public UInt128 w04 = 0;
        [FieldOffset(80)]
        public UInt128 w05 = 0;
        [FieldOffset(96)]
        public UInt128 w06 = 0;
        [FieldOffset(112)]
        public UInt128 w07 = 0;
        #endregion
    }
}

