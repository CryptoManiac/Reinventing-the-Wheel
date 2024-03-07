using System;
using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Crypto.Primitives.ByteVectors;

namespace Wheel.Crypto.Primitives.QWordVectors
{
    [StructLayout(LayoutKind.Explicit)]
    public struct QWordStruct
    {
        [FieldOffset(0)]
        public UInt128 value = 0;
        [FieldOffset(0)]
        public long lo;
        [FieldOffset(8)]
        public long hi;

        public QWordStruct(UInt128 input)
        {
            value = input;
        }

        /// <summary>
        /// Revert byte order
        /// </summary>
        public unsafe void Revert()
        {
            (lo, hi) = (IPAddress.NetworkToHostOrder(hi), IPAddress.NetworkToHostOrder(lo));
        }

        /// <summary>
        /// Implicit cast operator
        /// </summary>
        /// <param name="input">Value to convert from</param>
        public static implicit operator QWordStruct(UInt128 input)
        {
            return new QWordStruct(input);
        }

        public static implicit operator UInt128(QWordStruct input)
        {
            return input.value;
        }
    }

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

        public unsafe void SetWords(QWordVec8 wv8)
        {
            fixed (void* target = &this)
            {
                Buffer.MemoryCopy(&wv8, target, sizeof(UInt128) * 8, sizeof(UInt128) * 8);
            }
        }

        public unsafe void SetWords(params UInt128[] words)
        {
            if (words.Length != 8)
            {
                throw new ArgumentOutOfRangeException(nameof(words), words.Length, "Must provide 8 words exactly");
            }

            fixed (void* src = &words[0])
            {
                fixed (void* target = &this)
                {
                    Buffer.MemoryCopy(src, target, sizeof(UInt128) * 8, sizeof(UInt128) * 8);
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
        public unsafe void Reset()
        {
            fixed (void* ptr = &this)
            {
                Unsafe.InitBlockUnaligned(ptr, 0, (uint)sizeof(UInt128) * 8);
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
        private unsafe readonly UInt128 GetWord(int index)
        {
            if (index < 0 || index > 7)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 7] range");
            }

            fixed (QWordStruct* src = &w00)
            {
                return src[index].value;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe UInt128 SetWord(int index, UInt128 value)
        {
            if (index < 0 || index > 7)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 7] range");
            }

            fixed (QWordStruct* target = &w00)
            {
                return target[index].value = value;
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
        public QWordStruct w00;
        [FieldOffset(16)]
        public QWordStruct w01;
        [FieldOffset(32)]
        public QWordStruct w02;
        [FieldOffset(48)]
        public QWordStruct w03;

        [FieldOffset(64)]
        public QWordStruct w04;
        [FieldOffset(80)]
        public QWordStruct w05;
        [FieldOffset(96)]
        public QWordStruct w06;
        [FieldOffset(112)]
        public QWordStruct w07;
        #endregion
    }
}

