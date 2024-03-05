using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Crypto.Primitives.WordVectors;

namespace Wheel.Crypto.Primitives.ByteVectors
{
    /// <summary>
    /// 8 bytes long vector which can be represented as two 32-bit integers, one 64-bit integer or eight bytes
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public struct ByteVec8
    {
        /// <summary>
        /// Same data but as indexed structure of two 32-bt words
        /// </summary>
        [FieldOffset(0)]
        public WordVec2 wv2;

        /// <summary>
        /// 64-bit integer value
        /// </summary>
        [FieldOffset(0)]
        public ulong value;

        /// <summary>
        /// First half as 32-bit integer
        /// </summary>
        [FieldOffset(0)]
        public ByteVec4 bv4_00;

        /// <summary>
        /// Second half as 32-bit integer
        /// </summary>
        [FieldOffset(4)]
        public ByteVec4 bv4_01;

        public ByteVec8()
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="word">Value to construct from</param>
        public ByteVec8(ulong doubleWord)
        {
            value = doubleWord;
        }

        /// <summary>
        /// Implicit cast operator
        /// </summary>
        /// <param name="doubleWord">Value to convert from</param>
        public static implicit operator ByteVec8(ulong doubleWord)
        {
            return new ByteVec8(doubleWord);
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
                    Unsafe.InitBlockUnaligned(ptr, 0, 8);
                }
            }
        }

        /// <summary>
        /// Load value from byte array at given offset
        /// </summary>
        /// <param name="bytes">Byte array</param>
        /// <param name="offset">Offset to read from</param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public void LoadByteArray(byte[] bytes, int offset = 0)
        {
            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(offset), offset, "Offset must be a non-negative value");
            }

            if (offset + 8 > bytes.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(offset), offset, "Offset and the end of array must not be closer than 8 bytes");
            }

            unsafe
            {
                fixed (byte* target = &b00)
                {
                    Marshal.Copy(bytes, offset, new IntPtr(target), 8);
                }
            }
        }

        /// <summary>
        /// Write vector contents to byte array
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="offset"></param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public readonly void StoreByteArray(ref byte[] bytes, int offset = 0)
        {
            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(offset), offset, "Offset must be a non-negative value");
            }

            if (offset + 8 > bytes.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(offset), offset, "Offset and the end of array must not be closer than 8 bytes");
            }

            unsafe
            {
                fixed (byte* source = &b00)
                {
                    Marshal.Copy(new IntPtr(source), bytes, offset, 8);
                }
            }
        }

        /// <summary>
        /// Index access to individual byte fields
        /// </summary>
        /// <param name="key">Byte field index [0 .. 7]</param>
        /// <returns>Byte value</returns>
        public byte this[int key]
        {
            readonly get => GetByte(key);
            set => SetByte(key, value);
        }

        private readonly byte GetByte(int index)
        {
            if (index < 0 || index > 7)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 7] range");
            }

            unsafe
            {
                fixed (byte* src = &b00)
                {
                    return src[index];
                }
            }
        }

        private byte SetByte(int index, byte value)
        {
            if (index < 0 || index > 7)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 7] range");
            }

            unsafe
            {
                fixed (byte* target = &b00)
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
            ByteVec8 bv = new();
            for (byte i = 0; i < 8; i++)
            {
                bv[i] = i;
            }

            for (byte i = 0; i < 8; i++)
            {
                if (i != bv[i]) throw new InvalidDataException("ByteVec8 fail");
            }
        }

        #region Individual byte fields
        [FieldOffset(0)]
        public byte b00 = 0;

        [FieldOffset(1)]
        public byte b01 = 0;

        [FieldOffset(2)]
        public byte b02 = 0;

        [FieldOffset(3)]
        public byte b03 = 0;

        [FieldOffset(4)]
        public byte b04 = 0;

        [FieldOffset(5)]
        public byte b05 = 0;

        [FieldOffset(6)]
        public byte b06 = 0;

        [FieldOffset(7)]
        public byte b07 = 0;
        #endregion

    }
}
