

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Wheel.Crypto.Primitives.ByteVectors
{
    /// <summary>
    /// 4 bytes long vector which can be represented as either one 32-bit integer or four bytes
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public struct ByteVec4
    {
        /// <summary>
        /// 32-bit integer value
        /// </summary>
        [FieldOffset(0)]
        public uint value;

        public ByteVec4()
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="word">Value to construct from</param>
        public ByteVec4(uint word)
        {
            value = word;
        }

        /// <summary>
        /// Implicit cast operator
        /// </summary>
        /// <param name="word">Value to convert from</param>
        public static implicit operator ByteVec4(uint word)
        {
            return new ByteVec4(word);
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
                    Unsafe.InitBlockUnaligned(ptr, 0, 4);
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

            if (offset + 4 > bytes.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(offset), offset, "Offset and the end of array must not be closer than 4 bytes");
            }

            unsafe
            {
                fixed (byte* target = &b00)
                {
                    Marshal.Copy(bytes, offset, new IntPtr(target), 4);
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

            if (offset + 4 > bytes.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(offset), offset, "Offset and the end of array must not be closer than 4 bytes");
            }

            unsafe
            {
                fixed (byte* source = &b00)
                {
                    Marshal.Copy(new IntPtr(source), bytes, offset, 4);
                }
            }
        }

        /// <summary>
        /// Index access to individual byte fields
        /// </summary>
        /// <param name="key">Byte field index [0 .. 3]</param>
        /// <returns>Byte value</returns>
        public byte this[int key]
        {
            readonly get => GetByte(key);
            set => SetByte(key, value);
        }

        private readonly byte GetByte(int index)
        {
            if (index < 0 || index > 3)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 3] range");
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
            if (index < 0 || index > 3)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 3] range");
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
            ByteVec4 bv = new();
            for (byte i = 0; i < 4; i++)
            {
                bv[i] = i;
            }

            for (byte i = 0; i < 4; i++)
            {
                if (i != bv[i]) throw new InvalidDataException("ByteVec4 fail");
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
        #endregion
    }
}
