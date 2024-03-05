using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Crypto.Primitives.WordVectors;

namespace Wheel.Crypto.Primitives.ByteVectors
{
    /// <summary>
    /// 16 bytes long vector which can be represented as either four 32-bit integers or two 64-bit integers
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public struct ByteVec16
    {
        /// <summary>
        /// Same data but as indexed 4 words structure
        /// </summary>
        [FieldOffset(0)]
        public WordVec4 wv4;

        /// <summary>
        /// First double word (64-bit)
        /// </summary>
        [FieldOffset(0)]
        public ByteVec8 bv8_00;

        /// <summary>
        /// Second double word
        /// </summary>
        [FieldOffset(8)]
        public ByteVec8 bv8_01;

        public ByteVec16()
        {
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
                    Unsafe.InitBlockUnaligned(ptr, 0, 16);
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

            if (offset + 16 > bytes.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(offset), offset, "Offset and the end of array must not be closer than 16 bytes");
            }

            unsafe
            {
                fixed (byte* target = &b00)
                {
                    Marshal.Copy(bytes, offset, new IntPtr(target), 16);
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

            if (offset + 16 > bytes.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(offset), offset, "Offset and the end of array must not be closer than 16 bytes");
            }

            unsafe
            {
                fixed (byte* source = &b00)
                {
                    Marshal.Copy(new IntPtr(source), bytes, offset, 16);
                }
            }
        }

        /// <summary>
        /// Index access to individual byte fields
        /// </summary>
        /// <param name="key">Byte field index [0 .. 15]</param>
        /// <returns>Byte value</returns>
        public byte this[int key]
        {
            readonly get => GetByte(key);
            set => SetByte(key, value);
        }

        private readonly byte GetByte(int index)
        {
            if (index < 0 || index > 15)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 15] range");
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
            if (index < 0 || index > 15)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 15] range");
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
            ByteVec16 bv = new();
            for (byte i = 0; i < 16; i++)
            {
                bv[i] = i;
            }

            for (byte i = 0; i < 16; i++)
            {
                if (i != bv[i]) throw new InvalidDataException("ByteVec16 fail");
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

        [FieldOffset(8)]
        public byte b08 = 0;
        [FieldOffset(9)]
        public byte b09 = 0;
        [FieldOffset(10)]
        public byte b10 = 0;
        [FieldOffset(11)]
        public byte b11 = 0;

        [FieldOffset(12)]
        public byte b12 = 0;
        [FieldOffset(13)]
        public byte b13 = 0;
        [FieldOffset(14)]
        public byte b14 = 0;
        [FieldOffset(15)]
        public byte b15 = 0;
        #endregion

    }
}
