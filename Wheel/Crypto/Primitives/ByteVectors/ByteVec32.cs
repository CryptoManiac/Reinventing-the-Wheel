using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Crypto.Primitives.WordVectors;

namespace Wheel.Crypto.Primitives.ByteVectors
{
    /// <summary>
    /// 32 bytes long vector which can be represented as either eight 32-bit integers or four 64-bit integers
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public struct ByteVec32
    {
        /// <summary>
        /// Same value but as indexed structure of eight 32-bit words
        /// </summary>
        [FieldOffset(0)]
        public WordVec8 wv8;

        /// <summary>
        /// Same value but as indexed structure of four 64-bit words
        /// </summary>
        [FieldOffset(0)]
        public DWordVec4 dwv4;

        /// <summary>
        /// First half as 16-byte vector
        /// </summary>
        [FieldOffset(0)]
        public ByteVec16 bv16_00;

        /// <summary>
        /// Second half as 16-byte vector
        /// </summary>
        [FieldOffset(16)]
        public ByteVec16 bv16_01;

        /// <summary>
        /// Same value but as a structure of four 64-bit byte vectors
        /// </summary>
        [FieldOffset(0)]
        public ByteVec32_DoubleWords doubleWords;

        /// <summary>
        /// Same value but as a structure of eight 32-bit byte vectors
        /// </summary>
        [FieldOffset(0)]
        public ByteVec32_Words words;

        public ByteVec32()
        {
        }

        /// <summary>
        /// Set to zero
        /// </summary>
        public unsafe void Reset()
        {
            fixed (void* ptr = &this)
            {
                Unsafe.InitBlockUnaligned(ptr, 0, 32);
            }
        }

        /// <summary>
        /// Load value from byte array at given offset
        /// </summary>
        /// <param name="bytes">Byte array</param>
        /// <param name="offset">Offset to read from</param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public unsafe void LoadByteArray(byte[] bytes, uint offset = 0)
        {
            if (offset + 32 > bytes.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(offset), offset, "Offset and the end of array must not be closer than 32 bytes");
            }

            fixed (byte* target = &b00)
            {
                Marshal.Copy(bytes, (int)offset, new IntPtr(target), 32);
            }
        }

        /// <summary>
        /// Write vector contents to byte array
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="offset"></param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public unsafe readonly void StoreByteArray(ref byte[] bytes, uint offset = 0)
        {
            if (offset + 32 > bytes.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(offset), offset, "Offset and the end of array must not be closer than 32 bytes");
            }

            fixed (byte* source = &b00)
            {
                Marshal.Copy(new IntPtr(source), bytes, (int)offset, 32);
            }
        }

        /// <summary>
        /// Return data as a new byte array
        /// </summary>
        public readonly byte[] GetBytes()
        {
            byte[] bytes = new byte[32];
            StoreByteArray(ref bytes);
            return bytes;
        }

        /// <summary>
        /// Index access to individual byte fields
        /// </summary>
        /// <param name="key">Byte field index [0 .. 31]</param>
        /// <returns>Byte value</returns>
        public byte this[uint key]
        {
            readonly get => GetByte(key);
            set => SetByte(key, value);
        }

        private unsafe readonly byte GetByte(uint index)
        {
            if (index > 31)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 31] range");
            }

            fixed (byte* src = &b00)
            {
                return src[index];
            }
        }

        private unsafe byte SetByte(uint index, byte value)
        {
            if (index > 31)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 31] range");
            }

            fixed (byte* target = &b00)
            {
                return target[index] = value;
            }
        }

        /// <summary>
        /// Test method
        /// </summary>
        public static void Test()
        {
            ByteVec32 bv = new();
            for (byte i = 0; i < 32; i++)
            {
                bv[i] = i;
            }

            for (byte i = 0; i < 32; i++)
            {
                if (i != bv[i]) throw new InvalidDataException("ByteVec32 fail");
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

        [FieldOffset(16)]
        public byte b16 = 0;
        [FieldOffset(17)]
        public byte b17 = 0;
        [FieldOffset(18)]
        public byte b18 = 0;
        [FieldOffset(19)]
        public byte b19 = 0;

        [FieldOffset(20)]
        public byte b20 = 0;
        [FieldOffset(21)]
        public byte b21 = 0;
        [FieldOffset(22)]
        public byte b22 = 0;
        [FieldOffset(23)]
        public byte b23 = 0;

        [FieldOffset(24)]
        public byte b24 = 0;
        [FieldOffset(25)]
        public byte b25 = 0;
        [FieldOffset(26)]
        public byte b26 = 0;
        [FieldOffset(27)]
        public byte b27 = 0;

        [FieldOffset(28)]
        public byte b28 = 0;
        [FieldOffset(29)]
        public byte b29 = 0;
        [FieldOffset(30)]
        public byte b30 = 0;
        [FieldOffset(31)]
        public byte b31 = 0;
        #endregion
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct ByteVec32_DoubleWords
    {
        /// <summary>
        /// First double word (64-bit)
        /// </summary>
        [FieldOffset(0)]
        public ByteVec8 dw00;

        /// <summary>
        /// Second double word
        /// </summary>
        [FieldOffset(8)]
        public ByteVec8 dw01;

        /// <summary>
        /// Third double word 
        /// </summary>
        [FieldOffset(16)]
        public ByteVec8 dw02;

        /// <summary>
        /// Fourth double word
        /// </summary>
        [FieldOffset(24)]
        public ByteVec8 dw03;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct ByteVec32_Words
    {
        /// <summary>
        /// First word (32 bit)
        /// </summary>
        [FieldOffset(0)]
        public ByteVec4 w00;

        /// <summary>
        /// Second word
        /// </summary>
        [FieldOffset(4)]
        public ByteVec4 w01;

        /// <summary>
        /// Third word
        /// </summary>
        [FieldOffset(8)]
        public ByteVec4 w02;

        /// <summary>
        /// Four word
        /// </summary>
        [FieldOffset(12)]
        public ByteVec4 w03;

        /// <summary>
        /// Fith word (32 bit)
        /// </summary>
        [FieldOffset(16)]
        public ByteVec4 w04;

        /// <summary>
        /// Sixth word
        /// </summary>
        [FieldOffset(20)]
        public ByteVec4 w05;

        /// <summary>
        /// Seventh word
        /// </summary>
        [FieldOffset(24)]
        public ByteVec4 w06;

        /// <summary>
        /// Eigtht word
        /// </summary>
        [FieldOffset(28)]
        public ByteVec4 w07;
    }
}
