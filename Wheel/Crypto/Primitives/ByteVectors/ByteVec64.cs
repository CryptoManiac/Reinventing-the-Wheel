using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Crypto.Primitives.WordVectors;

namespace Wheel.Crypto.Primitives.ByteVectors
{
    /// <summary>
    /// 64 bytes long vector which can be represented as either sixteen 32-bit integers or eight 64-bit integers
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public struct ByteVec64
    {
        /// <summary>
        /// Same data but as indexed 16 words structure
        /// </summary>
        [FieldOffset(0)]
        public WordVec16 wv16;

        /// <summary>
        /// Same data but as indexed 8 double words structure
        /// </summary>
        [FieldOffset(0)]
        public DWordVec8 dwv8;

        /// <summary>
        /// Same data as as a structure of eight 64-bit byte vectors
        /// </summary>
        [FieldOffset(0)]
        public ByteVec64_DoubleWords doubleWords;

        /// <summary>
        /// Same data as as a structure of sixteen 32-bit byte vectors
        /// </summary>
        [FieldOffset(0)]
        public ByteVec64_Words words;

        public ByteVec64()
        {
        }

        /// <summary>
        /// Set to zero
        /// </summary>
        public unsafe void Reset()
        {
            fixed (void* ptr = &this)
            {
                Unsafe.InitBlockUnaligned(ptr, 0, 64);
            }
        }

        /// <summary>
        /// Reset some sequence of bytes to zero
        /// </summary>
        /// <param name="begin">Where to begin</param>
        /// <param name="sz">How many bytes to erase</param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public unsafe void Wipe(uint begin, uint sz)
        {
            // Begin index must have a sane value
            if (begin > 63)
            {
                throw new ArgumentOutOfRangeException(nameof(begin), begin, "begin index must be within [0 .. 63] range");
            }

            // Maximum size is a distance between the
            //  beginning and the vector size
            uint maxSz = 64 - begin;

            if (sz > maxSz)
            {
                throw new ArgumentOutOfRangeException(nameof(sz), sz, "sz must be within [0 .. " + maxSz + "] range");
            }

            fixed (byte* ptr = &b00)
            {
                Unsafe.InitBlockUnaligned(ptr + begin, 0, sz);
            }
        }

        /// <summary>
        /// Overwrite the part of value with a sequence of bytes
        /// </summary>
        /// <param name="bytes">Bytes to write</param>
        /// <param name="targetIndex">Offset to write them from the beginning of this vector</param>
        public unsafe void Write(Span<byte> bytes, uint targetIndex)
        {
            // Target index must have a sane value
            if (targetIndex > 127)
            {
                throw new ArgumentOutOfRangeException(nameof(targetIndex), targetIndex, "targetIndex index must be within [0 .. 128) range");
            }

            // Maximum size is a distance between the
            //  beginning and the vector size
            uint limit = 128 - targetIndex;

            if (bytes.Length > limit)
            {
                throw new ArgumentOutOfRangeException(nameof(bytes), bytes.Length, "byte sequence is too long");
            }

            fixed (byte* ptr = &b00)
            {
                Span<byte> target = new(ptr + targetIndex, bytes.Length);
                bytes.CopyTo(target);
            }
        }
        
        /// <summary>
        /// Load value from byte array at given offset
        /// </summary>
        /// <param name="bytes">Byte array</param>
        /// <param name="offset">Offset to read from</param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public unsafe void LoadByteArray(byte[] bytes, int offset = 0)
        {
            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(offset), offset, "Offset must be a non-negative value");
            }

            if (offset + 64 > bytes.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(offset), offset, "Offset and the end of array must not be closer than 64 bytes");
            }

            fixed (byte* target = &b00)
            {
                Marshal.Copy(bytes, offset, new IntPtr(target), 64);
            }
        }

        /// <summary>
        /// Write vector contents to byte array
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="offset"></param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public unsafe readonly void StoreByteArray(ref byte[] bytes, int offset = 0)
        {
            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(offset), offset, "Offset must be a non-negative value");
            }

            if (offset + 64 > bytes.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(offset), offset, "Offset and the end of array must not be closer than 64 bytes");
            }

            fixed (byte* source = &b00)
            {
                Marshal.Copy(new IntPtr(source), bytes, offset, 64);
            }
        }

        /// <summary>
        /// Return data as a new byte array
        /// </summary>
        public readonly byte[] GetBytes()
        {
            byte[] bytes = new byte[64];
            StoreByteArray(ref bytes);
            return bytes;
        }

        /// <summary>
        /// Index access to individual byte fields
        /// </summary>
        /// <param name="key">Byte field index [0 .. 63]</param>
        /// <returns>Byte value</returns>
        public byte this[int key]
        {
            readonly get => GetByte(key);
            set => SetByte(key, value);
        }

        private unsafe readonly byte GetByte(int index)
        {
            if (index < 0 || index > 63)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 63] range");
            }

            fixed (byte* src = &b00)
            {
                return src[index];
            }
        }

        private unsafe byte SetByte(int index, byte value)
        {
            if (index < 0 || index > 63)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 63] range");
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
            ByteVec64 bv = new();
            for (byte i = 0; i < 64; i++)
            {
                bv[i] = i;
            }

            for (byte i = 0; i < 64; i++)
            {
                if (i != bv[i]) throw new InvalidDataException("ByteVec64 fail");
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

        [FieldOffset(32)]
        public byte b32 = 0;
        [FieldOffset(33)]
        public byte b33 = 0;
        [FieldOffset(34)]
        public byte b34 = 0;
        [FieldOffset(35)]
        public byte b35 = 0;

        [FieldOffset(36)]
        public byte b36 = 0;
        [FieldOffset(37)]
        public byte b37 = 0;
        [FieldOffset(38)]
        public byte b38 = 0;
        [FieldOffset(39)]
        public byte b39 = 0;

        [FieldOffset(40)]
        public byte b40 = 0;
        [FieldOffset(41)]
        public byte b41 = 0;
        [FieldOffset(42)]
        public byte b42 = 0;
        [FieldOffset(43)]
        public byte b43 = 0;

        [FieldOffset(44)]
        public byte b44 = 0;
        [FieldOffset(45)]
        public byte b45 = 0;
        [FieldOffset(46)]
        public byte b46 = 0;
        [FieldOffset(47)]
        public byte b47 = 0;

        [FieldOffset(48)]
        public byte b48 = 0;
        [FieldOffset(49)]
        public byte b49 = 0;
        [FieldOffset(50)]
        public byte b50 = 0;
        [FieldOffset(51)]
        public byte b51 = 0;

        [FieldOffset(52)]
        public byte b52 = 0;
        [FieldOffset(53)]
        public byte b53 = 0;
        [FieldOffset(54)]
        public byte b54 = 0;
        [FieldOffset(55)]
        public byte b55 = 0;

        [FieldOffset(56)]
        public byte b56 = 0;
        [FieldOffset(57)]
        public byte b57 = 0;
        [FieldOffset(58)]
        public byte b58 = 0;
        [FieldOffset(59)]
        public byte b59 = 0;

        [FieldOffset(60)]
        public byte b60 = 0;
        [FieldOffset(61)]
        public byte b61 = 0;
        [FieldOffset(62)]
        public byte b62 = 0;
        [FieldOffset(63)]
        public byte b63 = 0;
        #endregion
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct ByteVec64_DoubleWords
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

        /// <summary>
        /// Fifth double word
        /// </summary>
        [FieldOffset(32)]
        public ByteVec8 dw04;

        /// <summary>
        /// Sixth double word
        /// </summary>
        [FieldOffset(40)]
        public ByteVec8 dw05;

        /// <summary>
        /// Seventh double word
        /// </summary>
        [FieldOffset(48)]
        public ByteVec8 dw06;

        /// <summary>
        /// Eighth double word
        /// </summary>
        [FieldOffset(56)]
        public ByteVec8 dw07;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct ByteVec64_Words
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

        /// <summary>
        /// Ninth word
        /// </summary>
        [FieldOffset(32)]
        public ByteVec4 w08;

        /// <summary>
        /// Tenth word
        /// </summary>
        [FieldOffset(36)]
        public ByteVec4 w09;

        /// <summary>
        /// Eleventh word
        /// </summary>
        [FieldOffset(40)]
        public ByteVec4 w10;

        /// <summary>
        /// Twelfth word
        /// </summary>
        [FieldOffset(44)]
        public ByteVec4 w11;

        /// <summary>
        /// Thirteenth word
        /// </summary>
        [FieldOffset(48)]
        public ByteVec4 w12;

        /// <summary>
        /// Fourteenth word
        /// </summary>
        [FieldOffset(52)]
        public ByteVec4 w13;

        /// <summary>
        /// Fifteenth word
        /// </summary>
        [FieldOffset(56)]
        public ByteVec4 w14;

        /// <summary>
        /// Sixteenth word
        /// </summary>
        [FieldOffset(60)]
        public ByteVec4 w15;
    }
}
