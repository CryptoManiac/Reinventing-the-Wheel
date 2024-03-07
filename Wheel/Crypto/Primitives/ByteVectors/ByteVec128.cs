using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Crypto.Primitives.QWordVectors;
using Wheel.Crypto.Primitives.WordVectors;

namespace Wheel.Crypto.Primitives.ByteVectors
{
    /// <summary>
    /// 64 bytes long vector which can be represented as either thirty 32-bit integers or sixteen 64-bit integers
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public struct ByteVec128
    {
        /// <summary>
        /// Same data but as indexed 16 double words structure
        /// </summary>
        [FieldOffset(0)]
        public DWordVec16 dwv16;

        /// <summary>
        /// Same data but as indexed 8 double words structure
        /// </summary>
        [FieldOffset(0)]
        public QWordVec8 qwv8;

        /// <summary>
        /// Same data as sixteen byte vectors
        /// </summary>
        [FieldOffset(0)]
        public ByteVec128_DoubleWords doubleWords;

        /// <summary>
        /// Same data as 32 byte vectors
        /// </summary>
        [FieldOffset(0)]
        public ByteVec128_Words words;

        /// Same data as 32 byte vectors
        /// </summary>
        [FieldOffset(0)]
        public ByteVec128_QuadWords qwords;

        public ByteVec128()
        {
        }

        /// <summary>
        /// Set to zero
        /// </summary>
        public unsafe void Reset()
        {
            fixed (void* ptr = &this)
            {
                Unsafe.InitBlockUnaligned(ptr, 0, 128);
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
            if (begin > 127)
            {
                throw new ArgumentOutOfRangeException(nameof(begin), begin, "begin index must be within [0 .. 63] range");
            }

            // Maximum size is a distance between the
            //  beginning and the vector size
            uint maxSz = 128 - begin;

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
                var target = new Span<byte>(ptr + targetIndex, bytes.Length);
                bytes.CopyTo(target);
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
            if (offset + 128 > bytes.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(offset), offset, "Offset and the end of array must not be closer than 128 bytes");
            }

            fixed (byte* target = &b00)
            {
                Marshal.Copy(bytes, (int)offset, new IntPtr(target), 128);
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
            if (offset + 128 > bytes.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(offset), offset, "Offset and the end of array must not be closer than 128 bytes");
            }

            fixed (byte* source = &b00)
            {
                Marshal.Copy(new IntPtr(source), bytes, (int)offset, 128);
            }
        }

        /// <summary>
        /// Return data as a new byte array
        /// </summary>
        public readonly byte[] GetBytes()
        {
            byte[] bytes = new byte[128];
            StoreByteArray(ref bytes);
            return bytes;
        }

        /// <summary>
        /// Index access to individual byte fields
        /// </summary>
        /// <param name="key">Byte field index [0 .. 63]</param>
        /// <returns>Byte value</returns>
        public byte this[uint key]
        {
            readonly get => GetByte(key);
            set => SetByte(key, value);
        }

        private unsafe readonly byte GetByte(uint index)
        {
            if (index > 127)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 127] range");
            }

            fixed (byte* src = &b00)
            {
                return src[index];
            }
        }

        private unsafe byte SetByte(uint index, byte value)
        {
            if (index > 127)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. 127] range");
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
            ByteVec128 bv = new();
            for (byte i = 0; i < 128; i++)
            {
                bv[i] = i;
            }

            for (byte i = 0; i < 128; i++)
            {
                if (i != bv[i]) throw new InvalidDataException("ByteVec128 fail");
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


        [FieldOffset(64)]
        public byte b64 = 0;
        [FieldOffset(65)]
        public byte b65 = 0;
        [FieldOffset(66)]
        public byte b66 = 0;
        [FieldOffset(67)]
        public byte b67 = 0;

        [FieldOffset(68)]
        public byte b68 = 0;
        [FieldOffset(69)]
        public byte b69 = 0;
        [FieldOffset(70)]
        public byte b70 = 0;
        [FieldOffset(71)]
        public byte b71 = 0;

        [FieldOffset(72)]
        public byte b72 = 0;
        [FieldOffset(73)]
        public byte b73 = 0;
        [FieldOffset(74)]
        public byte b74 = 0;
        [FieldOffset(75)]
        public byte b75 = 0;

        [FieldOffset(76)]
        public byte b76 = 0;
        [FieldOffset(77)]
        public byte b77 = 0;
        [FieldOffset(78)]
        public byte b78 = 0;
        [FieldOffset(79)]
        public byte b79 = 0;

        [FieldOffset(80)]
        public byte b80 = 0;
        [FieldOffset(81)]
        public byte b81 = 0;
        [FieldOffset(82)]
        public byte b82 = 0;
        [FieldOffset(83)]
        public byte b83 = 0;

        [FieldOffset(84)]
        public byte b84 = 0;
        [FieldOffset(85)]
        public byte b85 = 0;
        [FieldOffset(86)]
        public byte b86 = 0;
        [FieldOffset(87)]
        public byte b87 = 0;

        [FieldOffset(88)]
        public byte b88 = 0;
        [FieldOffset(89)]
        public byte b89 = 0;
        [FieldOffset(90)]
        public byte b90 = 0;
        [FieldOffset(91)]
        public byte b91 = 0;

        [FieldOffset(92)]
        public byte b92 = 0;
        [FieldOffset(93)]
        public byte b93 = 0;
        [FieldOffset(94)]
        public byte b94 = 0;
        [FieldOffset(95)]
        public byte b95 = 0;

        [FieldOffset(96)]
        public byte b96 = 0;
        [FieldOffset(97)]
        public byte b97 = 0;
        [FieldOffset(98)]
        public byte b98 = 0;
        [FieldOffset(99)]
        public byte b99 = 0;

        [FieldOffset(100)]
        public byte b100 = 0;
        [FieldOffset(101)]
        public byte b101 = 0;
        [FieldOffset(102)]
        public byte b102 = 0;
        [FieldOffset(103)]
        public byte b103 = 0;

        [FieldOffset(104)]
        public byte b104 = 0;
        [FieldOffset(105)]
        public byte b105 = 0;
        [FieldOffset(106)]
        public byte b106 = 0;
        [FieldOffset(107)]
        public byte b107 = 0;

        [FieldOffset(108)]
        public byte b108 = 0;
        [FieldOffset(109)]
        public byte b109 = 0;
        [FieldOffset(110)]
        public byte b110 = 0;
        [FieldOffset(111)]
        public byte b111 = 0;

        [FieldOffset(112)]
        public byte b112 = 0;
        [FieldOffset(113)]
        public byte b113 = 0;
        [FieldOffset(114)]
        public byte b114 = 0;
        [FieldOffset(115)]
        public byte b115 = 0;

        [FieldOffset(116)]
        public byte b116 = 0;
        [FieldOffset(117)]
        public byte b117 = 0;
        [FieldOffset(118)]
        public byte b118 = 0;
        [FieldOffset(119)]
        public byte b119 = 0;

        [FieldOffset(120)]
        public byte b120 = 0;
        [FieldOffset(121)]
        public byte b121 = 0;
        [FieldOffset(122)]
        public byte b122 = 0;
        [FieldOffset(123)]
        public byte b123 = 0;

        [FieldOffset(124)]
        public byte b124 = 0;
        [FieldOffset(125)]
        public byte b125 = 0;
        [FieldOffset(126)]
        public byte b126 = 0;
        [FieldOffset(127)]
        public byte b127 = 0;
        #endregion
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct ByteVec128_QuadWords
    {
        /// <summary>
        /// First half as 16-byte vector
        /// </summary>
        [FieldOffset(0)]
        public ByteVec16 qw_00;

        /// <summary>
        /// Second half as 16-byte vector
        /// </summary>
        [FieldOffset(16)]
        public ByteVec16 qw_01;

        /// <summary>
        /// Third 16-byte vector
        /// </summary>
        [FieldOffset(32)]
        public ByteVec16 qw_02;

        /// <summary>
        /// Fourth 16-byte vector
        /// </summary>
        [FieldOffset(48)]
        public ByteVec16 qw_03;

        /// <summary>
        /// Fith 16-byte vector
        /// </summary>
        [FieldOffset(64)]
        public ByteVec16 qw_04;

        /// <summary>
        /// Sixth 16-byte vector
        /// </summary>
        [FieldOffset(80)]
        public ByteVec16 qw_05;

        /// <summary>
        /// Seventh 16-byte vector
        /// </summary>
        [FieldOffset(96)]
        public ByteVec16 qw_06;

        /// <summary>
        /// Eigth 16-byte vector
        /// </summary>
        [FieldOffset(112)]
        public ByteVec16 qw_07;
    }

    /// <summary>
    /// A structure of sixteen 64-bit words as byte vectors
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public struct ByteVec128_DoubleWords
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

        /// <summary>
        /// Ninth double word
        /// </summary>
        [FieldOffset(64)]
        public ByteVec8 dw08;

        /// <summary>
        /// Tenth double word
        /// </summary>
        [FieldOffset(72)]
        public ByteVec8 dw09;

        /// <summary>
        /// Eleventh double word
        /// </summary>
        [FieldOffset(80)]
        public ByteVec8 dw10;

        /// <summary>
        /// Twelfth double word
        /// </summary>
        [FieldOffset(88)]
        public ByteVec8 dw11;

        /// <summary>
        /// Thirteenth double word
        /// </summary>
        [FieldOffset(96)]
        public ByteVec8 dw12;

        /// <summary>
        /// Fourteenth double word
        /// </summary>
        [FieldOffset(104)]
        public ByteVec8 dw13;

        /// <summary>
        /// Fifteenth double word
        /// </summary>
        [FieldOffset(112)]
        public ByteVec8 dw14;

        /// <summary>
        /// Sixteenth double word
        /// </summary>
        [FieldOffset(120)]
        public ByteVec8 dw15;
    }

    /// <summary>
    /// A structure of thirty-two 32-bit words as byte vectors
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public struct ByteVec128_Words
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

        /// <summary>
        /// Seventeenth word
        /// </summary>
        [FieldOffset(64)]
        public ByteVec4 w16;

        /// <summary>
        /// Eighteenth word
        /// </summary>
        [FieldOffset(68)]
        public ByteVec4 w17;

        /// <summary>
        /// Nineteenth word
        /// </summary>
        [FieldOffset(72)]
        public ByteVec4 w18;

        /// <summary>
        /// Twentieth word
        /// </summary>
        [FieldOffset(76)]
        public ByteVec4 w19;

        /// <summary>
        /// Twenty-first word
        /// </summary>
        [FieldOffset(80)]
        public ByteVec4 w20;

        /// <summary>
        /// Twenty-second word
        /// </summary>
        [FieldOffset(84)]
        public ByteVec4 w21;

        /// <summary>
        /// Twenty-third word
        /// </summary>
        [FieldOffset(88)]
        public ByteVec4 w22;

        /// <summary>
        /// Twenty-fourth word
        /// </summary>
        [FieldOffset(92)]
        public ByteVec4 w23;

        /// <summary>
        /// Twenty-fifth word
        /// </summary>
        [FieldOffset(96)]
        public ByteVec4 w24;

        /// <summary>
        /// Twenty-sixth word
        /// </summary>
        [FieldOffset(100)]
        public ByteVec4 w25;

        /// <summary>
        /// Twenty-seventh word
        /// </summary>
        [FieldOffset(104)]
        public ByteVec4 w26;

        /// <summary>
        /// Twenty-eighth word
        /// </summary>
        [FieldOffset(108)]
        public ByteVec4 w27;

        /// <summary>
        /// Twenty-ninth word
        /// </summary>
        [FieldOffset(112)]
        public ByteVec4 w28;

        /// <summary>
        /// Thirtieth word
        /// </summary>
        [FieldOffset(116)]
        public ByteVec4 w29;

        /// <summary>
        /// Thirty-first word
        /// </summary>
        [FieldOffset(120)]
        public ByteVec4 w30;

        /// <summary>
        /// Thirty-second word
        /// </summary>
        [FieldOffset(124)]
        public ByteVec4 w31;
    }
}
