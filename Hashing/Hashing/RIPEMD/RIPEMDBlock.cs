using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Wheel.Hashing.RIPEMD.Internal
{
    /// <summary>
    /// Represents the block data for the RIPEMD-160
    /// Note: Mostly identical to that of SHA-256
    /// </summary>
	[StructLayout(LayoutKind.Explicit)]
    internal struct InternalRIPEMDBlock
    {
        /// <summary>
        /// Overwrite the part of value with a sequence of bytes
        /// </summary>
        /// <param name="bytes">Bytes to write</param>
        /// <param name="targetIndex">Offset to write them from the beginning of this vector</param>
        public void Write(ReadOnlySpan<byte> input, uint targetIndex)
        {
            input.CopyTo(bytes.Slice((int)targetIndex, input.Length));
        }

        /// <summary>
        /// Set to zero
        /// </summary>
        public unsafe void Reset()
        {
            registers.Clear();
        }

        /// <summary>
        /// Size of structure in memory when treated as a collection of bytes
        /// </summary>
        public const int TypeByteSz = 64;

        /// <summary>
        /// Size of structure in memory when treated as a collection of uint values
        /// </summary>
        public const int TypeUintSz = TypeByteSz / sizeof(uint);

        /// <summary>
        /// Fixed size buffer for words
        /// </summary>
        [FieldOffset(0)]
        private unsafe fixed uint words[TypeUintSz];

        /// <summary>
        /// Fixed size buffer for the individual block bytes
        /// </summary>
        [FieldOffset(0)]
        private unsafe fixed byte data[TypeByteSz];

        /// <summary>
        /// Safe access to words
        /// </summary>
        public readonly unsafe Span<uint> registers
        {
            get
            {
                fixed (uint* ptr = &words[0])
                {
                    return new Span<uint>(ptr, TypeUintSz);
                }
            }
        }

        /// <summary>
        /// Safe access to bytes
        /// </summary>
        public readonly unsafe Span<byte> bytes
        {
            get
            {
                fixed (byte* ptr = &data[0])
                {
                    return new Span<byte>(ptr, TypeByteSz);
                }
            }
        }

        #region Individual word public access
        [FieldOffset(0)]
        public uint X00;
        [FieldOffset(4)]
        public uint X01;
        [FieldOffset(8)]
        public uint X02;
        [FieldOffset(12)]
        public uint X03;

        [FieldOffset(16)]
        public uint X04;
        [FieldOffset(20)]
        public uint X05;
        [FieldOffset(24)]
        public uint X06;
        [FieldOffset(28)]
        public uint X07;

        [FieldOffset(32)]
        public uint X08;
        [FieldOffset(36)]
        public uint X09;
        [FieldOffset(40)]
        public uint X10;
        [FieldOffset(44)]
        public uint X11;

        [FieldOffset(48)]
        public uint X12;
        [FieldOffset(52)]
        public uint X13;
        [FieldOffset(56)]
        public uint X14;
        [FieldOffset(60)]
        public uint X15;
        #endregion
    }
}

