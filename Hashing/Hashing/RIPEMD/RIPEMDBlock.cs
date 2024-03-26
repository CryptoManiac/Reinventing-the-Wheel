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
        public unsafe void Write(ReadOnlySpan<byte> bytes, uint targetIndex)
        {
            // Target index must have a sane value
            if (targetIndex >= TypeByteSz)
            {
                throw new ArgumentOutOfRangeException(nameof(targetIndex), targetIndex, "targetIndex index must be within [0 .. " + TypeByteSz + ") range");
            }

            // Maximum size is a distance between the
            //  beginning and the vector size
            uint limit = TypeByteSz - targetIndex;

            if (bytes.Length > limit)
            {
                throw new ArgumentOutOfRangeException(nameof(bytes), bytes.Length, "byte sequence is too long");
            }

            fixed (void* ptr = &this)
            {
                Span<byte> target = new((byte*)ptr + targetIndex, bytes.Length);
                bytes.CopyTo(target);
            }
        }

        /// <summary>
        /// Set to zero
        /// </summary>
        public unsafe void Reset()
        {
            fixed(byte* ptr = &bytes[0])
            {
                new Span<byte>(ptr, TypeByteSz).Clear();
            }
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
        /// Fixed size buffer for registers
        /// </summary>
        [FieldOffset(0)]
        internal unsafe fixed uint registers[TypeUintSz];

        /// <summary>
        /// Fixed size buffer for the individual block bytes
        /// </summary>
        [FieldOffset(0)]
        internal unsafe fixed byte bytes[TypeByteSz];

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

