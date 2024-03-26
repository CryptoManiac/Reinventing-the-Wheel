using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Miscellaneous.Support;

namespace Wheel.Hashing.SHA.SHA512.Internal
{
    /// <summary>
    /// Represents the block data for the 512-bit family of SHA functions
    /// </summary>
	[StructLayout(LayoutKind.Explicit)]
    internal unsafe struct InternalSHA512Block
	{
        /// <summary>
        /// Reset some sequence of bytes to zero
        /// </summary>
        /// <param name="begin">Where to begin</param>
        /// <param name="sz">How many bytes to erase</param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public unsafe void Wipe(uint begin, uint sz)
        {
            // Begin index must have a sane value
            if (begin >= TypeByteSz)
            {
                throw new ArgumentOutOfRangeException(nameof(begin), begin, "begin index must be within [0 .. " + TypeByteSz + ") range");
            }

            // Maximum size is a distance between the
            //  beginning and the vector size
            uint maxSz = TypeByteSz - begin;

            if (sz > maxSz)
            {
                throw new ArgumentOutOfRangeException(nameof(sz), sz, "sz must be within [0 .. " + maxSz + "] range");
            }

            fixed (void* ptr = &this)
            {
                new Span<byte>((byte*)ptr + begin, (int)sz).Clear();
            }
        }

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
            fixed (void* ptr = &this)
            {
                new Span<byte>(ptr, TypeByteSz).Clear();
            }
        }

        /// <summary>
        /// Size of structure in memory when treated as a collection of bytes
        /// </summary>
        public const int TypeByteSz = 128;

        /// <summary>
        /// Size of structure in memory when treated as a collection of ulong values
        /// </summary>
        public const int TypeUlongSz = TypeByteSz / sizeof(ulong);

        /// <summary>
        /// Fixed size buffer for registers
        /// </summary>
        [FieldOffset(0)]
        internal fixed ulong registers[TypeUlongSz];

        /// <summary>
        /// Buffer for the individuab block bytes
        /// </summary>
        [FieldOffset(0)]
        internal fixed byte bytes[TypeByteSz];

        /// <summary>
        /// Special case: Public access to the last QWord for length addition
        /// </summary>
        [FieldOffset(112)]
        public UInt128 lastQWord;
    }
}
