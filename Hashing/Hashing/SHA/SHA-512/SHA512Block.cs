using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Miscellaneous.Support;

namespace Wheel.Hashing.SHA.SHA512.Internal
{
    /// <summary>
    /// Represents the block data for the 512-bit family of SHA functions
    /// </summary>
	[StructLayout(LayoutKind.Explicit)]
    internal struct InternalSHA512Block
	{
        /// <summary>
        /// Reset some sequence of bytes to zero
        /// </summary>
        /// <param name="begin">Where to begin</param>
        /// <param name="sz">How many bytes to erase</param>
        public void Wipe(uint begin, uint sz)
        {
            bytes.Slice((int)begin, (int)sz).Clear();
        }

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
        public void Reset()
        {
            bytes.Clear();
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
        /// Buffer for the individuab block bytes
        /// </summary>
        [FieldOffset(0)]
        private unsafe fixed byte data[TypeByteSz];

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

        /// <summary>
        /// Special case: Public access to the last 64-bit integer for the finalization function
        /// </summary>
        [FieldOffset(120)]
        public ulong lastLong;

        /// <summary>
        /// Special case: Public access to the last QWord for length addition
        /// </summary>
        [FieldOffset(112)]
        public UInt128 lastQWord;
    }
}
