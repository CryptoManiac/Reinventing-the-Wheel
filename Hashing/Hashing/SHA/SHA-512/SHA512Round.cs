using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Miscellaneous.Support;

namespace Wheel.Hashing.SHA.SHA512.Internal
{
    /// <summary>
    /// Represents the round context data for the 512-bit family of SHA functions
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    internal struct InternalSHA512Round
    {
        /// <summary>
        /// Instantiate from array or a variable number of arguments
        /// </summary>
        /// <param name="ulongs"></param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public unsafe InternalSHA512Round(params ulong[] ulongs)
        {
            if (ulongs.Length != TypeUlongSz)
            {
                throw new ArgumentOutOfRangeException(nameof(ulongs), ulongs.Length, "Must provide " + TypeUlongSz + " arguments exactly");
            }

            fixed (void* source = &ulongs[0])
            {
                fixed (void* target = &this)
                {
                    new Span<byte>(source, TypeByteSz).CopyTo(new Span<byte>(target, TypeByteSz));
                }
            }
        }

        /// <summary>
        /// Initialize first 16 registers from the provided block and revert them
        /// </summary>
        /// <param name="block">A context to provide 16 registers</param>
        public InternalSHA512Round(in InternalSHA512Block block)
        {
            SetBlock(block);
            RevertBlock();
        }

        /// <summary>
        /// Set first 16 registers from the provided container
        /// </summary>
        /// <param name="block">A context to provide 16 registers</param>
        private unsafe void SetBlock(in InternalSHA512Block block)
        {
            fixed (void* source = &block)
            {
                fixed (void* target = &this)
                {
                    new Span<byte>(source, InternalSHA512Block.TypeByteSz).CopyTo(new Span<byte>(target, TypeByteSz));
                }
            }
        }

        /// <summary>
        /// Revert the byte order for the first 16 state registers
        /// </summary>
        private unsafe void RevertBlock()
        {
            for (int i = 0; i < InternalSHA512Block.TypeUlongSz; ++i)
            {
                Common.REVERT(ref registers[i]);
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
        /// Size of structure in memory when treated as a collection of ulong values
        /// </summary>
        public const int TypeUlongSz = 80;

        /// <summary>
        /// Size of structure in memory when treated as a collection of bytes
        /// </summary>
        public const int TypeByteSz = TypeUlongSz * sizeof(ulong);

        /// <summary>
        /// Fixed size buffer for registers
        /// </summary>
        [FieldOffset(0)]
        internal unsafe fixed ulong registers[TypeUlongSz];
    }
}
