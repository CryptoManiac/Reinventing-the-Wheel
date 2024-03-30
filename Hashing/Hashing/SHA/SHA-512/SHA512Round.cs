using System.Net;
using System.Runtime.InteropServices;

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
        public InternalSHA512Round(params ulong[] ulongs)
        {
            if (ulongs.Length != TypeUlongSz)
            {
                throw new ArgumentOutOfRangeException(nameof(ulongs), ulongs.Length, "Must provide " + TypeUlongSz + " arguments exactly");
            }
            ulongs.CopyTo(registers);
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
        private void SetBlock(in InternalSHA512Block block)
        {
            block.bytes.CopyTo(
                MemoryMarshal.Cast<ulong, byte>(registers)
            );
        }

        /// <summary>
        /// Revert the byte order for the first 16 state registers
        /// </summary>
        private void RevertBlock()
        {
            for (int i = 0; i < InternalSHA512Block.TypeUlongSz; ++i)
            {
                registers[i] = (ulong)IPAddress.HostToNetworkOrder((long)registers[i]);
            }
        }

        /// <summary>
        /// Set to zero
        /// </summary>
        public void Reset()
        {
            registers.Clear();
        }

        /// <summary>
        /// Safe access to words
        /// </summary>
        public readonly unsafe Span<ulong> registers
        {
            get
            {
                fixed (ulong* ptr = &words[0])
                {
                    return new Span<ulong>(ptr, TypeUlongSz);
                }
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
        private unsafe fixed ulong words[TypeUlongSz];
    }
}
