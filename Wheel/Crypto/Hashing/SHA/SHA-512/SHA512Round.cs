using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Crypto.Miscellaneous.Support;

namespace Wheel.Crypto.Hashing.SHA.SHA512.Internal
{
    /// <summary>
    /// Represents the round context data for the 512-bit family of SHA functions
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public unsafe struct InternalSHA512Round
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
        /// Instantiate as a copy of the other round context
        /// </summary>
        /// <param name="round">Other round context</param>
        public unsafe InternalSHA512Round(in InternalSHA512Round round)
        {
            fixed (void* source = &round)
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
        /// Index access to individual registers
        /// </summary>
        /// <param name="key">Field index [0 .. 79]</param>
        /// <returns>Word value</returns>
        public ulong this[uint key]
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            readonly get => GetRegisterUlong(key);
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            set => SetRegisterUlong(key, value);
        }

        #region Register access logic
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private readonly ulong GetRegisterUlong(uint index)
        {
            ThrowOrPassUlong(index);
            return registers[index];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe void SetRegisterUlong(uint index, ulong value)
        {
            ThrowOrPassUlong(index);
            registers[index] = value;
        }

        static void ThrowOrPassUlong(uint index)
        {
            if (index >= TypeUlongSz)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. " + TypeUlongSz + ") range");
            }
        }
        #endregion

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
        private void RevertBlock()
        {
            for (int i = 0; i < InternalSHA512Block.TypeUlongSz; ++i)
            {
                registers[i] = Common.REVERT(registers[i]);
            }
        }

        /// <summary>
        /// Revert the byte order for the state registers
        /// </summary>
        public void Revert()
        {
            for (int i = 0; i < TypeUlongSz; ++i)
            {
                registers[i] = Common.REVERT(registers[i]);
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
        static public readonly int TypeUlongSz = sizeof(InternalSHA512Round) / 8;

        /// <summary>
        /// Size of structure in memory when treated as a collection of bytes
        /// </summary>
        static public readonly int TypeByteSz = sizeof(InternalSHA512Round);

        #region Fixed size buffers for actual storage
        [FieldOffset(0)]
        private fixed byte data[640];
        [FieldOffset(0)]
        private fixed ulong registers[80];
        #endregion
    }
}
