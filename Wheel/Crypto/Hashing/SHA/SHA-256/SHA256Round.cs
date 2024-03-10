using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Crypto.Miscellaneous.Support;

namespace Wheel.Crypto.Hashing.SHA.SHA256.Internal
{
    /// <summary>
    /// Represents the round context data for the 256-bit family of SHA functions
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public unsafe struct InternalSHA256Round
    {
        /// <summary>
        /// Instantiate from array or a variable number of arguments
        /// </summary>
        /// <param name="uints"></param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public unsafe InternalSHA256Round(params uint[] uints)
        {
            if (uints.Length != TypeUintSz)
            {
                throw new ArgumentOutOfRangeException(nameof(uints), uints.Length, "Must provide " + TypeUintSz + " arguments exactly");
            }

            fixed (void* source = &uints[0])
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
        public InternalSHA256Round(in InternalSHA256Block block)
        {
            SetBlock(block);
            RevertBlock();
        }

        /// <summary>
        /// Index access to individual registers
        /// </summary>
        /// <param name="key">Byte field index [0 .. 63]</param>
        /// <returns>Word value</returns>
        public uint this[uint key]
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            readonly get => GetRegisterUint(key);
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            set => SetRegisterUint(key, value);
        }

        #region Register access logic
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe readonly uint GetRegisterUint(uint index)
        {
            ThrowOrPassUint(index);
            return registers[index];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe void SetRegisterUint(uint index, uint value)
        {
            ThrowOrPassUint(index);
            registers[index] = value;
        }

        static void ThrowOrPassUint(uint index)
        {
            if (index >= TypeUintSz)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. " + TypeUintSz + ") range");
            }
        }
        #endregion

        /// <summary>
        /// Set first 16 registers from the provided container
        /// </summary>
        /// <param name="block">A context to provide 16 registers</param>
        private unsafe void SetBlock(in InternalSHA256Block block)
        {
            fixed (void* source = &block)
            {
                fixed (void* target = &this)
                {
                    new Span<byte>(source, InternalSHA256Block.TypeByteSz).CopyTo(new Span<byte>(target, TypeByteSz));
                }
            }
        }

        /// <summary>
        /// Revert the byte order for the first 16 state registers
        /// </summary>
        private void RevertBlock()
        {
            for (int i = 0; i < InternalSHA256Block.TypeUintSz; ++i)
            {
                registers[i] = Common.REVERT(registers[i]);
            }
        }

        /// <summary>
        /// Revert the byte order for the state registers
        /// </summary>
        public void Revert()
        {
            for (int i = 0; i < TypeUintSz; ++i)
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
        /// Size of structure in memory when treated as a collection of uint values
        /// </summary>
        static public readonly int TypeUintSz = sizeof(InternalSHA256Round) / 4;

        // <summary>
        /// Size of structure in memory when treated as a collection of bytes
        /// </summary>
        static public readonly int TypeByteSz = sizeof(InternalSHA256Round);

        #region Fixed size buffers for actual storage
        [FieldOffset(0)]
        private fixed byte data[256];
        [FieldOffset(0)]
        private fixed uint registers[64];
        #endregion
    }
}
