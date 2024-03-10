using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Wheel.Crypto.Hashing.RIPEMD.Internal
{
    /// <summary>
    /// Access to individual block bytes through index operator
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public unsafe struct InternalRIPEMDStateBytes
    {
        /// <summary>
        /// Index access to individual registers
        /// </summary>
        /// <param name="key">Byte field index [0 .. 63]</param>
        /// <returns>Word value</returns>
        public byte this[uint key]
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            readonly get => GetRegisterByte(key);
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            set => SetRegisterByte(key, value);
        }

        #region Byte access logic
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe readonly byte GetRegisterByte(uint index)
        {
            ThrowOrPassByte(index);
            return data[index];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe void SetRegisterByte(uint index, byte value)
        {
            ThrowOrPassByte(index);
            data[index] = value;
        }

        static void ThrowOrPassByte(uint index)
        {
            if (index >= TypeByteSz)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. " + TypeByteSz + ") range");
            }
        }
        #endregion

        /// <summary>
        /// Size of structure in memory when treated as a collection of bytes
        /// </summary>
        static public readonly int TypeByteSz = sizeof(InternalRIPEMDStateBytes);

        [FieldOffset(0)]
        private fixed byte data[20];
    }

    /// <summary>
    /// Represents the block data for the RIPEMD-160
    /// Note: Mostly identical to that of SHA-256
    /// </summary>
	[StructLayout(LayoutKind.Explicit)]
    public unsafe struct InternalRIPEMDState
    {
        /// <summary>
        /// Instantiate from array or a variable number of arguments
        /// </summary>
        /// <param name="uints"></param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public unsafe InternalRIPEMDState(params uint[] uints)
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
        /// Instantiate as a copy of the other state
        /// </summary>
        /// <param name="round">Other block</param>
        public unsafe InternalRIPEMDState(in InternalRIPEMDState state)
        {
            Set(state);
        }

        /// <summary>
        /// Set to a copy of the other state
        /// </summary>
        /// <param name="round">Other block</param>
        public unsafe void Set(in InternalRIPEMDState state)
        {
            fixed (void* source = &state)
            {
                fixed (void* target = &this)
                {
                    new Span<byte>(source, TypeByteSz).CopyTo(new Span<byte>(target, TypeByteSz));
                }
            }
        }

        /// <summary>
        /// Dump vector contents
        /// </summary>
        /// <param name="bytes"></param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public unsafe readonly void Store(Span<byte> to)
        {
            int byteSz = TypeByteSz;

            if (to.Length > byteSz)
            {
                throw new ArgumentOutOfRangeException(nameof(to), to.Length, "Span must not be longer than " + byteSz + " bytes");
            }

            fixed (void* source = &this)
            {
                var from = new Span<byte>(source, to.Length);
                from.CopyTo(to);
            }
        }

        /// <summary>
        /// Index access to individual registers
        /// </summary>
        /// <param name="key">Field index [0 .. 7]</param>
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
        /// Size of structure in memory when treated as a collection of uint values
        /// </summary>
        static public readonly int TypeUintSz = sizeof(InternalRIPEMDState) / sizeof(uint);

        /// <summary>
        /// Size of structure in memory when treated as a collection of bytes
        /// </summary>
        static public readonly int TypeByteSz = sizeof(InternalRIPEMDState);

        #region Fixed size buffers for actual storage
        [FieldOffset(0)]
        private fixed byte data[20];
        [FieldOffset(0)]
        private fixed uint registers[5];
        #endregion

        /// <summary>
        /// Public access to the individual block bytes
        /// </summary>
        [FieldOffset(0)]
        public InternalRIPEMDStateBytes bytes;

        #region Individual word public access
        [FieldOffset(0)]
        public uint X00 = 0;
        [FieldOffset(1 * sizeof(uint))]
        public uint X01 = 0;
        [FieldOffset(2 * sizeof(uint))]
        public uint X02 = 0;
        [FieldOffset(3 * sizeof(uint))]
        public uint X03 = 0;
        [FieldOffset(4 * sizeof(uint))]
        public uint X04 = 0;
        #endregion
    }
}

