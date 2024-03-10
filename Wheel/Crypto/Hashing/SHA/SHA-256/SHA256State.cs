using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Crypto.Miscellaneous.Support;

namespace Wheel.Crypto.Hashing.SHA.SHA256.Internal
{
    /// <summary>
    /// Represents the state data for the 256-bit family of SHA functions
    /// </summary>
	[StructLayout(LayoutKind.Explicit)]
    public unsafe struct InternalSHA256State
    {
        /// <summary>
        /// Instantiate from array or a variable number of arguments
        /// </summary>
        /// <param name="uints"></param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public unsafe InternalSHA256State(params uint[] uints)
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
        public unsafe InternalSHA256State(in InternalSHA256State state)
        {
            Set(state);
        }

        public unsafe void Set(in InternalSHA256State state)
        {
            fixed (void* source = &state)
            {
                fixed (void* target = &this)
                {
                    new Span<byte>(source, TypeByteSz).CopyTo(new Span<byte>(target, TypeByteSz));
                }
            }
        }

        public void Add(in InternalSHA256State state)
        {
            a += state.a;
            b += state.b;
            c += state.c;
            d += state.d;
            e += state.e;
            f += state.f;
            g += state.g;
            h += state.h;
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
        /// Revert the byte order for the block registers
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
        static public readonly int TypeUintSz = sizeof(InternalSHA256State) / 4;

        /// <summary>
        /// Size of structure in memory when treated as a collection of bytes
        /// </summary>
        static public readonly int TypeByteSz = sizeof(InternalSHA256State);

        #region Fixed size buffers for actual storage
        [FieldOffset(0)]
        private fixed byte data[32];
        [FieldOffset(0)]
        private fixed uint registers[8];
        #endregion

        #region Public access to named register fields
        [FieldOffset(0)]
        public uint a;

        [FieldOffset(4)]
        public uint b;

        [FieldOffset(8)]
        public uint c;

        [FieldOffset(12)]
        public uint d;

        [FieldOffset(16)]
        public uint e;

        [FieldOffset(20)]
        public uint f;

        [FieldOffset(24)]
        public uint g;

        [FieldOffset(28)]
        public uint h;
        #endregion
    }
}
