using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Crypto.Miscellaneous.Support;

namespace Wheel.Crypto.Hashing.SHA.SHA512.Internal
{
    /// <summary>
    /// Represents the state data for the 512-bit family of SHA functions
    /// </summary>
	[StructLayout(LayoutKind.Explicit)]
    public unsafe struct InternalSHA512State
    {
        /// <summary>
        /// Instantiate from array or a variable number of arguments
        /// </summary>
        /// <param name="ulongs"></param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public unsafe InternalSHA512State(params ulong[] ulongs)
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
        /// Instantiate as a copy of the other state
        /// </summary>
        /// <param name="round">Other block</param>
        public unsafe InternalSHA512State(in InternalSHA512State state)
        {
            Set(state);
        }

        public unsafe void Set(in InternalSHA512State state)
        {
            fixed (void* source = &state)
            {
                fixed (void* target = &this)
                {
                    new Span<byte>(source, TypeByteSz).CopyTo(new Span<byte>(target, TypeByteSz));
                }
            }
        }

        public unsafe void Add(in InternalSHA512State state)
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
        /// Revert the byte order for the block registers
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
        static public readonly int TypeUlongSz = sizeof(InternalSHA512State) / 8;

        /// <summary>
        /// Size of structure in memory when treated as a collection of bytes
        /// </summary>
        static public readonly int TypeByteSz = sizeof(InternalSHA512State);

        #region Fixed size buffers for actual storage
        [FieldOffset(0)]
        private fixed byte data[64];
        [FieldOffset(0)]
        private fixed ulong registers[8];
        #endregion

        #region Public access to named register fields
        [FieldOffset(0)]
        public ulong a;

        [FieldOffset(8)]
        public ulong b;

        [FieldOffset(16)]
        public ulong c;

        [FieldOffset(24)]
        public ulong d;

        [FieldOffset(32)]
        public ulong e;

        [FieldOffset(40)]
        public ulong f;

        [FieldOffset(48)]
        public ulong g;

        [FieldOffset(56)]
        public ulong h;
        #endregion
    }
}
