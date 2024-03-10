using System.Runtime.InteropServices;

namespace Wheel.Crypto.Hashing.RIPEMD.Internal
{
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
        /// Size of structure in memory when treated as a collection of uint values
        /// </summary>
        static public readonly int TypeUintSz = sizeof(InternalRIPEMDState) / 4;

        /// <summary>
        /// Size of structure in memory when treated as a collection of bytes
        /// </summary>
        static public readonly int TypeByteSz = sizeof(InternalRIPEMDState);

        #region Individual word registers
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
        #endregion
    }
}

