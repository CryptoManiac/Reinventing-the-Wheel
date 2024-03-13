using System.Runtime.InteropServices;

namespace Wheel.Crypto.Hashing.RIPEMD.Internal
{
    /// <summary>
    /// Represents the block data for the RIPEMD-160
    /// Note: Mostly identical to that of SHA-256
    /// </summary>
	[StructLayout(LayoutKind.Explicit)]
    internal struct InternalRIPEMDState
    {
        /// <summary>
        /// Instantiate from array or a variable number of arguments
        /// </summary>
        /// <param name="uints"></param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public InternalRIPEMDState(params uint[] uints)
        {
            if (uints.Length != TypeUintSz)
            {
                throw new ArgumentOutOfRangeException(nameof(uints), uints.Length, "Must provide " + TypeUintSz + " arguments exactly");
            }

            X00 = uints[0];
            X01 = uints[1];
            X02 = uints[2];
            X03 = uints[3];
            X04 = uints[4];
        }

        /// <summary>
        /// Dump vector contents
        /// </summary>
        /// <param name="bytes"></param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public readonly void Store(Span<byte> to)
        {
            int byteSz = TypeByteSz;

            if (to.Length != byteSz)
            {
                throw new ArgumentOutOfRangeException(nameof(to), to.Length, "Span must be " + byteSz + " bytes long");
            }

            Span<uint> toX = MemoryMarshal.Cast<byte, uint>(to);

            toX[0] = X00;
            toX[1] = X01;
            toX[2] = X02;
            toX[3] = X03;
            toX[4] = X04;
        }

        /// <summary>
        /// Size of structure in memory when treated as a collection of uint values
        /// </summary>
        static public readonly int TypeUintSz = 5;

        /// <summary>
        /// Size of structure in memory when treated as a collection of bytes
        /// </summary>
        static public readonly int TypeByteSz = TypeUintSz * sizeof(uint);

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

