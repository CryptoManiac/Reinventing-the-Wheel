using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Crypto.Miscellaneous.Support;

namespace Wheel.Crypto.Hashing.SHA.SHA256.Internal
{
    /// <summary>
    /// Represents the state data for the 256-bit family of SHA functions
    /// </summary>
	[StructLayout(LayoutKind.Explicit)]
    internal struct InternalSHA256State
    {
        /// <summary>
        /// Instantiate from array or a variable number of arguments
        /// </summary>
        /// <param name="uints"></param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public InternalSHA256State(params uint[] uints)
        {
            if (uints.Length != TypeUintSz)
            {
                throw new ArgumentOutOfRangeException(nameof(uints), uints.Length, "Must provide " + TypeUintSz + " arguments exactly");
            }

            a = uints[0];
            b = uints[1];
            c = uints[2];
            d = uints[3];
            e = uints[4];
            f = uints[5];
            g = uints[6];
            h = uints[7];
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
        public readonly void Store(Span<byte> to)
        {
            int byteSz = TypeByteSz;

            if (to.Length > byteSz)
            {
                throw new ArgumentOutOfRangeException(nameof(to), to.Length, "Span must not be more than " + byteSz + " bytes long");
            }

            Span<uint> X = MemoryMarshal.Cast<byte, uint>(to);

            // First 7 fields for both SHA-256 and SHA-224
            X[0] = a;
            X[1] = b;
            X[2] = c;
            X[3] = d;
            X[4] = e;
            X[5] = f;
            X[6] = g;

            // 8th field for SHA-256
            if (X.Length == 8)
            {
                X[7] = h;
            }
        }

        /// <summary>
        /// Revert the byte order for the block registers
        /// </summary>
        public void Revert()
        {
            Common.REVERT(ref a);
            Common.REVERT(ref b);
            Common.REVERT(ref c);
            Common.REVERT(ref d);
            Common.REVERT(ref e);
            Common.REVERT(ref f);
            Common.REVERT(ref g);
            Common.REVERT(ref h);
        }

        /// <summary>
        /// Size of structure in memory when treated as a collection of uint values
        /// </summary>
        public const int TypeUintSz = 8;

        /// <summary>
        /// Size of structure in memory when treated as a collection of bytes
        /// </summary>
        public const int TypeByteSz = TypeUintSz * sizeof(uint);

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
