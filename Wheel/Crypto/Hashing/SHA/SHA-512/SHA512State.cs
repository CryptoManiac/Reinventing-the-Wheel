using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Crypto.Miscellaneous.Support;

namespace Wheel.Crypto.Hashing.SHA.SHA512.Internal
{
    /// <summary>
    /// Represents the state data for the 512-bit family of SHA functions
    /// </summary>
	[StructLayout(LayoutKind.Explicit)]
    public struct InternalSHA512State
    {
        /// <summary>
        /// Instantiate from array or a variable number of arguments
        /// </summary>
        /// <param name="ulongs"></param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public InternalSHA512State(params ulong[] ulongs)
        {
            if (ulongs.Length != TypeUlongSz)
            {
                throw new ArgumentOutOfRangeException(nameof(ulongs), ulongs.Length, "Must provide " + TypeUlongSz + " arguments exactly");
            }
            
            a = ulongs[0];
            b = ulongs[1];
            c = ulongs[2];
            d = ulongs[3];
            e = ulongs[4];
            f = ulongs[5];
            g = ulongs[6];
            h = ulongs[7];
        }

        /// <summary>
        /// Instantiate as a copy of the other state
        /// </summary>
        /// <param name="round">Other block</param>
        public unsafe InternalSHA512State(in InternalSHA512State state)
        {
            Set(state);
        }

        public void Set(in InternalSHA512State state)
        {
            a = state.a;
            b = state.b;
            c = state.c;
            d = state.d;
            e = state.e;
            f = state.f;
            g = state.g;
            h = state.h;
        }

        public void Add(in InternalSHA512State state)
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
                throw new ArgumentOutOfRangeException(nameof(to), to.Length, "Span must not be longer than " + byteSz + " bytes");
            }

            switch(to.Length)
            {
                case 28:
                    {
                        // SHA512_224 is a special one, treat
                        //  as 32 bit chunks for simplicity
                        Span<uint> X = MemoryMarshal.Cast<byte, uint>(to);
                        X[0] = a_hi;
                        X[1] = a_low;
                        X[2] = b_hi;
                        X[3] = b_low;
                        X[4] = c_hi;
                        X[5] = c_low;
                        X[6] = d_hi;
                        return;
                    }
                case 32:
                case 48:
                case 64:
                    {
                        // Cast to a set of 64-bit integers
                        Span<ulong> X = MemoryMarshal.Cast<byte, ulong>(to);

                        // 0 .. 3 for SHA512_256, SHA-384 and SHA-512
                        X[0] = a;
                        X[1] = b;
                        X[2] = c;
                        X[3] = d;

                        if (X.Length == 6 || X.Length == 8)
                        {
                            // 4 and 5 for both SHA-384 and SHA-512
                            X[4] = e;
                            X[5] = f;
                        }

                        if (X.Length == 8)
                        {
                            // 6 and 7 for SHA-512
                            X[6] = g;
                            X[7] = h;
                        }

                        return;
                    }
                default:
                    throw new ArgumentOutOfRangeException(nameof(to), to.Length, "Span must be 28, 32, 48 or 64 bytes long");
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
        /// Size of structure in memory when treated as a collection of ulong values
        /// </summary>
        public const int TypeUlongSz = 8;

        /// <summary>
        /// Size of structure in memory when treated as a collection of bytes
        /// </summary>
        public const int TypeByteSz = TypeUlongSz * sizeof(ulong);

        #region For Store() call from the SHA512_224 intances
        [FieldOffset(0)]
        private uint a_hi;
        [FieldOffset(4)]
        private uint a_low;

        [FieldOffset(8)]
        private uint b_hi;
        [FieldOffset(12)]
        private uint b_low;

        [FieldOffset(16)]
        private uint c_hi;
        [FieldOffset(20)]
        private uint c_low;

        [FieldOffset(24)]
        private uint d_hi;
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
