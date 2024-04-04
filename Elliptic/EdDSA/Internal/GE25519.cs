using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace EdDSA.Internal
{
    /// <summary>
    /// GE stands for Group Element
    /// Memory-safe wrapper over fixed-length number arrays
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    internal struct GE25519
    {
        [FieldOffset(0 * ModM.ModM_WORDS * sizeof(ulong))]
        private unsafe fixed ulong _X[ModM.ModM_WORDS];
        [FieldOffset(1 * ModM.ModM_WORDS * sizeof(ulong))]
        private unsafe fixed ulong _Y[ModM.ModM_WORDS];
        [FieldOffset(2 * ModM.ModM_WORDS * sizeof(ulong))]
        private unsafe fixed ulong _Z[ModM.ModM_WORDS];
        [FieldOffset(3 * ModM.ModM_WORDS * sizeof(ulong))]
        private unsafe fixed ulong _T[ModM.ModM_WORDS];

        /// <summary>
        /// All integers at once, used by constructor
        /// </summary>
        [FieldOffset(0)]
        private unsafe fixed ulong _ALL[TypeUlongSz];

        public const int TypeUlongSz = 4 * ModM.ModM_WORDS;

        public GE25519(ReadOnlySpan<ulong> values)
        {
            // Will throw on insufficient length
            values[..TypeUlongSz].CopyTo(ALL);
        }

        public unsafe Span<ulong> X
        {
            get {
                fixed (ulong* ptr = &_X[0])
                {
                    return new(ptr, ModM.ModM_WORDS);
                }
            }
        }

        public unsafe Span<ulong> Y
        {
            get
            {
                fixed (ulong* ptr = &_Y[0])
                {
                    return new(ptr, ModM.ModM_WORDS);
                }
            }
        }

        public unsafe Span<ulong> Z
        {
            get
            {
                fixed(ulong* ptr = &_Z[0])
                {
                    return new(ptr, ModM.ModM_WORDS);
                }
            }
        }

        public unsafe Span<ulong> T
        {
            get
            {
                fixed (ulong* ptr = &_T[0])
                {
                    return new(ptr, ModM.ModM_WORDS);
                }
            }
        }

        public unsafe Span<ulong> ALL
        {
            get
            {
                fixed (ulong* ptr = &_ALL[0])
                {
                    return new(ptr, TypeUlongSz);
                }
            }
        }

    }
}
