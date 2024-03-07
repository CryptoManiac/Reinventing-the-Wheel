using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Wheel.Crypto.Miscellaneous.Support
{

    internal static class Common
	{
        public static uint REVERT(uint value)
        {
            return
                (value & 0x000000FFU) << 24
                | (value & 0x0000FF00U) << 8
                | (value & 0x00FF0000U) >> 8
                | (value & 0xFF000000U) >> 24;
        }

        public static ulong REVERT(ulong value)
        {
            return
                 (0x00000000000000FF) & (value >> 56)
                 | (0x000000000000FF00) & (value >> 40)
                 | (0x0000000000FF0000) & (value >> 24)
                 | (0x00000000FF000000) & (value >> 8)
                 | (0x000000FF00000000) & (value << 8)
                 | (0x0000FF0000000000) & (value << 24)
                 | (0x00FF000000000000) & (value << 40)
                 | (0xFF00000000000000) & (value << 56);
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct ULongLong128
        {
            [FieldOffset(0)]
            public UInt128 value;
            [FieldOffset(0)]
            public ulong lo;
            [FieldOffset(8)]
            public ulong hi;

            public ULongLong128(UInt128 input)
            {
                value = input;
            }

            public ULongLong128(ulong lo, ulong hi)
            {
                this.lo = lo;
                this.hi = hi;
            }
        }

        /// <summary>
        /// Revert byte order for the 128 bit integer value
        /// </summary>
        /// <param name="value"></param>
        /// <returns>Reverted value</returns>
        public static UInt128 REVERT(UInt128 value)
        {
            ULongLong128 wrapped = new(value);
            return new ULongLong128(
                REVERT(wrapped.hi),
                REVERT(wrapped.lo)
            ).value;
        }

        /// <summary>
        /// Reverse byte order for a sequence of 8 words (32-bit) located at given address
        /// </summary>
        /// <param name="p">Word sequence address</param>
        public unsafe static void REVERT8(uint* p)
        {
            REVERT(p, 0);
            REVERT(p, 1);
            REVERT(p, 2);
            REVERT(p, 3);
            REVERT(p, 4);
            REVERT(p, 5);
            REVERT(p, 6);
            REVERT(p, 7);
        }

        /// <summary>
        /// Reverse byte order for a sequence of 8 double words (64-bit) located at given address
        /// </summary>
        /// <param name="p">Word sequence address</param>
        public unsafe static void REVERT8(ulong* p)
        {
            REVERT(p, 0);
            REVERT(p, 1);
            REVERT(p, 2);
            REVERT(p, 3);
            REVERT(p, 4);
            REVERT(p, 5);
            REVERT(p, 6);
            REVERT(p, 7);
        }

        /// <summary>
        /// Reverse byte order for a sequence of 16 words (32-bit) located at given address
        /// </summary>
        /// <param name="p">Word sequence address</param>
        public unsafe static void REVERT16(uint *p)
        {
            REVERT(p, 0);
            REVERT(p, 1);
            REVERT(p, 2);
            REVERT(p, 3);
            REVERT(p, 4);
            REVERT(p, 5);
            REVERT(p, 6);
            REVERT(p, 7);
            REVERT(p, 8);
            REVERT(p, 9);
            REVERT(p, 10);
            REVERT(p, 11);
            REVERT(p, 12);
            REVERT(p, 13);
            REVERT(p, 14);
            REVERT(p, 15);
        }

        /// <summary>
        /// Reverse byte order for a sequence of 16 double words (64-bit) located at given address
        /// </summary>
        /// <param name="p">Word sequence address</param>
        public unsafe static void REVERT16(ulong *p)
        {
            REVERT(p, 0);
            REVERT(p, 1);
            REVERT(p, 2);
            REVERT(p, 3);
            REVERT(p, 4);
            REVERT(p, 5);
            REVERT(p, 6);
            REVERT(p, 7);
            REVERT(p, 8);
            REVERT(p, 9);
            REVERT(p, 10);
            REVERT(p, 11);
            REVERT(p, 12);
            REVERT(p, 13);
            REVERT(p, 14);
            REVERT(p, 15);
        }

        private unsafe static void REVERT(uint* p, int offset)
        {
            uint v = *(p + offset);

            *(p + offset) =
                (v & 0x000000FFU) << 24
                | (v & 0x0000FF00U) << 8
                | (v & 0x00FF0000U) >> 8
                | (v & 0xFF000000U) >> 24;
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe static void REVERT(ulong* p, int offset)
        {
            ulong v = *(p + offset);

            *(p + offset) =
                (0x00000000000000FF) & (v >> 56)
                 | (0x000000000000FF00) & (v >> 40)
                 | (0x0000000000FF0000) & (v >> 24)
                 | (0x00000000FF000000) & (v >> 8)
                 | (0x000000FF00000000) & (v << 8)
                 | (0x0000FF0000000000) & (v << 24)
                 | (0x00FF000000000000) & (v << 40)
                 | (0xFF00000000000000) & (v << 56);
        }
    }
}
