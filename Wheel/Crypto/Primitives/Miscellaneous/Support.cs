using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Wheel.Crypto.Miscellaneous.Support
{

    internal static class Common
	{
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint REVERT(uint value)
        {
            return (uint)IPAddress.NetworkToHostOrder((int)value);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong REVERT(ulong value)
        {
            return (ulong)IPAddress.NetworkToHostOrder((long)value);
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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe static void REVERT(uint* p, int offset)
        {
            *(p + offset) = (uint)IPAddress.NetworkToHostOrder((int)*(p + offset));
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe static void REVERT(ulong* p, int offset)
        {
            *(p + offset) = (ulong)IPAddress.NetworkToHostOrder((long)*(p + offset));
        }
    }
}
