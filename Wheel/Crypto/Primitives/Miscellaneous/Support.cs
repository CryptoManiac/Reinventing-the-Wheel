using System.Net;
using System.Runtime.CompilerServices;

namespace Wheel.Crypto.Miscellaneous.Support
{

    internal static class Common
	{
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void REVERT(ref uint value)
        {
            value = (uint)IPAddress.NetworkToHostOrder((int)value);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void REVERT(ref ulong value)
        {
            value = (ulong)IPAddress.NetworkToHostOrder((long)value);
        }

        /// <summary>
        /// Revert 128-bit integer in place
        /// </summary>
        /// <param name="value"></param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe static void REVERT(ref UInt128 value)
        {
            fixed(void *ptr = &value)
            {
                long* lo = (long*)ptr;
                long* hi = lo + 1;

                (*lo, *hi) = (IPAddress.NetworkToHostOrder(*hi), IPAddress.NetworkToHostOrder(*lo));
            }
        }
    }
}
