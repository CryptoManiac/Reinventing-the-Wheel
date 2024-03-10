using System.Net;
using System.Runtime.CompilerServices;

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
