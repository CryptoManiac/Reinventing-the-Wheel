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
    }
}
