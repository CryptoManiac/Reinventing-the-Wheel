namespace Wheel.Hashing.RIPEMD.Internal
{
    internal static class InternalRIPEMDConstants
	{
        /// <summary>
        /// RIPEMD-160 initial state
        /// </summary>
        public static InternalRIPEMDState ripemd_init_state = new(0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0);
    }
}

