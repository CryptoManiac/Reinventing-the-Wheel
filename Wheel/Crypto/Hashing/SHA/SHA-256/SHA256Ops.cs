using System.Runtime.CompilerServices;

namespace Wheel.Crypto.Hashing.SHA.SHA256.Internal
{
    public static class InternalSHA256Ops
    {
        // Inline for performance reasons
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint ROTR(uint x, int n) => (x >> n) | (x << (32 - n));
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint CHOOSE(uint e, uint f, uint g) => (e & f) ^ (~e & g);
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint MAJ(uint a, uint b, uint c) => (a & (b | c)) | (b & c);
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint SIG0(uint x) => ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3);
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint SIG1(uint x) => ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10);
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint SIGMA0(uint x) => ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint SIGMA1(uint x) => ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
    }
}
