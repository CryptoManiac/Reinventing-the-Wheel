using System.Runtime.CompilerServices;

namespace Wheel.Hashing.SHA.SHA512.Internal;

internal static class InternalSHA512Ops
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong SHFR(ulong x, int n) => x >> n;
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong ROTR(ulong x, int n) => (x >> n) | (x << (64 - n));
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong CHOOSE(ulong x, ulong y, ulong z) => (x & y) ^ (~x & z);
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong MAJ(ulong x, ulong y, ulong z) => (x & y) ^ (x & z) ^ (y & z);
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong SIGMA0(ulong x) => ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39);
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong SIGMA1(ulong x) => ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41);
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong SIG0(ulong x) => ROTR(x, 1) ^ ROTR(x, 8) ^ SHFR(x, 7);
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong SIG1(ulong x) => ROTR(x, 19) ^ ROTR(x, 61) ^ SHFR(x, 6);
}
