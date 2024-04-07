using System.Runtime.CompilerServices;

namespace Wheel.Crypto.Elliptic.EdDSA.Internal.Platform;

/// <summary>
/// Conversion functions. Likely to be removed in the future.
/// </summary>
internal static class Conv
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void U32TO8_LE(Span<byte> p, uint v)
    {
        p[0] = (byte)v;
        p[1] = (byte)(v >> 8);
        p[2] = (byte)(v >> 16);
        p[3] = (byte)(v >> 24);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong U8TO64_LE(ReadOnlySpan<byte> p)
    {
        return
         p[0] |
         ((ulong)p[1] << 8) |
         ((ulong)p[2] << 16) |
         ((ulong)p[3] << 24) |
         ((ulong)p[4] << 32) |
         ((ulong)p[5] << 40) |
         ((ulong)p[6] << 48) |
         ((ulong)p[7] << 56);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void U64TO8_LE(Span<byte> p, ulong v)
    {
        p[0] = (byte)(v);
        p[1] = (byte)(v >> 8);
        p[2] = (byte)(v >> 16);
        p[3] = (byte)(v >> 24);
        p[4] = (byte)(v >> 32);
        p[5] = (byte)(v >> 40);
        p[6] = (byte)(v >> 48);
        p[7] = (byte)(v >> 56);
    }
}

/// <summary>
/// Low-level primitives for Curve25519 math
/// </summary>
internal static class ASM
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void mul64x64_128(out UInt128 @out, ulong a, ulong b) {
        @out = (UInt128)a * b;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void shr128_pair(out ulong @out, ulong hi, ulong lo, int shift) {
        @out = (ulong)((((UInt128)hi << 64) | lo) >> (shift));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void shl128_pair(out ulong @out, ulong hi, ulong lo, int shift)
    {
        @out = (ulong)(((((UInt128)hi << 64) | lo) << (shift)) >> 64);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void shr128(out ulong @out, UInt128 @in, int shift) {
        @out = (ulong)(@in >> (shift));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void shl128(out ulong @out, UInt128 @in, int shift) {
        @out = (ulong)((@in << shift) >> 64);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void add128(ref UInt128 a, UInt128 b) => a += b;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void add128_64(ref UInt128 a, UInt128 b) => a += (ulong) b;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong lo128(UInt128 a) => ((ulong)a);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong hi128(UInt128 a) => ((ulong)(a >> 64));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint ROTL32(uint a, int b) => (((a) << (b)) | ((a) >> (32 - b)));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint ROTR32(uint a, int b) => (((a) >> (b)) | ((a) << (32 - b)));
}

