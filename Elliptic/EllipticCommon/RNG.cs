using System;
using System.Runtime.InteropServices;

namespace Wheel.Crypto.Elliptic.EllipticCommon;

/// <summary>
/// Random number generator
/// </summary>
public static class RNG
{
    private static System.Security.Cryptography.RandomNumberGenerator gen = System.Security.Cryptography.RandomNumberGenerator.Create();
    private static object LockGuard = new();

    public static void Fill(Span<ulong> rnd)
    {
        lock (LockGuard)
        {
            Span<byte> byteView = MemoryMarshal.Cast<ulong, byte>(rnd);
            RNG.gen.GetBytes(byteView);
        }
    }

    public static void Fill(Span<byte> rnd)
    {
        lock (LockGuard)
        {
            RNG.gen.GetBytes(rnd);
        }
    }
}
