using System;
using System.Runtime.InteropServices;
using static System.Runtime.InteropServices.JavaScript.JSType;

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
            gen.GetBytes(byteView);
        }
    }

    public static void Fill(Span<byte> rnd)
    {
        lock (LockGuard)
        {
            gen.GetBytes(rnd);
        }
    }
}

/// <summary>
/// Estimation of Shannon's entropy of
///  input in a memory-secure manner
/// </summary>
public static class Entropy
{
    private static double LogTwo(double v)
    {
        return Math.Log(v) / Math.Log(2);
    }

    public static double Estimate(Span<byte> input)
    {
        double frequency, compression = 0;

        Span<double> Table = stackalloc double[256];

        // Clear table
        Table.Clear();

        foreach (var c in input)
        {
            Table[c] += 1;
        }

        foreach (var f in Table)
        {
            if (f != 0)
            {
                frequency = f / input.Length;
                compression += frequency * LogTwo(frequency);
            }
        }

        // Clear table
        Table.Clear();

        return compression * -1;
    }

}
