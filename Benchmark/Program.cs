using Wheel.Crypto.SHA;
using System.Diagnostics;

public class BenchmarkProgram
{
    private static void Benchmark(string name, Action action, int n, int bytes)
    {
        int cpuFreq = 3200; // Set your processor clock in MHz here

        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("{0} {1}", name, bytes);
        Console.ForegroundColor = ConsoleColor.Gray;
        GC.Collect();
        GC.WaitForPendingFinalizers();
        var watch = new Stopwatch();
        var start = DateTime.UtcNow;
        var values = new float[n];
        for (int i = 0; i < n; i++)
        {
            watch.Restart();
            action();
            watch.Stop();
            double thisIteration = watch.Elapsed.TotalSeconds;
            values[i] = (float)thisIteration;
        }
        var total = (DateTime.UtcNow - start).TotalSeconds;
        var perIteration = total / n;
        Array.Sort(values);
        double sum = values.Sum();
        double sumOfSquares = values.Sum(x => x * x);
        double average = sum / n;
        double stdDev = Math.Sqrt(sumOfSquares / n - average * average);
        double median = values[n / 2];
        double min = values.Min();
        double max = values.Max();

        double low90 = values[n / 10];
        double high90 = values[n - 1 - n / 10];
        double delta90 = (high90 - low90) / 2;
        double relativeDelta90 = delta90 / median;
        double average90 = values.Where(x => (x >= low90) && (x <= high90)).Average();

        double low75 = values[n / 4];
        double high75 = values[n - 1 - n / 4];
        double delta75 = (high75 - low75) / 2;
        double relativeDelta75 = delta75 / median;
        double average75 = values.Where(x => (x >= low75) && (x <= high75)).Average();

        Console.WriteLine("{0} us / {1} per second / {2} cycles",
            Math.Round(average90 * 1E6, 2), Math.Round(1 / average90), Math.Round(average90 * cpuFreq * 1E6));
        Console.WriteLine("Average {0} us, Median {1} us, min {2}, max {3}", Math.Round(average * 1E6, 2),
                          Math.Round(median * 1E6, 2), Math.Round(min * 1E6, 2), Math.Round(max * 1E6, 2));
        Console.WriteLine("80% within ±{0}% average {1} | 50% within ±{2}% average {3}",
            Math.Round(relativeDelta90 * 100, 2), Math.Round(average90 * 1E6, 2),
            Math.Round(relativeDelta75 * 100, 2), Math.Round(average75 * 1E6, 2));
        if (bytes > 0)
        {
            double bytesPerSecond = bytes / average90;
            double cyclesPerByte = (cpuFreq * 1E6) / bytesPerSecond;
            Console.WriteLine("{0} MB/s / {1} cycles/byte",
                Math.Round(bytesPerSecond / 1E6, 2), Math.Round(cyclesPerByte, 2));
        }
        Console.WriteLine();
    }

    private static void SHA256_Calc(byte[] message)
    {
        SHA256 hasher = new();
        hasher.Update(message);
        hasher.Digest();
    }

    private static void SHA256_Calc_Reuse(ref SHA256 hasher, ref byte[] hash, byte[] message)
    {
        hasher.Reset();
        hasher.Update(message);
        hasher.Digest(ref hash);
    }

    private static void SHA512_Calc(byte[] message)
    {
        SHA512 hasher = new();
        hasher.Update(message);
        hasher.Digest();
    }

    private static void SHA512_Calc_Reuse(ref SHA512 hasher, ref byte[] hash, byte[] message)
    {
        hasher.Reset();
        hasher.Update(message);
        hasher.Digest(ref hash);
    }

    public static void Main()
    {
        const int n = 10000;

        foreach (var size in new[] { 144, 1000, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 1048576, 2097152 })
        {
            Console.ForegroundColor = ConsoleColor.Yellow;

            var message = new byte[size];
            var hash256 = new byte[32];
            var hash512 = new byte[64];

            SHA256 hasher256 = new();
            SHA512 hasher512 = new();

            Benchmark("SHA256_Calc", () => SHA256_Calc(message), n, size);
            Benchmark("SHA256_Calc_Reuse", () => SHA256_Calc_Reuse(ref hasher256, ref hash256, message), n, size);
            Benchmark("SHA512_Calc", () => SHA512_Calc(message), n, size);
            Benchmark("SHA512_Calc_Reuse", () => SHA512_Calc_Reuse(ref hasher512, ref hash512, message), n, size);

            Console.WriteLine("SHA256 {0} {1}", size, Convert.ToHexString(hash256));
            Console.WriteLine("SHA512 {0} {1}", size, Convert.ToHexString(hash512));
            Console.WriteLine();
        }
    }
}
