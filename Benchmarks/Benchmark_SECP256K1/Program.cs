using Wheel.Crypto.Elliptic.ECDSA;
using System.Diagnostics;
using System.Text;
using Wheel.Hashing.HMAC.SHA2;
using Wheel.Hashing.HMAC;
using Wheel.Hashing.SHA.SHA256;
using Wheel.Crypto.Elliptic.EllipticCommon;

static void Benchmark(string name, Action action, int n)
{
    int cpuFreq = 2600; // Set your processor clock in MHz here

    Console.ForegroundColor = ConsoleColor.White;
    Console.WriteLine("{0}", name);
    Console.ForegroundColor = ConsoleColor.Gray;
    GC.Collect();
    GC.WaitForPendingFinalizers();
    var watch = new Stopwatch();
    var start = DateTime.UtcNow;
    var values = new float[n];
    for (int i = 0; i < n; ++i)
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
    Console.WriteLine();
}


string secret_seed = "The quick brown fox jumps over the lazy dog";
string personalization = "For signing tests";
int secret_key_number = 0;

ECCurve curve = ECCurve.Get_SECP256K1();

// Derive new secret key
curve.GenerateDeterministicSecret<HMAC_SHA512>(out ECPrivateKey secretKey, Encoding.ASCII.GetBytes(secret_seed), Encoding.ASCII.GetBytes(personalization), secret_key_number);

if (!secretKey.ComputePublicKey(out IPublicKey publicKey))
{
    throw new SystemException("Computation of the public key has failed");
}

static void SignData<HMAC_IMPL>(Span<byte> signature, IPrivateKey sk, string message, ICurve curve) where HMAC_IMPL : unmanaged, IMac
{
    // Empty for tests
    Span<byte> message_hash = stackalloc byte[32];
    SHA256.Hash(message_hash, Encoding.ASCII.GetBytes(message));

    if (!sk.SignDeterministic<HMAC_IMPL>(out DERSignature derSig, message_hash))
    {
        throw new SystemException("Signing failed");
    }

    if (signature.Length < derSig.Encode(signature))
    {
        throw new Exception("Signature buffer is too short");
    }
}

string message = "aaa";
byte[] message_hash = new byte[32];
SHA256.Hash(message_hash, Encoding.ASCII.GetBytes(message));

bool VerifySignature(ReadOnlySpan<byte> signature, string message, ReadOnlySpan<byte> public_key, ICurve curve)
{
    return new ECPublicKey(curve, public_key).VerifySignature(new DERSignature(curve, signature), message_hash);
}

Benchmark("Sign<HMAC_SHA512>", () => {
    Span<byte> signature = stackalloc byte[curve.DERSignatureSize];
    SignData<HMAC_SHA512>(signature, secretKey, message, curve);
}, 1000);

byte[] public_key_uncompressed = new byte[curve.UncompressedPublicKeySize];

if (!publicKey.Serialize(public_key_uncompressed))
{
    throw new SystemException("Serialization of the public key has failed");
}

byte[] signature = new byte[curve.DERSignatureSize];
SignData<HMAC_SHA512>(signature, secretKey, message, curve);
Benchmark("Verify<HMAC_SHA512>", () => VerifySignature(signature, message, public_key_uncompressed, curve), 1000);

