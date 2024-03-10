using System.Text;
using Wheel.Crypto.Hashing.SHA.SHA256;
using Wheel.Crypto.Hashing.SHA.SHA512;
using Wheel.Crypto.Hashing.RIPEMD;
using Wheel.Crypto.Hashing;

// Perverted tests
SortedDictionary<string, KeyValuePair<Func<IHasher>, Tuple<string, string>>> tortureScript = new()
{
    {
        "RIPEMD160", new (
            () => new RIPEMD160(),
            new (
                "52783243c1697bdbe16d37f97f68f08325dc1528",
                "29b6df855772aa9a95442bf83b282b495f9f6541"
            )
        )
    },
    {
        "SHA224", new (
            () => new SHA224(),
            new (
                "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67",
                "b5989713ca4fe47a009f8621980b34e6d63ed3063b2a0a2c867d8a85"
            )
        )
    },
    {
        "SHA256", new (
            () => new SHA256(),
            new (
                "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
                "50e72a0e26442fe2552dc3938ac58658228c0cbfb1d2ca872ae435266fcd055e"
            )
        )
    },
    {
        "SHA384", new (
            () => new SHA384(),
            new (
                "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
                "5441235cc0235341ed806a64fb354742b5e5c02a3c5cb71b5f63fb793458d8fdae599c8cd8884943c04f11b31b89f023"
            )
        )
    },
    {
        "SHA512", new (
            () => new SHA512(),
            new (
                "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
                "b47c933421ea2db149ad6e10fce6c7f93d0752380180ffd7f4629a712134831d77be6091b819ed352c2967a2e2d4fa5050723c9630691f1a05a7281dbe6c1086"
            )
        )
    },
    {
        "SHA512_256", new (
            () => new SHA512_256(),
            new (
                "9a59a052930187a97038cae692f30708aa6491923ef5194394dc68d56c74fb21",
                "b5855a6179802ce567cbf43888284c6ac7c3f6c48b08c5bc1e8ad75d12782c9e"
            )
        )
    },
    {
        "SHA512_224", new (
            () => new SHA512_224(),
            new (
                "37ab331d76f0d36de422bd0edeb22a28accd487b7a8453ae965dd287",
                "9a7f86727c3be1403d6702617646b15589b8c5a92c70f1703cd25b52"
            )
        )
    }
};

static void WriteRepeatedly(IHasher hasher, byte[] input, int iterations)
{
    for (int i = 0; i < iterations; ++i)
    {
        hasher.Update(input);
    }
}

static void FinalizeAndCompare(IHasher hasher, string expected)
{
    string hash = Convert.ToHexString(hasher.Digest()).ToLower();

    if (hash != expected)
    {
        Console.WriteLine("Calculated: {0}", hash);
        Console.WriteLine("Expected: {0}", expected);
        throw new SystemException("Result \"" + hash.Substring(0, 16) + "...\" is not \"" + expected[..16] + "...\"");
    }
    Console.WriteLine("Okay");
}

static void Torture_1Mill(string algoName, Func<IHasher> algorithm, bool once, string expected)
{
    IHasher hasher = algorithm();

    Console.Write("Torture {0} ", algoName);

    if (once)
    {
        Console.WriteLine("(1M \"a\" characters of input at once) => {0} ...", expected[..16]);

        // Input message: 1 million repetitions
        // of the character "a" (0x61).
        byte[] input = new byte[1000000];
        Array.Fill<byte>(input, 0x61);
        hasher.Update(input);
    }
    else
    {
        Console.WriteLine("(1M \"a\" characters of input iteratively) => {0} ...", expected[..16]);
        WriteRepeatedly(hasher, "a"u8.ToArray(), 1000000);
    }

    FinalizeAndCompare(hasher, expected);
}

static void Torture_1Gig(string algoName, Func<IHasher> algorithm, string expected)
{
    string pattern = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno";

    Console.WriteLine("Torture {0} (1G \"{1}\" repeated characters input) => {2} ...", algoName, pattern, expected[..16]);

    IHasher hasher = algorithm();

    // Input message: pattern to be repeated
    byte[] input = Encoding.ASCII.GetBytes(pattern);

    // Repeat sequence 16,777,216 times
    WriteRepeatedly(hasher, input, 16777216);

    FinalizeAndCompare(hasher, expected);
}

foreach (var (name, (algorithm, (oneMillion, oneGig))) in tortureScript) {
    Torture_1Mill(name, algorithm, true, oneMillion);
    Torture_1Mill(name, algorithm, false, oneMillion);
    Torture_1Gig(name, algorithm, oneGig);
}
