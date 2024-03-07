using System.Text;
using Wheel.Crypto.SHA;

static void Torture_224_1Million_a_once()
{
    string expected = "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67";
    Console.WriteLine("Torture SHA224 (1M \"a\" characters input at once) => {0} ...", expected.Substring(0, 16));

    // Input message: one million (1,000,000) repetitions of the character "a" (0x61).
    byte[] input = new byte[1000000];
    Array.Fill<byte>(input, 0x61);

    SHA224 hasher = new();
    hasher.Update(input);

    string hash = Convert.ToHexString(hasher.Digest()).ToLower();

    if (hash != expected)
    {
        Console.WriteLine("Calculated: {0}", hash);
        Console.WriteLine("Expected: {0}", expected);
        throw new SystemException("Result \"" + hash.Substring(0, 16) + "...\" is not \"" + expected.Substring(0, 16) + "...\"");
    }
    Console.WriteLine("Okay");
}

static void Torture_256_1Million_a_once()
{
    string expected = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
    Console.WriteLine("Torture SHA256 (1M \"a\" characters input at once) => {0} ...", expected.Substring(0, 16));

    // Input message: one million (1,000,000) repetitions of the character "a" (0x61).
    byte[] input = new byte[1000000];
    Array.Fill<byte>(input, 0x61);

    SHA256 hasher = new();
    hasher.Update(input);

    string hash = Convert.ToHexString(hasher.Digest()).ToLower();

    if (hash != expected)
    {
        Console.WriteLine("Calculated: {0}", hash);
        Console.WriteLine("Expected: {0}", expected);
        throw new SystemException("Result \"" + hash.Substring(0, 16) + "...\" is not \"" + expected.Substring(0, 16) + "...\"");
    }
    Console.WriteLine("Okay");
}

static void Torture_512_1Million_a_once()
{
    string expected = "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b";
    Console.WriteLine("Torture SHA512 (1M \"a\" characters input at once) => {0} ...", expected.Substring(0, 16));

    // Input message to be repeated: single "a" character
    byte[] input = new byte[1] { 0x61 };

    SHA512 hasher = new();

    // Update million times
    for (int i = 0; i < 1000000; ++i)
    {
        hasher.Update(input);
    }

    string hash = Convert.ToHexString(hasher.Digest()).ToLower();

    if (hash != expected)
    {
        Console.WriteLine("Calculated: {0}", hash);
        Console.WriteLine("Expected: {0}", expected);
        throw new SystemException("Result \"" + hash.Substring(0, 16) + "...\" is not \"" + expected.Substring(0, 16) + "...\"");
    }
    Console.WriteLine("Okay");
}

static void Torture_224_1Million_a_iter()
{
    string expected = "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67";
    Console.WriteLine("Torture SHA224 (1M \"a\" characters input iteratively) => {0} ...", expected.Substring(0, 16));

    // Input message to be repeated: single "a" character
    byte[] input = new byte[1] { 0x61 };

    SHA224 hasher = new();

    // Update million times
    for (int i = 0; i < 1000000; ++i)
    {
        hasher.Update(input);
    }

    string hash = Convert.ToHexString(hasher.Digest()).ToLower();

    if (hash != expected)
    {
        Console.WriteLine("Calculated: {0}", hash);
        Console.WriteLine("Expected: {0}", expected);
        throw new SystemException("Result \"" + hash.Substring(0, 16) + "...\" is not \"" + expected.Substring(0, 16) + "...\"");
    }
    Console.WriteLine("Okay");
}

static void Torture_256_1Million_a_iter()
{
    string expected = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
    Console.WriteLine("Torture SHA256 (1M \"a\" characters input iteratively) => {0} ...", expected.Substring(0, 16));

    // Input message to be repeated: single "a" character
    byte[] input = new byte[1] { 0x61 };

    SHA256 hasher = new();

    // Update million times
    for (int i = 0; i < 1000000; ++i)
    {
        hasher.Update(input);
    }

    string hash = Convert.ToHexString(hasher.Digest()).ToLower();

    if (hash != expected)
    {
        Console.WriteLine("Calculated: {0}", hash);
        Console.WriteLine("Expected: {0}", expected);
        throw new SystemException("Result \"" + hash.Substring(0, 16) + "...\" is not \"" + expected.Substring(0, 16) + "...\"");
    }
    Console.WriteLine("Okay");
}

static void Torture_512_1Million_a_iter()
{
    string expected = "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b";
    Console.WriteLine("Torture SHA512 (1M \"a\" characters input iteratively) => {0} ...", expected.Substring(0, 16));

    byte[] input = new byte[1000000];
    Array.Fill<byte>(input, 0x61);

    SHA512 hasher = new();
    hasher.Update(input);

    string hash = Convert.ToHexString(hasher.Digest()).ToLower();

    if (hash != expected)
    {
        Console.WriteLine("Calculated: {0}", hash);
        Console.WriteLine("Expected: {0}", expected);
        throw new SystemException("Result \"" + hash.Substring(0, 16) + "...\" is not \"" + expected.Substring(0, 16) + "...\"");
    }
    Console.WriteLine("Okay");
}

static void Torture_224_1Gigabyte()
{
    string pattern = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno";
    string expected = "b5989713ca4fe47a009f8621980b34e6d63ed3063b2a0a2c867d8a85";

    Console.WriteLine("Torture SHA224 (1G \"{0}\" repeated characters input) => {1} ...", pattern, expected.Substring(0, 16));

    // Input message: pattern to be repeated
    byte[] input = Encoding.ASCII.GetBytes(pattern);

    SHA224 hasher = new();

    // Repeat sequence 16,777,216 times
    for (int i = 0; i < 16777216; ++i)
    {
        hasher.Update(input);
    }

    string hash = Convert.ToHexString(hasher.Digest()).ToLower();

    if (hash != expected)
    {
        Console.WriteLine("Calculated: {0}", hash);
        Console.WriteLine("Expected: {0}", expected);
        throw new SystemException("Result \"" + hash.Substring(0, 16) + "...\" is not \"" + expected.Substring(0, 16) + "...\"");
    }
    Console.WriteLine("Okay");
}

static void Torture_256_1Gigabyte()
{
    string pattern = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno";
    string expected = "50e72a0e26442fe2552dc3938ac58658228c0cbfb1d2ca872ae435266fcd055e";

    Console.WriteLine("Torture SHA256 (1G \"{0}\" repeated characters input) => {1} ...", pattern, expected.Substring(0, 16));

    // Input message: pattern to be repeated
    byte[] input = Encoding.ASCII.GetBytes(pattern);

    SHA256 hasher = new();

    // Repeat sequence 16,777,216 times
    for (int i = 0; i < 16777216; ++i)
    {
        hasher.Update(input);
    }

    string hash = Convert.ToHexString(hasher.Digest()).ToLower();

    if (hash != expected)
    {
        Console.WriteLine("Calculated: {0}", hash);
        Console.WriteLine("Expected: {0}", expected);
        throw new SystemException("Result \"" + hash.Substring(0, 16) + "...\" is not \"" + expected.Substring(0, 16) + "...\"");
    }
    Console.WriteLine("Okay");
}

static void Torture_512_1Gigabyte()
{
    string pattern = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno";
    string expected = "b47c933421ea2db149ad6e10fce6c7f93d0752380180ffd7f4629a712134831d77be6091b819ed352c2967a2e2d4fa5050723c9630691f1a05a7281dbe6c1086";

    Console.WriteLine("Torture SHA512 (1G \"{0}\" repeated characters input) => {1} ...", pattern, expected.Substring(0, 16));

    // Input message: pattern to be repeated
    byte[] input = Encoding.ASCII.GetBytes(pattern);

    SHA512 hasher = new();

    // Repeat sequence 16,777,216 times
    for (int i = 0; i < 16777216; ++i)
    {
        hasher.Update(input);
    }

    string hash = Convert.ToHexString(hasher.Digest()).ToLower();

    if (hash != expected)
    {
        Console.WriteLine("Calculated: {0}", hash);
        Console.WriteLine("Expected: {0}", expected);
        throw new SystemException("Result \"" + hash.Substring(0, 16) + "...\" is not \"" + expected.Substring(0, 16) + "...\"");
    }
    Console.WriteLine("Okay");
}

// Perverted tests
Torture_224_1Million_a_once();
Torture_256_1Million_a_once();
Torture_512_1Million_a_once();
Torture_224_1Million_a_iter();
Torture_256_1Million_a_iter();
Torture_512_1Million_a_iter();
Torture_224_1Gigabyte();
Torture_256_1Gigabyte();
Torture_512_1Gigabyte();
