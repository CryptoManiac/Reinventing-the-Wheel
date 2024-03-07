
using System.Text;
using Wheel.Crypto.SHA;
using System.Collections.Generic;

public static class Test
{
    public static SortedDictionary<string, string> GetVectors256()
    {
        SortedDictionary<string, string> v = new()
        {
            {
                "", // Empty
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            },
            {
                "abc", // 24 bits
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            },
            {
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", // 448 bits
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
            },
            {
                "The quick brown fox jumps over the lazy dog",
                "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
            },
            {
                "The quick brown fox jumps over the lazy cog",
                "e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be"
            },
            {
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", // 896 bits
                "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
            }
        };
        return v;
    }

    public static SortedDictionary<string, string> GetVectors512()
    {
        SortedDictionary<string, string> v = new()
        {
            {
                "",  // Empty
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            },
            {
                "abc", // 24 bits
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            },
            {
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", // 448 bits
                "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"
            },
            {
                "The quick brown fox jumps over the lazy dog",
                "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"
            },
            {
                "The quick brown fox jumps over the lazy cog",
                "3eeee1d0e11733ef152a6c29503b3ae20c4f1f3cda4cb26f1bc1a41f91c7fe4ab3bd86494049e201c4bd5155f31ecb7a3c8606843c4cc8dfcab7da11c8ae5045"
            },
            {
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", // 896 bits
                "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
            }
        };
        return v;
    }

    public static string CalculateSHA256(string input) 
    {
        SHA256 hasher = new();
        byte[] data = Encoding.ASCII.GetBytes(input);
        hasher.Update(data);
        return Convert.ToHexString(
            hasher.Digest()
        ).ToLower();
    }

    public static string CalculateSHA512(string input)
    {
        SHA512 hasher = new();
        byte[] data = Encoding.ASCII.GetBytes(input);
        hasher.Update(data);
        return Convert.ToHexString(
            hasher.Digest()
        ).ToLower();
    }

    public static void Torture_256_1Million_a_once()
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

    public static void Torture_512_1Million_a_once()
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

    public static void Torture_256_1Million_a_iter()
    {
        string expected = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
        Console.WriteLine("Torture SHA256 (1M \"a\" characters input iteratively) => {0} ...", expected.Substring(0, 16));

        // Input message to be repeated: single "a" character
        byte[] input = new byte[1] {0x61};

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

    public static void Torture_512_1Million_a_iter()
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

    public static void Torture_256_1Gigabyte()
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

    public static void Torture_512_1Gigabyte()
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

    public static void Main()
    {
        // Test SHA256 and SHA512 against the provided vectors

        foreach(var entry in GetVectors256())
        {
            Console.WriteLine("Checking SHA256 \"{0}\" => {1}...", entry.Key, entry.Value.Substring(0, 16));

            string hash = CalculateSHA256(entry.Key);
            if (hash != entry.Value)
            {
                Console.WriteLine("Calculated: {0}", hash);
                Console.WriteLine("Expected: {0}", entry.Value);
                throw new SystemException("Result \"" + hash.Substring(0, 16) + "...\" is not \"" + entry.Value.Substring(0, 16) + "...\" for input \"" + entry.Key + "\"");
            }
            Console.WriteLine("Okay");
        }

        foreach (var entry in GetVectors512())
        {
            Console.WriteLine("Checking SHA512 \"{0}\" => {1}...", entry.Key, entry.Value.Substring(0, 16));

            string hash = CalculateSHA512(entry.Key);
            if (hash != entry.Value)
            {
                Console.WriteLine("Calculated: {0}", hash);
                Console.WriteLine("Expected: {0}", entry.Value);
                throw new SystemException("Result \"" + hash.Substring(0, 16) + "...\" is not \"" + entry.Value.Substring(0, 16) + "...\" for input \"" + entry.Key + "\"");
            }
            Console.WriteLine("Okay");
        }

        // Perverted cases
        Torture_256_1Million_a_once();
        Torture_512_1Million_a_once();
        Torture_256_1Million_a_iter();
        Torture_512_1Million_a_iter();
        Torture_256_1Gigabyte();
        Torture_512_1Gigabyte();
    }
}


/*
byte[] hash1 = new byte[32];
SHA256 hasher1 = new();
hasher1.Update(new byte[66]);
hasher1.Digest(ref hash1);
Console.WriteLine("{0}", Convert.ToHexString(hash1));
hasher1.Reset();
hasher1.Update(new byte[32] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 });
hasher1.Digest(ref hash1);
Console.WriteLine("{0}", Convert.ToHexString(hash1));

byte[] hash2 = new byte[64];
SHA512 hasher2 = new();
hasher2.Update(new byte[66]);
hasher2.Digest(ref hash2);
Console.WriteLine("{0}", Convert.ToHexString(hash2));
hasher2.Reset();
hasher2.Update(new byte[32] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 });
hasher2.Digest(ref hash2);
Console.WriteLine("{0}", Convert.ToHexString(hash2));
*/