
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

    public static SortedDictionary<string, string> GetVectors512_256()
    {
        SortedDictionary<string, string> v = new()
        {
            {
                "", // Empty
                "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"
            },
            {
                "abc", // 24 bits
                "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
            },
            {
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", // 448 bits
                "bde8e1f9f19bb9fd3406c90ec6bc47bd36d8ada9f11880dbc8a22a7078b6a461"
            },
            {
                "The quick brown fox jumps over the lazy dog",
                "dd9d67b371519c339ed8dbd25af90e976a1eeefd4ad3d889005e532fc5bef04d"
            },
            {
                "The quick brown fox jumps over the lazy cog",
                "cc8d255a7f2f38fd50388fd1f65ea7910835c5c1e73da46fba01ea50d5dd76fb"
            },
            {
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", // 896 bits
                "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a"
            }
        };
        return v;
    }

    public static SortedDictionary<string, string> GetVectors224()
    {
        SortedDictionary<string, string> v = new()
        {
            {
                "", // Empty
                "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
            },
            {
                "abc", // 24 bits
                "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
            },
            {
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", // 448 bits
                "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"
            },
            {
                "The quick brown fox jumps over the lazy dog",
                "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525"
            },
            {
                "The quick brown fox jumps over the lazy cog",
                "fee755f44a55f20fb3362cdc3c493615b3cb574ed95ce610ee5b1e9b"
            },
            {
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", // 896 bits
                "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3"
            }
        };
        return v;
    }

    public static SortedDictionary<string, string> GetVectors512_224()
    {
        SortedDictionary<string, string> v = new()
        {
            {
                "", // Empty
                "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"
            },
            {
                "abc", // 24 bits
                "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"
            },
            {
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", // 448 bits
                "e5302d6d54bb242275d1e7622d68df6eb02dedd13f564c13dbda2174"
            },
            {
                "The quick brown fox jumps over the lazy dog",
                "944cd2847fb54558d4775db0485a50003111c8e5daa63fe722c6aa37"
            },
            {
                "The quick brown fox jumps over the lazy cog",
                "2b9d6565a7e40f780ba8ab7c8dcf41e3ed3b77997f4c55aa987eede5"
            },
            {
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", // 896 bits
                "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9"
            }
        };
        return v;
    }

    public static SortedDictionary<string, string> GetVectors384()
    {
        SortedDictionary<string, string> v = new()
        {
            {
                "", // Empty
                "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
            },
            {
                "abc", // 24 bits
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
            },
            {
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", // 448 bits
                "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b"
            },
            {
                "The quick brown fox jumps over the lazy dog",
                "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1"
            },
            {
                "The quick brown fox jumps over the lazy cog",
                "098cea620b0978caa5f0befba6ddcf22764bea977e1c70b3483edfdf1de25f4b40d6cea3cadf00f809d422feb1f0161b"
            },
            {
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", // 896 bits
                "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
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

    public static string CalculateSHA224(string input)
    {
        SHA224 hasher = new();
        byte[] data = Encoding.ASCII.GetBytes(input);
        hasher.Update(data);
        return Convert.ToHexString(
            hasher.Digest()
        ).ToLower();
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

    public static string CalculateSHA384(string input)
    {
        SHA384 hasher = new();
        byte[] data = Encoding.ASCII.GetBytes(input);
        hasher.Update(data);
        return Convert.ToHexString(
            hasher.Digest()
        ).ToLower();
    }

    public static string CalculateSHA512_256(string input)
    {
        SHA512_256 hasher = new();
        byte[] data = Encoding.ASCII.GetBytes(input);
        hasher.Update(data);
        return Convert.ToHexString(
            hasher.Digest()
        ).ToLower();
    }

    public static string CalculateSHA512_224(string input)
    {
        SHA512_224 hasher = new();
        byte[] data = Encoding.ASCII.GetBytes(input);
        hasher.Update(data);
        return Convert.ToHexString(
            hasher.Digest()
        ).ToLower();
    }

    public static void Torture_224_1Million_a_once()
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

    public static void Torture_224_1Million_a_iter()
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

    public static void Torture_256_1Million_a_iter()
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

    public static void Torture_224_1Gigabyte()
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
        // Test SHA224, SHA256 and SHA512 against the provided vectors
        foreach (var entry in GetVectors224())
        {
            Console.WriteLine("Checking SHA224 \"{0}\" => {1}...", entry.Key, entry.Value.Substring(0, 16));

            string hash = CalculateSHA224(entry.Key);
            if (hash != entry.Value)
            {
                Console.WriteLine("Calculated: {0}", hash);
                Console.WriteLine("Expected: {0}", entry.Value);
                throw new SystemException("Result \"" + hash.Substring(0, 16) + "...\" is not \"" + entry.Value.Substring(0, 16) + "...\" for input \"" + entry.Key + "\"");
            }
            Console.WriteLine("Okay");
        }

        foreach (var entry in GetVectors256())
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

        foreach (var entry in GetVectors384())
        {
            Console.WriteLine("Checking SHA384 \"{0}\" => {1}...", entry.Key, entry.Value.Substring(0, 16));

            string hash = CalculateSHA384(entry.Key);
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

        foreach (var entry in GetVectors512_224())
        {
            Console.WriteLine("Checking SHA512_224 \"{0}\" => {1}...", entry.Key, entry.Value.Substring(0, 16));

            string hash = CalculateSHA512_224(entry.Key);
            if (hash != entry.Value)
            {
                Console.WriteLine("Calculated: {0}", hash);
                Console.WriteLine("Expected: {0}", entry.Value);
                throw new SystemException("Result \"" + hash.Substring(0, 16) + "...\" is not \"" + entry.Value.Substring(0, 16) + "...\" for input \"" + entry.Key + "\"");
            }
            Console.WriteLine("Okay");
        }

        foreach (var entry in GetVectors512_256())
        {
            Console.WriteLine("Checking SHA512_256 \"{0}\" => {1}...", entry.Key, entry.Value.Substring(0, 16));

            string hash = CalculateSHA512_256(entry.Key);
            if (hash != entry.Value)
            {
                Console.WriteLine("Calculated: {0}", hash);
                Console.WriteLine("Expected: {0}", entry.Value);
                throw new SystemException("Result \"" + hash.Substring(0, 16) + "...\" is not \"" + entry.Value.Substring(0, 16) + "...\" for input \"" + entry.Key + "\"");
            }
            Console.WriteLine("Okay");
        }

        // Perverted cases
        Torture_224_1Million_a_once();
        Torture_256_1Million_a_once();
        Torture_512_1Million_a_once();
        Torture_224_1Million_a_iter();
        Torture_256_1Million_a_iter();
        Torture_512_1Million_a_iter();
        Torture_224_1Gigabyte();
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