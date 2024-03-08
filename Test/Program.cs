
using System.Text;
using Wheel.Crypto.Primitives;
using Wheel.Crypto.RIPEMD;
using Wheel.Crypto.SHA;

static string CalculateHash(string input, IHasher hasher)
{
    byte[] data = Encoding.ASCII.GetBytes(input);
    hasher.Update(data);
    return Convert.ToHexString(
        hasher.Digest()
    ).ToLower();
}

SortedDictionary<string, Func<IHasher>> algorithms = new()
{
    { "RIPEMD160", () => new RIPEMD160() },
    { "SHA224", () => new SHA224() },
    { "SHA256", () => new SHA256() },
    { "SHA512_224", () => new SHA512_224() },
    { "SHA512_256", () => new SHA512_256() },
    { "SHA384", () => new SHA384() },
    { "SHA512", () => new SHA512() },
};

SortedDictionary<string, SortedDictionary<string, string>> vectors = new()
{
    {
        "", new(){
            { "RIPEMD160", "9c1185a5c5e9fc54612808977ee8f548b2258d31" },
            { "SHA224", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f" },
            { "SHA256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
            { "SHA512_224", "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4" },
            { "SHA512_256", "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a" },
            { "SHA384", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" },
            { "SHA512", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" },
        }
    },
    {
        "abc", new(){
            { "RIPEMD160", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc" },
            { "SHA224", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" },
            { "SHA256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
            { "SHA512_224", "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa" },
            { "SHA512_256", "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23" },
            { "SHA384", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7" },
            { "SHA512", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
        }
    },
    {
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", new(){
            { "RIPEMD160", "12a053384a9c0c88e405a06c27dcf49ada62eb2b" },
            { "SHA224", "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525" },
            { "SHA256", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
            { "SHA512_224", "e5302d6d54bb242275d1e7622d68df6eb02dedd13f564c13dbda2174" },
            { "SHA512_256", "bde8e1f9f19bb9fd3406c90ec6bc47bd36d8ada9f11880dbc8a22a7078b6a461" },
            { "SHA384", "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b" },
            { "SHA512", "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445" },
        }
    },
    {
        "The quick brown fox jumps over the lazy dog", new(){
            { "RIPEMD160", "37f332f68db77bd9d7edd4969571ad671cf9dd3b" },
            { "SHA224", "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525" },
            { "SHA256", "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592" },
            { "SHA512_224", "944cd2847fb54558d4775db0485a50003111c8e5daa63fe722c6aa37" },
            { "SHA512_256", "dd9d67b371519c339ed8dbd25af90e976a1eeefd4ad3d889005e532fc5bef04d" },
            { "SHA384", "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1" },
            { "SHA512", "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6" },
        }
    },
    {
        "The quick brown fox jumps over the lazy cog", new(){
            { "RIPEMD160", "132072df690933835eb8b6ad0b77e7b6f14acad7" },
            { "SHA224", "fee755f44a55f20fb3362cdc3c493615b3cb574ed95ce610ee5b1e9b" },
            { "SHA256", "e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be" },
            { "SHA512_224", "2b9d6565a7e40f780ba8ab7c8dcf41e3ed3b77997f4c55aa987eede5" },
            { "SHA512_256", "cc8d255a7f2f38fd50388fd1f65ea7910835c5c1e73da46fba01ea50d5dd76fb" },
            { "SHA384", "098cea620b0978caa5f0befba6ddcf22764bea977e1c70b3483edfdf1de25f4b40d6cea3cadf00f809d422feb1f0161b" },
            { "SHA512", "3eeee1d0e11733ef152a6c29503b3ae20c4f1f3cda4cb26f1bc1a41f91c7fe4ab3bd86494049e201c4bd5155f31ecb7a3c8606843c4cc8dfcab7da11c8ae5045" },
        }
    },
    {
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", new(){
            { "RIPEMD160", "6f3fa39b6b503c384f919a49a7aa5c2c08bdfb45" },
            { "SHA224", "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3" },
            { "SHA256", "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1" },
            { "SHA512_224", "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9" },
            { "SHA512_256", "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a" },
            { "SHA384", "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039" },
            { "SHA512", "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909" },
        }
    },
};

static void CompareWithExpected(string expected, string calculated)
{
    var oldColour = Console.ForegroundColor;

    if (expected != calculated)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write("BAD");
        Console.ForegroundColor = oldColour;
        Console.WriteLine(" {0} is not {1}", calculated, expected);
        return;
    }

    Console.ForegroundColor = ConsoleColor.Green;
    Console.Write("OK");
    Console.ForegroundColor = oldColour;
    Console.Write(" {0}\n", calculated);
}

static void PrintUnknown(string calculated)
{
    var oldColour = Console.ForegroundColor;
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.Write("???");
    Console.ForegroundColor = oldColour;
    Console.Write(" {0}\n", calculated);
}

// Iterate through vector data to get algorithm
//  associations and test them
foreach (var (input, expectations) in vectors)
{
    Console.WriteLine("\nInput: \"{0}\" ({1} bytes)\n", input, input.Length);

    foreach (var (name, algorithm) in algorithms)
    {
        Console.Write("{0} ", name);

        var calculated = CalculateHash(input, algorithm());

        if (expectations.ContainsKey(name))
        {
            CompareWithExpected(expectations[name], calculated);
        }
        else
        {
            PrintUnknown(calculated);
        }
    }
}
