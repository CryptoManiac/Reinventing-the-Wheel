using System.Text;
using Wheel.Crypto.Hashing.RIPEMD;
using Wheel.Crypto.Hashing.SHA.SHA256;
using Wheel.Crypto.Hashing.SHA.SHA512;
using Wheel.Crypto.Hashing;
using Wheel.Crypto.Hashing.SHA3;
using Wheel.Crypto.Hashing.HMAC;
using Wheel.Crypto.Hashing.HMAC.SHA2;

static string CalculateHash(string input, IHasher hasher)
{
    byte[] data = Encoding.ASCII.GetBytes(input);
    hasher.Update(data);
    return Convert.ToHexString(
        hasher.Digest()
    ).ToLower();
}

static string CalculateHMAC(string key, string message, int mac_length, Func<byte[], IMac> algorithm)
{
    byte[] pw = Encoding.ASCII.GetBytes(key);
    byte[] data = Encoding.ASCII.GetBytes(message);

    IMac hasher = algorithm(pw);
    hasher.Update(data);

    Span<byte> mac = stackalloc byte[mac_length == 0 ? hasher.HashSz : mac_length];
    hasher.Digest(mac);
    return Convert.ToHexString(mac).ToLower();
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
    { "SHA3_256", () => new SHA3_256() },
    { "SHA3_384", () => new SHA3_384() },
    { "SHA3_512", () => new SHA3_512() },
    { "Keccak_256", () => new Keccak_256() },
    { "Keccak_384", () => new Keccak_384() },
    { "Keccak_512", () => new Keccak_512() },
};

SortedDictionary<string, Func<byte[], IMac>> mac_algorithms = new()
{
    { "HMAC_SHA224", (byte[] pw) => new HMAC_SHA224(pw) },
    { "HMAC_SHA256", (byte[] pw) => new HMAC_SHA256(pw) },
    { "HMAC_SHA384", (byte[] pw) => new HMAC_SHA512_384(pw) },
    { "HMAC_SHA512", (byte[] pw) => new HMAC_SHA512(pw) },
};

Tuple<string, string, int>[] mac_messages = new Tuple<string, string, int>[7]
{
    new ( "\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v", "Hi There", 0 ),
    new ( "Jefe", "what do ya want for nothing?", 0 ),

    // Does not pass
    new ( "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd", 0 ),
    // Does not pass
    new ( "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19", "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd", 0 ),

    new ( "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c", "Test With Truncation", 16 ),
    new ( "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", "Test Using Larger Than Block-Size Key - Hash Key First", 0 ),
    new ( "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.", 0 ),
};

SortedDictionary<string, string[]> mac_vectors = new()
{
    {
        "HMAC_SHA224",
        new string[]
        {
            "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
            "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44",
            "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea",
            "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a",
            "0e2aea68a90c8d37c988bcdb9fca6fa8",
            "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e",
            "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1",
        }
    },
    {
        "HMAC_SHA256",
        new string[]
        {
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            "a3b6167473100ee06e0c796c2955552b",
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",

        }
    },
    {
        "HMAC_SHA384",
        new string[]
        {
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
            "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27",
            "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb",
            "3abf34c3503b2a23a46efc619baef897",
            "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
            "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e",
        }
    },
    {
        "HMAC_SHA512",
        new string[]
        {
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
            "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
            "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
            "415fad6271580a531d4179bc891d87a6",
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
            "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"
        }
    },
};

SortedDictionary<string, SortedDictionary<string, string>> hash_vectors = new()
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
            { "SHA3_256", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" },
            { "SHA3_384", "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004" },
            { "SHA3_512", "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26" },
            { "Keccak_256", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" },
            { "Keccak_384", "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff" },
            { "Keccak_512", "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e" },
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
            { "SHA3_256", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532" },
            { "SHA3_384", "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25" },
            { "SHA3_512", "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0" },
            { "Keccak_256", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45" },
            { "Keccak_384", "f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99f8c681e4afaf31a34db29fb763e3c28e" },
            { "Keccak_512", "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96" },
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
            { "SHA3_256", "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376" },
            { "SHA3_384", "991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22" },
            { "SHA3_512", "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e" },
            { "Keccak_256", "45d3b367a6904e6e8d502ee04999a7c27647f91fa845d456525fd352ae3d7371" },
            { "Keccak_384", "b41e8896428f1bcbb51e17abd6acc98052a3502e0d5bf7fa1af949b4d3c855e7c4dc2c390326b3f3e74c7b1e2b9a3657" },
            { "Keccak_512", "6aa6d3669597df6d5a007b00d09c20795b5c4218234e1698a944757a488ecdc09965435d97ca32c3cfed7201ff30e070cd947f1fc12b9d9214c467d342bcba5d" },
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
            { "SHA3_256", "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04" },
            { "SHA3_384", "7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41" },
            { "SHA3_512", "01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450" },
            { "Keccak_256", "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15" },
            { "Keccak_384", "283990fa9d5fb731d786c5bbee94ea4db4910f18c62c03d173fc0a5e494422e8a0b3da7574dae7fa0baf005e504063b3" },
            { "Keccak_512", "d135bb84d0439dbac432247ee573a23ea7d3c9deb2a968eb31d47c4fb45f1ef4422d6c531b5b9bd6f449ebcc449ea94d0a8f05f62130fda612da53c79659f609" },
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
            { "SHA3_256", "cc80b0b13ba89613d93f02ee7ccbe72ee26c6edfe577f22e63a1380221caedbc" },
            { "SHA3_384", "e414797403c7d01ab64b41e90df4165d59b7f147e4292ba2da336acba242fd651949eb1cfff7e9012e134b40981842e1" },
            { "SHA3_512", "28e361fe8c56e617caa56c28c7c36e5c13be552b77081be82b642f08bb7ef085b9a81910fe98269386b9aacfd2349076c9506126e198f6f6ad44c12017ca77b1" },
            { "Keccak_256", "ed6c07f044d7573cc53bf1276f8cba3dac497919597a45b4599c8f73e22aa334" },
            { "Keccak_384", "1cc515e1812491058d8b8b226fd85045e746b4937a58b0111b6b7a39dd431b6295bd6b6d05e01e225586b4dab3cbb87a" },
            { "Keccak_512", "10f8caabb5b179861da5e447d34b84d604e3eb81830880e1c2135ffc94580a47cb21f6243ec0053d58b1124d13af2090033659075ee718e0f111bb3f69fb24cf" },
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
            { "SHA3_256", "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18" },
            { "SHA3_384", "79407d3b5916b59c3e30b09822974791c313fb9ecc849e406f23592d04f625dc8c709b98b43b3852b337216179aa7fc7" },
            { "SHA3_512", "afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185" },
            { "Keccak_256", "f519747ed599024f3882238e5ab43960132572b7345fbeb9a90769dafd21ad67" },
            { "Keccak_384", "cc063f34685135368b34f7449108f6d10fa727b09d696ec5331771da46a923b6c34dbd1d4f77e595689c1f3800681c28" },
            { "Keccak_512", "ac2fb35251825d3aa48468a9948c0a91b8256f6d97d8fa4160faff2dd9dfcc24f3f1db7a983dad13d53439ccac0b37e24037e7b95f80f59f37a2f683c4ba4682" },
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
foreach (var (input, expectations) in hash_vectors)
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

/*
foreach(var (name, algorithm) in mac_algorithms )
{
    string[] vectors = mac_vectors[name];

    for (int i = 0; i < vectors.Length; ++i)
    {
        var (key, message, out_len) = mac_messages[i];
        string expected = vectors[i];
        string hmac = CalculateHMAC(key, message, out_len, algorithm);

        Console.WriteLine("Testing {0} with vector #{1}\nExpected: {2} got: {3}", name, i, expected, hmac);
    }

}*/