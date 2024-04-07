using System.Text;
using Hashing.Hashing.HMAC;
using Wheel.Crypto.Elliptic.ECDSA;
using Wheel.Crypto.Elliptic.EllipticCommon;
using Wheel.Hashing.HMAC;
using Wheel.Hashing.SHA.SHA256;
using Wheel.Hashing.SHA.SHA512;

string message = "aaa";

// Should give these results:
// SECP384R1 private key: DB395A4721E3698864A50BBDBC5D12EFDE180237713AC2A692E4349FDBBC09E09E3465AA7E8E400D3D94B22585567C2D
// SECP384R1 public key: 04A5E9AA03A743A12496DBA968846A6FD3F98E329898359E0DF691EC5961467E0149B16B5080FEAF8BFECEF6D30D2CE7AF8D4C9A100CE2E191CFEFE1194C0D5BB736459EABC9243C3A93A06698E202251171468D60522463886E6077802EF35463
// SECP384R1 compressed public key: 03A5E9AA03A743A12496DBA968846A6FD3F98E329898359E0DF691EC5961467E0149B16B5080FEAF8BFECEF6D30D2CE7AF
string secret_seed = "The quick brown fox jumps over the lazy dog";
string personalization = "For signing tests";
int secret_key_number = 0;

// Must be valid, check here: http://kjur.github.io/jsrsasign/sample/sample-ecdsa.html (select SECP384R1 curve and SHA256withECDSA algorithm)
SortedDictionary<string, string> vectors = new()
{
    {  "HMAC_SHA224", "3065023100FDB2598347BE0661B4C1D2CD2779037D46AF97D58C2C77448A84B4BCB5DD47B959A7E3EB56841604832A3746C044AE9C023061DD8F96763AF15FA43DA9BC757C5C31FF087739AA9480FB19D8CA50E2B0C3F4193E93D4C2FA155358D28029CDB597EC"},
    {  "HMAC_SHA256", "3065023100E90FBAC0551E966DDD425F1D28D235B2F35828F02D76C9B5EF506875147E5A5E9F678B9A6563B0D02354FFA363DF5A1C02300EC39DC69FF528AF886C416B01E7F8B6432D3C7B17FFC9355CCBF963523C3529FE7874494CDE74012173D2497767EBEF"},
    {  "HMAC_SHA512", "306402303FBA712FE61C705B81CD5075BE5E16E27DCB26671499AB72BB6604F24D0E4983FFD9C67A912529F22B8E0B7AAB1E756E02303EABFFF8F406399ACEDB4AB68184B7E1B12E5880D5FE3202CA3DE94F3DFBBC77FCCBDDB580CD6D1091B47E29E84EC56D"},
};

// Some signatures which have been made by this script: http://kjur.github.io/jsrsasign/sample/sample-ecdsa.html
List<string> signaturesToCheck = new()
{
    // Positive R and S
    "3064023040ce0e675695b2591506964328c913870c0abdcefd7b84e0e6b5bcc0bc203a6498b912244a61d3b4257a408c24257dba023066f7b2d7997c2c1659ec5d7e207323f651e4d90c6892aacb61170647fb8a4cf0f4f9246c250101687b1d1b212c3399e3",
    "30640230376a8ae396d1b3b53bc6d51b7498051dd02d296aa8dc522db2eeb426bdaa584f2ef532c6df1c8ffe5ae740af41c6b55402307c958e163221eaab98e2431602598396261bcb06f61a67703d93583ac28a068d100da73b51f73009e05dffc30a1a8676",
    "30640230126bed647639bbf641e795e3e13b746100d3023c911d81d144ee9183a4d2785c2f01074cb75252c6d05932391bb5b72402302d6391c0ef366dae2f572fd89cfba33c8c93c835135dac6666b49e1159be51699afe0d254200990ffbe297517286b0b1",
    "3064023019f3fdfb6751364e950c3c0ec5071cb34b29705628b77ffb663ea08fd17b9f033f55160f8b9bbae79bec29baa0b26cf102301adb5b205b6d2e8bef7c3332de996f7612aef3af85d9d83b1faea65b4d272de76eed920b051b40f5dc744c01afdb86e8",

    // Negarive R
    "3065023100ba1e5f0b1bb02327a30fd5b70f1a711662902230c86cc4577b9e65bb66d63de13b61b64684b1ae12d8e0c55b3b75cc6d02305bfbf93043d8fa304263a2a25f06f85fb9f49df2a3865f239d7c236c77e0db886f63dac0f7695ac240eb4d3583410b92",
    "3065023100c9cb94455619a07c0f56e7e506a126efe0b8b1bb1f82536b030563154449fc99fc43489effa93eac7104193e1616c7160230767c261ef57a96409fa8eee69a8e7b10d386019e346bf7678da0c7a9c1cc2627d7d6cca8eddc31f4b9a8f0ba63e1673a",
    "3065023100b2a28491e0cc99b0a662b62d92ecb01f83a4cb517e4e983959d1fdb85bf9c35c0cba31b9da02f14d28d3320c94854f560230013bbde9fc1e6da047e38e18a7f292fdf26b140d143c70c438db202d3cdc77b95e7e25eec632f47124baea65f5361434",
    "3065023100c3b8e2dae1ba825e72e5e3641875cd09cb262982086678df27725f106b997c229e6c045ab609443458a825b260a1389902303992c6bd0b9ad7999432058cd8d9657f972929b2fc7696df3b8dae7e6abac232fb8b6a0026d87bf3933dd3d8e33aeffd",

    // Negative S
    "306502307f144755beaa69fa192197658f2906d7274914a17a72ab1049b79f94bd987c3e7fce48a88ea3f0cc465e20cb373e07bf023100848c00c5c03e89016874771d23b828a85f206f6bea1d82232b19c8836ccf52a128485ad219e73d35e92408b6b47a4039",
    "306502306eae177a090b287c58089b1a6454e0fdfbe02acddb32ab29e4d71f85da6e9df4b76b61823f5e64a95f02316f6788c2c3023100833bb6689f640230f114f92856a9f4a3b5612fb138a4ddbbe6425566637405008775f0885170fb4b48e25b9dafb21c55",
    "3065023027b7013d97f88d6cffd16822cda55c52469b29bd288b59ee0c457d3ce366b78b3fe9ea22650192a0108e6b106ba5f922023100b93e0d8f4e570d9d6531bd7cd54c7f4af6c5c16357c7b09fcb14a822af8e1d72f57e4e4ed947df0cc2d01a648b83a509",
    "306502307ec71ed10a3479d4ea0bba51ee88acd40480aadf3aa1a725f33f5eb70d778208cc528b0a4b49305bda845bc2ae05a75a023100ccde7a0ca1e654f38200b3b7b3e25c8d1f402dfe542f507e896bcddea75f0461f41e59c2d1432cde6a9797d5051c26a0",

    // Negative R and S
    "306602310091d55aae41719d4adf3cec696b7c0dfe64df7783a87bd714e60a348cf6d9f0a96a9e70e625febf80d8e68076fde5f5ba023100a0cd87068bad8e651986cbc5bafaef2859328344b867201c26bb9e470fb2cd81794b238accc800f8ee5d44495eabafe5",
    "3066023100f023c44c731876c5ac5f8409bbb49206e8ffb16b5e4e6e652a9c36827d2a9be7ec993ce40f6ce78c7e0d6474f6e59dbd0231009b015a7d3ac0f5529c0668082961987884303493a9d718bc4eefce5f7a03a6ab8a675cdc3d970844a71de773a9d8be20",
    "3066023100ce63e3cc10f0b499d524f40bdd799a32a6e246b87051447626ec7ec9a2a8a405bf49a00999574079569e6651aaf0b851023100f171fbbc5ceb14272da1d5e6d90ecf4305cfd09de23a97de231094f82abd738b5965d83fb1ab5a42050b5c7f2a407f72",
    "3066023100cc33d7f349d7bc654d9d7c228a7ba40d309fc6a816238a7c0dc635ec688c698bede9ad5996713ba4b5fa57eb70b2dc000231009318b2c8f6af5f74b6fe7853cb8c83afa50f57ddc6de15ef17d981cd911fc4681adf6a9dfb13d6839e5dbb48b4049a51",
};

static int SignData<HMAC_IMPL>(Span<byte> signature, ECPrivateKey sk, string message, ECCurve curve) where HMAC_IMPL : unmanaged, IMac
{
    // Empty for tests
    Span<byte> message_hash = stackalloc byte[32];
    SHA256.Hash(message_hash, Encoding.ASCII.GetBytes(message));

    if (!sk.SignDeterministic<HMAC_IMPL>(out DERSignature derSig, message_hash))
    {
        throw new SystemException("Signing failed");
    }

    int encodedSz = derSig.Encode(signature);
    if (encodedSz > signature.Length)
    {
        throw new Exception("Signature buffer is too short");
    }

    return encodedSz;
}

static int SignDataNonDeterministic(Span<byte> signature, ECPrivateKey sk, string message, ECCurve curve)
{
    // Empty for tests
    Span<byte> message_hash = stackalloc byte[32];
    SHA256.Hash(message_hash, Encoding.ASCII.GetBytes(message));

    // Try signing until the signing will succeed
    DERSignature derSig;
    while (!sk.Sign(out derSig, message_hash)) ;

    int encodedSz = derSig.Encode(signature);
    if (encodedSz > signature.Length)
    {
        throw new Exception("Signature buffer is too short");
    }

    return encodedSz;
}

static bool VerifySignature(ReadOnlySpan<byte> signature, string message, ReadOnlySpan<byte> public_key, ECCurve curve)
{
    Span<byte> message_hash = stackalloc byte[32];
    SHA256.Hash(message_hash, Encoding.ASCII.GetBytes(message));
    return new ECPublicKey(curve, public_key).VerifySignature(new DERSignature(curve, signature), message_hash);
}

void CompareSig(string algorithm, Span<byte> signature)
{
    var oldColour = Console.ForegroundColor;
    string signatureHex = Convert.ToHexString(signature);
    string expectedHex = vectors[algorithm];
    bool isOk = expectedHex == signatureHex;

    Console.ForegroundColor = isOk ? ConsoleColor.Green : ConsoleColor.Red;
    Console.WriteLine("{0}: {1} {2}", algorithm, signatureHex, isOk ? "OK" : expectedHex);
    Console.ForegroundColor = oldColour;
}

ECCurve curve = ECCurve.Get_SECP384R1();

// Derive new secret key
curve.GenerateDeterministicSecret<HMAC<SHA512>>(out ECPrivateKey secretKey, Encoding.ASCII.GetBytes(secret_seed), Encoding.ASCII.GetBytes(personalization), secret_key_number);

if (!secretKey.ComputePublicKey(out ECPublicKey publicKey))
{
    throw new SystemException("Computation of the public key has failed");
}

Span<byte> secret_key = stackalloc byte[curve.PrivateKeySize];
Span<byte> public_key_uncompressed = stackalloc byte[curve.UncompressedPublicKeySize];
Span<byte> public_key_compressed = stackalloc byte[curve.CompressedPublicKeySize];

if (!secretKey.Serialize(secret_key))
{
    throw new SystemException("Serialization of the secret key has failed");
}

if (!publicKey.Compress(public_key_compressed))
{
    throw new SystemException("Compression of the public key has failed");
}

if (!publicKey.Serialize(public_key_uncompressed))
{
    throw new SystemException("Serialization of the public key has failed");
}

Console.WriteLine("SECP384R1 private key: {0}", Convert.ToHexString(secret_key));
Console.WriteLine("SECP384R1 private key entropy: {0}", Entropy.Estimate(secret_key));
Console.WriteLine("SECP384R1 public key: 04{0}", Convert.ToHexString(public_key_uncompressed));
Console.WriteLine("SECP384R1 compressed public key: {0}", Convert.ToHexString(public_key_compressed));
Console.WriteLine("Message to sign: {0}", message);

Span<byte> signature = stackalloc byte[curve.DERSignatureSize];

Console.WriteLine("Deterministic SECP384R1 signatures:");

int sha224SigSz = SignData<HMAC<SHA224>>(signature, secretKey, message, curve);

if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}

CompareSig("HMAC_SHA224", signature.Slice(0, sha224SigSz));

int sha256SigSz = SignData<HMAC<SHA256>>(signature, secretKey, message, curve);
if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}

CompareSig("HMAC_SHA256", signature.Slice(0, sha256SigSz));

int sha512SigSz = SignData<HMAC<SHA512>>(signature, secretKey, message, curve);

if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}

CompareSig("HMAC_SHA512", signature.Slice(0, sha512SigSz));

Console.WriteLine("DER decoding and verification tests:");
foreach (var sHex in signaturesToCheck)
{
    Console.Write(sHex);
    var testSig = Convert.FromHexString(sHex);
    if (!VerifySignature(testSig, message, public_key_uncompressed, curve))
    {
        throw new SystemException("Signature verification failure");
    }
    Console.WriteLine(" OK");
}

Console.WriteLine("Non-deterministic signing tests:");

int try1SigSz = SignDataNonDeterministic(signature, secretKey, message, curve);
Console.Write(Convert.ToHexString(signature.Slice(0, try1SigSz)));

if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}
Console.WriteLine(" OK");

int try2SigSz = SignDataNonDeterministic(signature, secretKey, message, curve);
Console.Write(Convert.ToHexString(signature.Slice(0, try2SigSz)));

if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}
Console.WriteLine(" OK");

int try3SigSz = SignDataNonDeterministic(signature, secretKey, message, curve);
Console.Write(Convert.ToHexString(signature.Slice(0, try3SigSz)));

if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}
Console.WriteLine(" OK");
