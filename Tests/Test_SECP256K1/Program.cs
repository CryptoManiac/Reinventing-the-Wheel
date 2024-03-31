using System.Text;
using Wheel.Crypto.Elliptic.ECDSA;
using Wheel.Crypto.Elliptic.EllipticCommon;
using Wheel.Hashing.HMAC;
using Wheel.Hashing.HMAC.SHA2;
using Wheel.Hashing.SHA.SHA256;

string message = "aaa";

// Should give these results:
// SECP256K1 private key: DB395A4721E3698864A50BBDBC5D12EFDE180237713AC2A692E4349FDBBC09E0
// SECP256K1 public key: 048D61DED99E550773BB1E5A1E4E434D86ABD6BA218EF75F299A156956AEFFC626C33D8ED80692B9C209219BB95E8BB8A4116A35B04860415DAA79D8B4ED498584
// SECP256K1 compressed public key: 028D61DED99E550773BB1E5A1E4E434D86ABD6BA218EF75F299A156956AEFFC626
string secret_seed = "The quick brown fox jumps over the lazy dog";
string personalization = "For signing tests";
int secret_key_number = 0;

// Must be valid, check here: http://kjur.github.io/jsrsasign/sample/sample-ecdsa.html (select secp256k1 curve and SHA256withECDSA algorithm)
SortedDictionary<string, string> vectors = new()
{
    {  "HMAC_SHA224", "3046022100D1EBC8275D9968755C3D115807F2E716E09F14FAC22C97158B5FCBF5ABA99812022100FEB054F457813B7B89F99FB5ACF945827D8458D7C5729587E12406B4FEED3017"},
    {  "HMAC_SHA256", "3045022100BA782410D7A5EC5A1AF77D53E80228364FCDF290B032A5BBFF75E6D06904DB940220587E3837243080A75A50BA3EE374B807ED79A4557BD5FC3FA007727431BE18D8"},
    {  "HMAC_SHA512", "3046022100BFDA6D25CCE288D1A2A910813B8AEEC2042AD4CE6FF87841D716502BCC8305F1022100A73E717C7BEC5B3B96F7534641A58748B1A4DE4FC2CD62063B25C7B15CA273F7"},
};

// Some signatures which have been made by this script: http://kjur.github.io/jsrsasign/sample/sample-ecdsa.html
List<string> signaturesToCheck = new()
{
    // Both R and S are positive
    "304402201f514b59d14276eeb8375b00c291347c48159889abbaad8150e9f6867be0111e02205206b28e8a487e3c8a9916f7ce3002ce557de5acc9361505071036335c073758",
    "3044022038625ce36809169a52add0f6310f349b06a0a8b145ceac4359bd7aff9d822c0602207207e06d2aea8da43b679528e29f84cc88124766f366d976f3e2ba392c54a6d7",
    "3044022073eb2afa60084e81717cac8607104668ac883a6343f9eb368a5c8e45f08dbefe02207055cd1888e4bac112027164f5989f73994df532c11ba970edff74f7c9c3f687",
    "3044022014d7fbfc7dbd63655faed9badb050555016d52af04277b01d0b683eda28f181202207178d1b346d30fc1765989372b73547e85677215fcaa5fc0bc2e166cae26a255",

    // Negative R
    // Will fail
    "304502210098c9efb17292d9c58fa32ec342c424f67b790851c66aa87f81733d1c684d3b5d0220798acc27772346a39ed7b39fb9abc2ddc2bca708d603e4f49009edf6662e874e",
    "3045022100f9511c2776782c8ecd917b2d91ce68c3752fda9772ae86d4614553fe75a285b202201e4b9cd28ae8bed4dce711b10c920562eae6768bed118da015d2af793542acd0",
    "30450221008093f5a220311706fe5a238018566cb8318d5a113c4d2e5e4fbe3b241372e9f40220252dfe32ed6d1fcbf793c8e93d8ca412cdba6a2441895294134bb0d9f79b740a",
    "3045022100b9d83750e83f01aef0aac39d0c9c7b4e9a97aa5f4cced10023b61ae6beec3d2802204f241daf5bc4c68a7037b947f64a3235a5b2a2cb53799d429946b60397de9847",

    // Negative S
    "304502203d868162d435ac949d0d70a64b26672b85ed8b5de2511db8a87586a0d311d42e022100b9a4d58e6523981dc0053244a741a6f7fbf665990549f57651c9a4df3d053331",
    "30450220693bced671a32852fbe2d6b1e0ba442d821ca9992943a04982de671979ffa947022100c081defd190643cff4557f434632decbfea4e7463a31446e16a9e11c5b27ff0c",
    "304502200ec8de90a9a9f51fea4c964fb28f70a93c364b69b6d98ddcd77051ffa3310d4e022100aa927ae57838cd2abeb13e1ff0854c68cdaa08ef841c3cbfe0645fe40b02f46b",
    "304502206376efc78336a258ebe71cf430f5d49b6d06b553ac8c730fb8d94df1f76a6742022100ad0e653f85b1702beed81be3326c7d30b45c3dea3b76792d765f7b6c93dc1081",

    // Negative R and S
    "3046022100c6786cb035038c50cf28a6c88bf8fcf7eeca3f2deaece652eb3ee76cfa522c68022100aa34eb2ada770b8c3ba95af568a0ec55db2a46fc8dfc1700f46ed769af0402ec",
    "3046022100c8387475e234c46462eacd27d4fc82e044f2221f4ec3a256b2358acef5fd1e09022100ce6a7060cfb92ea938ca6d4c814cf613ac32ee78b8d0d91bc7b56e9e21da9fae",
    "3046022100bf78c448c27ea8771dad3725724bb156d3f25e566e20bda0e83dcc891844bed802210091cba4ad7570115118f711f29fc348978cca4bd3cf53fb00db029141b6e43a1f",
    "304602210099873660c7a6b326771161081f759575b391d0c6a91f4be719487c3d22750bef022100e39aee85a9b9d061fb28f6b5054967d3577f49014f9cba84d5925fc21c6be101",
};

static int SignData<HMAC_IMPL>(Span<byte> signature, IPrivateKey sk, string message, ECCurve curve) where HMAC_IMPL : unmanaged, IMac
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

static int SignDataNonDeterministic<HMAC_IMPL>(Span<byte> signature, IPrivateKey sk, string message, ICurve curve) where HMAC_IMPL : unmanaged, IMac
{
    // Empty for tests
    Span<byte> message_hash = stackalloc byte[32];
    SHA256.Hash(message_hash, Encoding.ASCII.GetBytes(message));

    // Try signing until the signing will succeed
    DERSignature derSig;
    while (!sk.Sign<HMAC_IMPL>(out derSig, message_hash)) ;

    int encodedSz = derSig.Encode(signature);
    if (encodedSz > signature.Length)
    {
        throw new Exception("Signature buffer is too short");
    }

    return encodedSz;
}

static bool VerifySignature(ReadOnlySpan<byte> signature, string message, ReadOnlySpan<byte> public_key, ICurve curve)
{
    Span<byte> message_hash = stackalloc byte[32];
    SHA256.Hash(message_hash, Encoding.ASCII.GetBytes(message));
    return curve.MakePublicKey(public_key).VerifySignature(new DERSignature(curve, signature), message_hash);
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

ECCurve curve = ECCurve.Get_SECP256K1();

// Derive new secret key
curve.GenerateDeterministicSecret<HMAC_SHA512>(out IPrivateKey secretKey, Encoding.ASCII.GetBytes(secret_seed), Encoding.ASCII.GetBytes(personalization), secret_key_number);

if (!secretKey.ComputePublicKey(out IPublicKey publicKey))
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

Console.WriteLine("SECP256K1 private key: {0}", Convert.ToHexString(secret_key));
Console.WriteLine("SECP256K1 public key: 04{0}", Convert.ToHexString(public_key_uncompressed));
Console.WriteLine("SECP256K1 compressed public key: {0}", Convert.ToHexString(public_key_compressed));
Console.WriteLine("Message to sign: {0}", message);

Span<byte> signature = stackalloc byte[curve.DERSignatureSize];

Console.WriteLine("Deterministic SECP256K1 signatures:");

int sha224SigSz = SignData<HMAC_SHA224>(signature, secretKey, message, curve);

if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}

CompareSig("HMAC_SHA224", signature.Slice(0, sha224SigSz));

int sha256SigSz = SignData<HMAC_SHA256>(signature, secretKey, message, curve);
if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}

CompareSig("HMAC_SHA256", signature.Slice(0, sha256SigSz));

int sha512SigSz = SignData<HMAC_SHA512>(signature, secretKey, message, curve);

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

sha224SigSz = SignDataNonDeterministic<HMAC_SHA224>(signature, secretKey, message, curve);
Console.Write("HMAC_SHA224: {0}", Convert.ToHexString(signature.Slice(0, sha224SigSz)));

if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}
Console.WriteLine(" OK");

sha256SigSz = SignDataNonDeterministic<HMAC_SHA256>(signature, secretKey, message, curve);
Console.Write("HMAC_SHA256: {0}", Convert.ToHexString(signature.Slice(0, sha256SigSz)));

if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}
Console.WriteLine(" OK");

sha512SigSz = SignDataNonDeterministic<HMAC_SHA512>(signature, secretKey, message, curve);
Console.Write("HMAC_SHA512: {0}", Convert.ToHexString(signature.Slice(0, sha512SigSz)));

if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}
Console.WriteLine(" OK");
