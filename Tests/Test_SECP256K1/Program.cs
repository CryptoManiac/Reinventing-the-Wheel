using System.Text;
using Wheel.Crypto.Elliptic;
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
    {  "HMAC_SHA224", "30440220D1EBC8275D9968755C3D115807F2E716E09F14FAC22C97158B5FCBF5ABA998120220FEB054F457813B7B89F99FB5ACF945827D8458D7C5729587E12406B4FEED3017"},
    {  "HMAC_SHA256", "30440220BA782410D7A5EC5A1AF77D53E80228364FCDF290B032A5BBFF75E6D06904DB940220587E3837243080A75A50BA3EE374B807ED79A4557BD5FC3FA007727431BE18D8"},
    {  "HMAC_SHA512", "30440220BFDA6D25CCE288D1A2A910813B8AEEC2042AD4CE6FF87841D716502BCC8305F10220A73E717C7BEC5B3B96F7534641A58748B1A4DE4FC2CD62063B25C7B15CA273F7"},
};

static void SignData<HMAC_IMPL>(Span<byte> signature, ECPrivateKey sk, string message, ECCurve curve) where HMAC_IMPL : unmanaged, IMac
{
    // Empty for tests
    Span<byte> message_hash = stackalloc byte[32];
    SHA256.Hash(message_hash, Encoding.ASCII.GetBytes(message));

    if (!sk.Sign<HMAC_IMPL, DERSignature>(out DERSignature derSig, message_hash))
    {
        throw new SystemException("Signing failed");
    }

    if (signature.Length < derSig.Encode(signature))
    {
        throw new Exception("Signature buffer is too short");
    }
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

ECCurve curve = ECCurve.Get_SECP256K1();

// Derive new secret key
curve.GenerateSecret<HMAC_SHA512>(out ECPrivateKey secretKey, Encoding.ASCII.GetBytes(secret_seed), Encoding.ASCII.GetBytes(personalization), secret_key_number);

if (!secretKey.ComputePublicKey(out ECPublicKey publicKey))
{
    throw new SystemException("Computation of the public key has failed");
}

Span<byte> secret_key = stackalloc byte[32];
Span<byte> public_key_uncompressed = stackalloc byte[64];
Span<byte> public_key_compressed = stackalloc byte[33];

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

Span<byte> signature = stackalloc byte[70];

Console.WriteLine("Generated SECP256K1 signatures:");

SignData<HMAC_SHA224>(signature, secretKey, message, curve);

if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}

CompareSig("HMAC_SHA224", signature);

SignData<HMAC_SHA256>(signature, secretKey, message, curve);
if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}

CompareSig("HMAC_SHA256", signature);


SignData<HMAC_SHA512>(signature, secretKey, message, curve);

if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}

CompareSig("HMAC_SHA512", signature);

