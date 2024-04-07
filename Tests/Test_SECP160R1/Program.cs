using System.Text;
using Hashing.Hashing.HMAC;
using Wheel.Crypto.Elliptic.ECDSA;
using Wheel.Crypto.Elliptic.EllipticCommon;
using Wheel.Hashing.HMAC;
using Wheel.Hashing.SHA.SHA256;
using Wheel.Hashing.SHA.SHA512;

string message = "aaa";

// Should give these results:
// SECP160R1 private key: 00F0D58A83B58E16142278FDD076070D969A958989
// SECP160R1 public key: 0400103346CA120480B2671E14C82AEBE8E64CB2DD40002B885B503445D96242BD01AD91C3CF8D35931A67
// SECP160R1 compressed public key: 0300103346CA120480B2671E14C82AEBE8E64CB2DD40
string secret_seed = "The quick brown fox jumps over the lazy dog";
string personalization = "For signing tests";
int secret_key_number = 0;

SortedDictionary<string, string> vectors = new()
{
    {  "HMAC_SHA224", "302E02150093066992E3B8BA8533013C87A93DDD6BD1D6B42202150020B1D1FEFE53696CB6338E5CF8B9745624307126"},
    {  "HMAC_SHA256", "302E021500FA7117B79213B9E24D3E402A58E77381B303924D02150014AF98513E9DEC867A3AD0D63F831F292B20122B"},
    {  "HMAC_SHA512", "302E021500F8813D59513113DE6CE1E2CA8907D9F3CFC6939B02150074E582076012CDC2E27467A23EF233799810997A"},
};

// TODO: Add test cases

List<string> signaturesToCheck = new()
{
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

ECCurve curve = ECCurve.Get_SECP160R1();

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

Console.WriteLine("SECP160R1 private key: {0}", Convert.ToHexString(secret_key));
Console.WriteLine("SECP160R1 public key: 04{0}", Convert.ToHexString(public_key_uncompressed));
Console.WriteLine("SECP160R1 compressed public key: {0}", Convert.ToHexString(public_key_compressed));
Console.WriteLine("Message to sign: {0}", message);

Span<byte> signature = stackalloc byte[curve.DERSignatureSize];

Console.WriteLine("Deterministic SECP160R1 signatures:");

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
