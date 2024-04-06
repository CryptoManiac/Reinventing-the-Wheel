using System.Text;
using Wheel.Crypto.Elliptic.EdDSA;
using Wheel.Hashing.HMAC;
using Wheel.Hashing.HMAC.SHA2;
using Wheel.Hashing.SHA.SHA256;

string message = "aaa";

// Should give these results:
// Ed25519 private key: 988223833DB8B9C92AB4DEF4C1397161FC370554DD0E8740E70CCCEB9E2DC049
// Ed25519 public key: C6DD35511FA2D07EC24F9CF77417399A9B66FF905D619184197191D71340E5FF
string secret_seed = "The quick brown fox jumps over the lazy dog";
string personalization = "For signing tests";
int secret_key_number = 0;

// Must be valid, check here: https://cyphr.me/ed25519_tool/ed.html (select Ed25519 algorithm and use SHA256 hash of "aaa" as the data)
SortedDictionary<string, string> compactVectors = new()
{
    {  "HMAC_SHA224", "4B01B36263A10305A4E4ED9165129F436A6911BF432B055D394B2EDA807B0D08B1E26ED6956FB204CFF67978838F20838FC754970671B60E3F0762C5DD9DCB07"},
    {  "HMAC_SHA256", "77319BCE8C22D92829EB4BF0B4AB77CD681E25D4890847548B260F1447C21F96554126B05C7CC8798BB1CABDE9322FE9EFC7E430C417AB4692E3553156648103"},
    {  "HMAC_SHA512", "4998FED64D7427AAA04AD23446809514D11180AFDD8FB9E082C6625F3E82C2792752BE4424F0BEA584C0CF38EC3460355579EFE8F41C7244CD57666E3332420D"},
};

SortedDictionary<string, string> derVectors = new()
{
    {  "HMAC_SHA224", "304502204B01B36263A10305A4E4ED9165129F436A6911BF432B055D394B2EDA807B0D08022100B1E26ED6956FB204CFF67978838F20838FC754970671B60E3F0762C5DD9DCB07"},
    {  "HMAC_SHA256", "3044022077319BCE8C22D92829EB4BF0B4AB77CD681E25D4890847548B260F1447C21F960220554126B05C7CC8798BB1CABDE9322FE9EFC7E430C417AB4692E3553156648103"},
    {  "HMAC_SHA512", "304402204998FED64D7427AAA04AD23446809514D11180AFDD8FB9E082C6625F3E82C27902202752BE4424F0BEA584C0CF38EC3460355579EFE8F41C7244CD57666E3332420D"},
};

static byte[] GetSigningHash(string message)
{
    byte[] message_hash = new byte[32];
    SHA256.Hash(message_hash, Encoding.ASCII.GetBytes(message));
    return message_hash;
}

static int SignCompact<HMAC_IMPL>(Span<byte> signature, EdPrivateKey sk, Span<byte> message_hash, EdCurve curve) where HMAC_IMPL : unmanaged, IMac
{
    if (!sk.SignDeterministic<HMAC_IMPL>(out CompactSignature cmpSig, message_hash))
    {
        throw new SystemException("Signing failed");
    }

    int encodedSz = cmpSig.Encode(signature);
    if (encodedSz > signature.Length)
    {
        throw new Exception("Signature buffer is too short");
    }

    return encodedSz;
}

static int SignDER<HMAC_IMPL>(Span<byte> signature, EdPrivateKey sk, Span<byte> message_hash, EdCurve curve) where HMAC_IMPL : unmanaged, IMac
{
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

static int SignNonDeterministicCompact(Span<byte> signature, EdPrivateKey sk, Span<byte> message_hash, EdCurve curve)
{
    if (!sk.Sign(out CompactSignature cmpSig, message_hash))
    {
        throw new SystemException("Signing failed");
    }

    int encodedSz = cmpSig.Encode(signature);
    if (encodedSz > signature.Length)
    {
        throw new Exception("Signature buffer is too short");
    }

    return encodedSz;
}

static int SignNonDeterministicDER(Span<byte> signature, EdPrivateKey sk, Span<byte> message_hash, EdCurve curve)
{
    if (!sk.Sign(out DERSignature derSig, message_hash))
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
static bool VerifySigCompact(ReadOnlySpan<byte> signature, Span<byte> message_hash, ReadOnlySpan<byte> public_key, EdCurve curve)
{
    return new EdPublicKey(curve, public_key).VerifySignature(new CompactSignature(curve, signature), message_hash);
}

static bool VerifySigDER(ReadOnlySpan<byte> signature, Span<byte> message_hash, ReadOnlySpan<byte> public_key, EdCurve curve)
{
    return new EdPublicKey(curve, public_key).VerifySignature(new DERSignature(curve, signature), message_hash);
}

void CompareSig(string algorithm, Span<byte> signature, SortedDictionary<string, string> vectors)
{
    var oldColour = Console.ForegroundColor;
    string signatureHex = Convert.ToHexString(signature);
    string expectedHex = vectors[algorithm];
    bool isOk = expectedHex == signatureHex;

    Console.ForegroundColor = isOk ? ConsoleColor.Green : ConsoleColor.Red;
    Console.WriteLine("{0}: {1} {2}", algorithm, signatureHex, isOk ? "OK" : expectedHex);
    Console.ForegroundColor = oldColour;
}

EdCurve curve = EdCurve.Get_EdCurve_SHA2();

// Derive new secret key
curve.GenerateDeterministicSecret<HMAC_SHA512>(out EdPrivateKey secretKey, Encoding.ASCII.GetBytes(secret_seed), Encoding.ASCII.GetBytes(personalization), secret_key_number);

if (!secretKey.ComputePublicKey(out EdPublicKey publicKey))
{
    throw new SystemException("Computation of the public key has failed");
}

Span<byte> secret_key = stackalloc byte[curve.PrivateKeySize];
Span<byte> public_key = stackalloc byte[curve.CompressedPublicKeySize];

if (!secretKey.Serialize(secret_key))
{
    throw new SystemException("Serialization of the secret key has failed");
}

if (!publicKey.Compress(public_key))
{
    throw new SystemException("Compression of the public key has failed");
}

Span<byte> message_hash = GetSigningHash(message);

Console.WriteLine("ED25519 private key: {0}", Convert.ToHexString(secret_key));
Console.WriteLine("ED25519 public key: {0}", Convert.ToHexString(public_key));
Console.WriteLine("Message to sign: {0}", message);
Console.WriteLine("Message hash to be signed: {0}", Convert.ToHexString(message_hash));

Span<byte> signature_compact = stackalloc byte[curve.CompactSignatureSize];
Span<byte> signature_der = stackalloc byte[curve.DERSignatureSize];

Console.WriteLine("Deterministic ED25519 compact signatures:");

int sha224SigSz = SignCompact<HMAC_SHA224>(signature_compact, secretKey, message_hash, curve);

if (!VerifySigCompact(signature_compact, message_hash, public_key, curve))
{
    throw new SystemException("Signature verification failure");
}

CompareSig("HMAC_SHA224", signature_compact.Slice(0, sha224SigSz), compactVectors);

int sha256SigSz = SignCompact<HMAC_SHA256>(signature_compact, secretKey, message_hash, curve);

if (!VerifySigCompact(signature_compact, message_hash, public_key, curve))
{
    throw new SystemException("Signature verification failure");
}

CompareSig("HMAC_SHA256", signature_compact.Slice(0, sha256SigSz), compactVectors);

int sha512SigSz = SignCompact<HMAC_SHA512>(signature_compact, secretKey, message_hash, curve);

if (!VerifySigCompact(signature_compact, message_hash, public_key, curve))
{
    throw new SystemException("Signature verification failure");
}

CompareSig("HMAC_SHA512", signature_compact.Slice(0, sha512SigSz), compactVectors);

Console.WriteLine("Deterministic ED25519 DER signatures:");

int sha224DERSigSz = SignDER<HMAC_SHA224>(signature_der, secretKey, message_hash, curve);

if (!VerifySigDER(signature_der, message_hash, public_key, curve))
{
    throw new SystemException("Signature verification failure");
}

CompareSig("HMAC_SHA224", signature_der.Slice(0, sha224DERSigSz), derVectors);

int sha256DERSigSz = SignDER<HMAC_SHA256>(signature_der, secretKey, message_hash, curve);

if (!VerifySigDER(signature_der, message_hash, public_key, curve))
{
    throw new SystemException("Signature verification failure");
}

CompareSig("HMAC_SHA256", signature_der.Slice(0, sha256DERSigSz), derVectors);

int sha512DERSigSz = SignDER<HMAC_SHA512>(signature_der, secretKey, message_hash, curve);

if (!VerifySigDER(signature_der, message_hash, public_key, curve))
{
    throw new SystemException("Signature verification failure");
}

CompareSig("HMAC_SHA512", signature_der.Slice(0, sha512DERSigSz), derVectors);

Console.WriteLine("Non-deterministic compact signing tests:");

int try1SigSz = SignNonDeterministicCompact(signature_compact, secretKey, message_hash, curve);
Console.Write(Convert.ToHexString(signature_compact.Slice(0, try1SigSz)));

if (!VerifySigCompact(signature_compact, message_hash, public_key, curve))
{
    throw new SystemException("Signature verification failure");
}
Console.WriteLine(" OK");

int try2SigSz = SignNonDeterministicCompact(signature_compact, secretKey, message_hash, curve);
Console.Write(Convert.ToHexString(signature_compact.Slice(0, try2SigSz)));

if (!VerifySigCompact(signature_compact, message_hash, public_key, curve))
{
    throw new SystemException("Signature verification failure");
}
Console.WriteLine(" OK");

int try3SigSz = SignNonDeterministicCompact(signature_compact, secretKey, message_hash, curve);
Console.Write(Convert.ToHexString(signature_compact.Slice(0, try3SigSz)));

if (!VerifySigCompact(signature_compact, message_hash, public_key, curve))
{
    throw new SystemException("Signature verification failure");
}
Console.WriteLine(" OK");

Console.WriteLine("Non-deterministic DER signing tests:");

int derTry1 = SignNonDeterministicDER(signature_der, secretKey, message_hash, curve);
Console.Write(Convert.ToHexString(signature_der.Slice(0, derTry1)));

if (!VerifySigDER(signature_der, message_hash, public_key, curve))
{
    throw new SystemException("Signature verification failure");
}
Console.WriteLine(" OK");

int derTry2 = SignNonDeterministicDER(signature_der, secretKey, message_hash, curve);
Console.Write(Convert.ToHexString(signature_der.Slice(0, derTry2)));

if (!VerifySigDER(signature_der, message_hash, public_key, curve))
{
    throw new SystemException("Signature verification failure");
}
Console.WriteLine(" OK");

int derTry3 = SignNonDeterministicDER(signature_der, secretKey, message_hash, curve);
Console.Write(Convert.ToHexString(signature_der.Slice(0, derTry3)));

if (!VerifySigDER(signature_der, message_hash, public_key, curve))
{
    throw new SystemException("Signature verification failure");
}
Console.WriteLine(" OK");

