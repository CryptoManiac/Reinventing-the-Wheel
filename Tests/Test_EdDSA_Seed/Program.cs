using System.Text;
using Wheel.Crypto.Elliptic.EdDSA;
using Wheel.Hashing.HMAC;
using Wheel.Hashing.HMAC.SHA2;
using Wheel.Hashing.SHA.SHA256;

string message = "aaa";

// Should give these results:
// Ed25519 private key: 58B5968C488E2722C0E0F511F69BC72CDAE887CD879C6BC2CDEAD88DF6AA9869
// Ed25519 public key: 8262C50CE735D9234664BD1A90DB48BA1A23F01FC6453E82BFFA537CBEE1A1D1
string ed25519_seed = "A4E872FF25D9C8848825FADC9E0FB369E570F10075B7E20CEE2671AED3C1001A";

// Must be valid, check here: https://cyphr.me/ed25519_tool/ed.html (select Ed25519 algorithm and use SHA256 hash of "aaa" as the data)
SortedDictionary<string, string> compactVectors = new()
{
    {  "HMAC_SHA224", "6E662B8D23262B22A672CB8D7049B4F29A29058DE2722003295AB8FBE3C3BDD8C5663E34FDECC7EAFB88B8DA4251F4F0FC64F28DF17A83E115FEF2E0ABE5170A"},
    {  "HMAC_SHA256", "32ACEAB20FE72BB4C7FC37A6AB3E6DE2AF7F55E41237118B7E8AD5E19E23738475365DFB182889B114BDBDA9071686AF11169C6963277E156BDE4C89ACDD0606"},
    {  "HMAC_SHA512", "3B0B6B7D250790BEF64BF1C58468A6F73CC13531B10DB71228BA2F7529C69186A0393BB2D64A2E6B2368C4F1F98E1D0C217BB6AD48847DB0296B976CB9B83102"},
};

SortedDictionary<string, string> derVectors = new()
{
    {  "HMAC_SHA224", "304502206E662B8D23262B22A672CB8D7049B4F29A29058DE2722003295AB8FBE3C3BDD8022100C5663E34FDECC7EAFB88B8DA4251F4F0FC64F28DF17A83E115FEF2E0ABE5170A"},
    {  "HMAC_SHA256", "3044022032ACEAB20FE72BB4C7FC37A6AB3E6DE2AF7F55E41237118B7E8AD5E19E237384022075365DFB182889B114BDBDA9071686AF11169C6963277E156BDE4C89ACDD0606"},
    {  "HMAC_SHA512", "304502203B0B6B7D250790BEF64BF1C58468A6F73CC13531B10DB71228BA2F7529C69186022100A0393BB2D64A2E6B2368C4F1F98E1D0C217BB6AD48847DB0296B976CB9B83102"},
};

// Signature which has been made by this script: https://cyphr.me/ed25519_tool/ed.html
List<string> signaturesToCheck = new()
{
    "E59BC96F4513CC07DC327A7F04F2DFE092AC7A77AF2109279E25B49C1A46167D4B7C4612A498B7A83AF3639FBA8C5E829A13D7055F779ABD902CC93D6C9F960B",
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

static int SignNonDeterministicCompact<HMAC_IMPL>(Span<byte> signature, EdPrivateKey sk, Span<byte> message_hash, EdCurve curve) where HMAC_IMPL : unmanaged, IMac
{
    if (!sk.Sign<HMAC_IMPL>(out CompactSignature cmpSig, message_hash))
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

static int SignNonDeterministicDER<HMAC_IMPL>(Span<byte> signature, EdPrivateKey sk, Span<byte> message_hash, EdCurve curve) where HMAC_IMPL : unmanaged, IMac
{
    if (!sk.Sign<HMAC_IMPL>(out DERSignature derSig, message_hash))
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
curve.ExpandSeed(out EdPrivateKey secretKey, Convert.FromHexString(ed25519_seed));

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

Console.WriteLine("ED25519 seed: {0}", ed25519_seed);
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

sha224SigSz = SignNonDeterministicCompact<HMAC_SHA224>(signature_compact, secretKey, message_hash, curve);
Console.Write("HMAC_SHA224: {0}", Convert.ToHexString(signature_compact.Slice(0, sha224SigSz)));

if (!VerifySigCompact(signature_compact, message_hash, public_key, curve))
{
    throw new SystemException("Signature verification failure");
}
Console.WriteLine(" OK");

sha256SigSz = SignNonDeterministicCompact<HMAC_SHA256>(signature_compact, secretKey, message_hash, curve);
Console.Write("HMAC_SHA256: {0}", Convert.ToHexString(signature_compact.Slice(0, sha256SigSz)));

if (!VerifySigCompact(signature_compact, message_hash, public_key, curve))
{
    throw new SystemException("Signature verification failure");
}
Console.WriteLine(" OK");

sha512SigSz = SignNonDeterministicCompact<HMAC_SHA512>(signature_compact, secretKey, message_hash, curve);
Console.Write("HMAC_SHA512: {0}", Convert.ToHexString(signature_compact.Slice(0, sha512SigSz)));

if (!VerifySigCompact(signature_compact, message_hash, public_key, curve))
{
    throw new SystemException("Signature verification failure");
}
Console.WriteLine(" OK");

Console.WriteLine("Non-deterministic DER signing tests:");

sha224SigSz = SignNonDeterministicDER<HMAC_SHA224>(signature_der, secretKey, message_hash, curve);
Console.Write("HMAC_SHA224: {0}", Convert.ToHexString(signature_der.Slice(0, sha224SigSz)));

if (!VerifySigDER(signature_der, message_hash, public_key, curve))
{
    throw new SystemException("Signature verification failure");
}
Console.WriteLine(" OK");

sha256SigSz = SignNonDeterministicDER<HMAC_SHA256>(signature_der, secretKey, message_hash, curve);
Console.Write("HMAC_SHA256: {0}", Convert.ToHexString(signature_der.Slice(0, sha256SigSz)));

if (!VerifySigDER(signature_der, message_hash, public_key, curve))
{
    throw new SystemException("Signature verification failure");
}
Console.WriteLine(" OK");

sha512SigSz = SignNonDeterministicDER<HMAC_SHA512>(signature_der, secretKey, message_hash, curve);
Console.Write("HMAC_SHA512: {0}", Convert.ToHexString(signature_der.Slice(0, sha512SigSz)));

if (!VerifySigDER(signature_der, message_hash, public_key, curve))
{
    throw new SystemException("Signature verification failure");
}
Console.WriteLine(" OK");

Console.WriteLine("Decoding and verification tests:");
foreach (var sHex in signaturesToCheck)
{
    Console.Write(sHex);
    var testSig = Convert.FromHexString(sHex);
    if (!VerifySigCompact(testSig, message_hash, public_key, curve))
    {
        throw new SystemException("Signature verification failure");
    }
    Console.WriteLine(" OK");
}
