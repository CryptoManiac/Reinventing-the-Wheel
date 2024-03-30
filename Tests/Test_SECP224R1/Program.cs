using System.Text;
using Wheel.Crypto.Elliptic.ECDSA;
using Wheel.Crypto.Elliptic.EllipticCommon;
using Wheel.Hashing.HMAC;
using Wheel.Hashing.HMAC.SHA2;
using Wheel.Hashing.SHA.SHA256;

string message = "aaa";

// Should give these results:
// SECP224R1 private key: DB395A4721E3698864A50BBDBC5D12EFDE180237713AC2A692E4349F
// SECP224R1 public key: 04C9B6C7B016E66481AD68E6D0CA25873B2AAA05114D04E378D293B51F5760C12069FC901B74079199FE3F43E95C34E930D132D7D9CBBD67FE
// SECP224R1 compressed public key: 02C9B6C7B016E66481AD68E6D0CA25873B2AAA05114D04E378D293B51F
string secret_seed = "The quick brown fox jumps over the lazy dog";
string personalization = "For signing tests";
int secret_key_number = 0;

SortedDictionary<string, string> vectors = new()
{
    {  "HMAC_SHA224", "303C021CEFBE1C9CF08272025950D625242F010EE970CFF4059205BF69EC8A36021C7F2B49F031DFC0D42B46CA7C2C5AA30135A6A724A055CCF40B58B869"},
    {  "HMAC_SHA256", "303C021C3F3FDFCFD7867728782817789CCBDD62856ABA4FED330F14B9E6F429021C3F57AC1E563E796E6F06BCA55C40E2C10C320041D01B3A37F0DEF2BA"},
    {  "HMAC_SHA512", "303C021CD51603A5B959F3F9A872918451C329C7654E6A9AE97CFF0270591E28021C0E06CE48E08D59BF47071E4404786828ADA1F318419EA994A0BAD208"},
};

// TODO: Add test cases

List<string> signaturesToCheck = new()
{
};

List<string> nonCanonicalToCheck = new()
{
};

static void SignData<HMAC_IMPL>(Span<byte> signature, IPrivateKey sk, string message, ECCurve curve) where HMAC_IMPL : unmanaged, IMac
{
    // Empty for tests
    Span<byte> message_hash = stackalloc byte[32];
    SHA256.Hash(message_hash, Encoding.ASCII.GetBytes(message));

    if (!sk.Sign<HMAC_IMPL>(out DERSignature derSig, message_hash))
    {
        throw new SystemException("Signing failed");
    }

    if (signature.Length < derSig.Encode(signature))
    {
        throw new Exception("Signature buffer is too short");
    }
}

static bool VerifySignature(ReadOnlySpan<byte> signature, string message, ReadOnlySpan<byte> public_key, ECCurve curve, bool nonCanonical=false)
{
    Span<byte> message_hash = stackalloc byte[32];
    SHA256.Hash(message_hash, Encoding.ASCII.GetBytes(message));
    return curve.MakePublicKey(public_key).VerifySignature(new DERSignature(curve, signature, nonCanonical), message_hash);
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

ECCurve curve = ECCurve.Get_SECP224R1();

// Derive new secret key
curve.GenerateSecret<HMAC_SHA512>(out IPrivateKey secretKey, Encoding.ASCII.GetBytes(secret_seed), Encoding.ASCII.GetBytes(personalization), secret_key_number);

if (!secretKey.ComputePublicKey(out IPublicKey publicKey))
{
    throw new SystemException("Computation of the public key has failed");
}

Span<byte> secret_key = stackalloc byte[curve.NUM_N_BYTES];
Span<byte> public_key_uncompressed = stackalloc byte[2 * curve.NUM_N_BYTES];
Span<byte> public_key_compressed = stackalloc byte[1 + curve.NUM_N_BYTES];

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

Console.WriteLine("SECP224R1 private key: {0}", Convert.ToHexString(secret_key));
Console.WriteLine("SECP224R1 public key: 04{0}", Convert.ToHexString(public_key_uncompressed));
Console.WriteLine("SECP224R1 compressed public key: {0}", Convert.ToHexString(public_key_compressed));
Console.WriteLine("Message to sign: {0}", message);

Span<byte> signature = stackalloc byte[DERSignature.GetEncodeSize(curve)];

Console.WriteLine("Generated SECP224R1 signatures:");

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

Console.WriteLine("Canonical DER decoding and verification tests:");
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

Console.WriteLine("Non-canonical DER decoding and verification tests:");
foreach (var sHex in nonCanonicalToCheck)
{
    Console.Write(sHex);
    var testSig = Convert.FromHexString(sHex);
    if (!VerifySignature(testSig, message, public_key_uncompressed, curve, true))
    {
        throw new SystemException("Signature verification failure");
    }
    Console.WriteLine(" OK");
}
