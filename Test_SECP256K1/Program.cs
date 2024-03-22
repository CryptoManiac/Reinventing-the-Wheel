using System.Text;
using Wheel.Crypto.Elliptic;
using Wheel.Crypto.Hashing.HMAC;
using Wheel.Crypto.Hashing.HMAC.SHA2;
using Wheel.Crypto.Hashing.SHA.SHA256;

string message = "aaa";

// Should give these results:
// SECP256K1 private key: 2618BB1DA0D193FE955B981F3D84922BA6D277C06C19FB4E32607AB46D68E643
// SECP256K1 public key: 046EB792F5CB23479D08AC708EE4DF0C7606E80052F6C4FC7178D9127AD7B81C90C56F7B8AEE29A86CCF5DC91A44CF649E4C379999043738ADC410309800537AB9
// SECP256K1 compressed public key: 036EB792F5CB23479D08AC708EE4DF0C7606E80052F6C4FC7178D9127AD7B81C90
string secret_seed = "The quick brown fox jumps over the lazy dog";
string personalization = "For signing tests";
int secret_key_number = 0;
int derive_iterations = 2048;

// Must be valid, check here: http://kjur.github.io/jsrsasign/sample/sample-ecdsa.html (select secp256k1 curve and SHA256withECDSA algorithm)
SortedDictionary<string, string> vectors = new()
{
    {  "HMAC_SHA224", "30440220D2A5AD3915BFB2800EE48D1FBFA01F9A0283F3D9C3378D5FFFEBE3A33EE7377D0220F44ED44A537E9F96250D89C6201343FC03A5F73A9104B5D39868D5B298777B2D"},
    {  "HMAC_SHA256", "30440220B4CA2939A13C2C2DCCD3A109CDC803693C988B5AFCB1A9283F97E382F12B04F50220239FA5E16AE0EEC0CA028938155348234582576F06F259810166BBE5D926BD3C"},
    {  "HMAC_SHA512", "3044022096D0CFCB991C2FB819DB7307FEB73156B8BD24EC5DF9C174CD455AA19354C83D0220DA98C310BA0D163210CCB8EC17B9BCDDFA5AEA974A84C727A7AB2AB5056A5742"},
};

static void SignData<HMAC_IMPL>(Span<byte> signature, ECPrivateKey sk, string message, ECCurve curve) where HMAC_IMPL : unmanaged, IMac
{
    // Empty for tests
    Span<byte> message_hash = stackalloc byte[32];
    SHA256.Hash(message_hash, Encoding.ASCII.GetBytes(message));

    DERSignature derSig = new();
    if (!sk.Sign<HMAC_IMPL, DERSignature>(ref derSig, message_hash))
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
ECPrivateKey.GenerateSecret<HMAC_SHA512>(curve, out ECPrivateKey secretKey, Encoding.ASCII.GetBytes(secret_seed), Encoding.ASCII.GetBytes(personalization), secret_key_number, derive_iterations);

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

