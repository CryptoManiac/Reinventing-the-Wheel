using System.Text;
using Wheel.Crypto.Elliptic;
using Wheel.Crypto.Hashing.HMAC;
using Wheel.Crypto.Hashing.HMAC.SHA2;
using Wheel.Crypto.Hashing.SHA.SHA256;

string message = "aaa";
string private_key_hex = "80eaba734c283aba9f2f8a96e1152c97aa8357357e83b1f91b60dc987c486bcb"; // Pub: 041c5091d939a42d67c2b4f7bd44cceb2159e5b192df22527baf1ae83bbf8191b30e6fe36f426369054e1a06b571230f4af589d7e30a20b8f2cb3ea4ee96493dc6

// Must be valid, check here: http://kjur.github.io/jsrsasign/sample/sample-ecdsa.html (select secp256k1 curve and SHA256withECDSA algorithm)
SortedDictionary<string, string> vectors = new()
{
    {  "HMAC_SHA224", "3044022060D8CCF762053A529310A8C0545FA6F1F0161BD3AE5E72BAB86E934C58866F490220CA56EFB8D9038F8172EC9624CCFA47568AAF46A69F1F955FF92F6F411B0FAB02"},
    {  "HMAC_SHA256", "30440220C3C0AA9060E9F6598B1D0CE49445A50924CF159D074BCADAB9EA8D5784D9EE1302204E1B7E0AE57A7A72B454B44E5F54792849F63EB97DF8A14329BCA0A31F920B97"},
    {  "HMAC_SHA512", "304402200A71911B43549345D71BEFEA8666ECE38BDD5C22E3597E06F5239CB22B9011100220DF803647D9753E0009DC27D594B15EDDB75C1B980011CABCE7AB66FE22F1D684"},
};

static void SignData<HMAC_IMPL>(Span<byte> signature, ECPrivateKey sk, string message, ECCurve curve) where HMAC_IMPL : unmanaged, IMac
{
    // Empty for tests
    Span<byte> additional_entropy = stackalloc byte[0];
    Span<byte> message_hash = stackalloc byte[32];
    SHA256.Hash(message_hash, Encoding.ASCII.GetBytes(message));
    
    DERSignature derSig = new(curve);

    if (!sk.Sign<HMAC_IMPL>(ref derSig, message_hash, additional_entropy))
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

    ECPublicKey pk = new(curve);
    if (!pk.Parse(public_key))
    {
        throw new SystemException("Public key parse failed");
    }

    DERSignature derSig = new(curve);
    if (!derSig.Parse(signature))
    {
        throw new SystemException("Invalid signature format");
    }

    return pk.VerifySignature(derSig, message_hash);
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

Console.WriteLine("SECP256K1 private key: {0}", private_key_hex);
Console.WriteLine("Message to sign: {0}", message);

byte[] private_bytes = Convert.FromHexString(private_key_hex);

ECPrivateKey sk = new(curve);
if (!sk.Parse(private_bytes))
{
    throw new SystemException("Private key parse failed");
}

Span<byte> public_key_uncompressed = stackalloc byte[64];
Span<byte> public_key_compressed = stackalloc byte[33];

ECPublicKey pk = new(curve);
if (!sk.ComputePublicKey(ref pk))
{
    throw new SystemException("Computation of the public key has failed");
}

if (!pk.Compress(public_key_compressed))
{
    throw new SystemException("Compression of the public key has failed");
}

if (!pk.Serialize(public_key_uncompressed))
{
    throw new SystemException("Serialization of the public key has failed");
}

Console.WriteLine("SECP256K1 public key: 04{0}", Convert.ToHexString(public_key_uncompressed));
Console.WriteLine("SECP256K1 compressed public key: {0}", Convert.ToHexString(public_key_compressed));


Span<byte> signature = stackalloc byte[70];

Console.WriteLine("Generated SECP256K1 signatures:");

SignData<HMAC_SHA224>(signature, sk, message, curve);

if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}

CompareSig("HMAC_SHA224", signature);

SignData<HMAC_SHA256>(signature, sk, message, curve);
if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}

CompareSig("HMAC_SHA256", signature);


SignData<HMAC_SHA512>(signature, sk, message, curve);

if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}

CompareSig("HMAC_SHA512", signature);

