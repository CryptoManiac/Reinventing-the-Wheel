using System.Text;
using Wheel.Crypto.Elliptic.SECP256K1;
using Wheel.Crypto.Hashing.HMAC;
using Wheel.Crypto.Hashing.HMAC.SHA2;
using Wheel.Crypto.Hashing.SHA.SHA256;

string message = "aaa";
string private_key_hex = "80eaba734c283aba9f2f8a96e1152c97aa8357357e83b1f91b60dc987c486bcb"; // Pub: 041c5091d939a42d67c2b4f7bd44cceb2159e5b192df22527baf1ae83bbf8191b30e6fe36f426369054e1a06b571230f4af589d7e30a20b8f2cb3ea4ee96493dc6

// Must be valid, check here: http://kjur.github.io/jsrsasign/sample/sample-ecdsa.html
SortedDictionary<string, string> vectors = new()
{
    {  "HMAC_SHA224", "30440220DDA4D137FAE0D0B0046E0A9E68CA3F23D3AF6E492AA7444C202F4E26D7B16756022096919920F06F1E7D4C6E27181A89DF459D494B51C0C5FC6C17214B38F37024B4"},
    {  "HMAC_SHA256", "30440220AD5A49829F2D04835F5C1643CBDE5C3EFFAAF004FD26768B02E922C3A31BCA7D0220FD003EF5FF29C03AD2B9FEEA3FDFF0EBB7EA62142A4F0AB1EFA8E599EA41E285"},
    {  "HMAC_SHA512", "304402202BCDF1077AA384AF0C0BE397847B66FE37A9CACE91E2020A3F3D0790FF2CBA9902206785B1803A3F8F80E4E5FC98ED59B4B47D8E58D64C41B821AA4E79F9DF5737C1"},
};

static void SignData<HMAC_IMPL>(Span<byte> signature, string private_key, string message) where HMAC_IMPL : unmanaged, IMac
{
    // Empty for tests
    Span<byte> additional_entropy = stackalloc byte[0];

    Span<byte> message_hash = stackalloc byte[32];
    SHA256.Hash(message_hash, Encoding.ASCII.GetBytes(message));
    Span<byte> signature_compact = stackalloc byte[64];
    ECKey.SignDeterministic<HMAC_IMPL>(signature_compact, Convert.FromHexString(private_key), message_hash, additional_entropy);
    if (signature.Length < ECSig.CompactToDER(signature, signature_compact))
    {
        throw new Exception("Signature buffer is too short");
    }
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

Console.WriteLine("SECP256K1 private key: {0}", private_key_hex);
Console.WriteLine("Message to sign: {0}", message);

Span<byte> public_key_uncompressed = stackalloc byte[64];
Span<byte> public_key_compressed = stackalloc byte[33];
ECKey.ComputePublicKey(public_key_uncompressed, Convert.FromHexString(private_key_hex));
ECKey.Compress(public_key_uncompressed, public_key_compressed);

Console.WriteLine("SECP256K1 public key: 04{0}", Convert.ToHexString(public_key_uncompressed));
Console.WriteLine("SECP256K1 compressed public key: {0}", Convert.ToHexString(public_key_compressed));


Span<byte> signature = stackalloc byte[70];

Console.WriteLine("Generated SECP256K1 signatures:");

SignData<HMAC_SHA224>(signature, private_key_hex, message);
CompareSig("HMAC_SHA224", signature);
SignData<HMAC_SHA256>(signature, private_key_hex, message);
CompareSig("HMAC_SHA256", signature);
SignData<HMAC_SHA512>(signature, private_key_hex, message);
CompareSig("HMAC_SHA512", signature);
