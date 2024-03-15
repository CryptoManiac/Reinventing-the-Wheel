using System.Text;
using Wheel.Crypto.Elliptic.SECP256K1;
using Wheel.Crypto.Hashing.HMAC.SHA2;
using Wheel.Crypto.Hashing.SHA.SHA256;

string message = "aaa";
string private_key_hex = "80eaba734c283aba9f2f8a96e1152c97aa8357357e83b1f91b60dc987c486bcb"; // Pub: 041c5091d939a42d67c2b4f7bd44cceb2159e5b192df22527baf1ae83bbf8191b30e6fe36f426369054e1a06b571230f4af589d7e30a20b8f2cb3ea4ee96493dc6

// string expectedSig = "30440220A6C18B5CB0815B1C59FF63F293C99B2DB7CE3E37F974B30F1A4D609CA7E9F8900220B4326F2EB91C929579BCB93D4635A3F0CC39888465E490F8D958C8A7782A9D9F";

static void SignData(Span<byte> signature, ReadOnlySpan<byte> private_key, ReadOnlySpan<byte> message)
{
    // Empty for tests
    Span<byte> additional_entropy = stackalloc byte[0];

    Span<byte> message_hash = stackalloc byte[32];
    SHA256.Hash(message_hash, message);
    Console.WriteLine("Signing hash: {0}", Convert.ToHexString(message_hash));
    Span<byte> signature_compact = stackalloc byte[64];
    ECKey.SignDeterministic(signature_compact, private_key, message_hash, additional_entropy, new HMAC_SHA256());
    if (signature.Length < ECSig.CompactToDER(signature, signature_compact))
    {
        throw new Exception("Signature buffer is too short");
    }
}

Console.WriteLine("SECP256K1 private key: {0}", private_key_hex);
Console.WriteLine("Message to sign: {0}", message);

Span<byte> public_key_uncompressed = stackalloc byte[64];
Span<byte> public_key_compressed = stackalloc byte[33];
ECKey.ComputePublicKey(public_key_uncompressed, Convert.FromHexString(private_key_hex));
ECKey.Compress(public_key_uncompressed, public_key_compressed);

// Must be valid, check here: http://kjur.github.io/jsrsasign/sample/sample-ecdsa.html
Console.WriteLine("SECP256K1 public key: {0}", Convert.ToHexString(public_key_uncompressed));
Console.WriteLine("SECP256K1 compressed public key: {0}", Convert.ToHexString(public_key_compressed));

Span<byte> signature_der = new byte[70];
SignData(signature_der, Convert.FromHexString(private_key_hex), Encoding.ASCII.GetBytes(message));
Console.WriteLine("SECP256K1 signature: {0}", Convert.ToHexString(signature_der));
