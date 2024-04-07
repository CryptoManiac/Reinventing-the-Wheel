using System.Text;
using Wheel.Crypto.Elliptic.ECDSA;
using Wheel.Hashing.SHA.SHA256;

List<Tuple<string, SECPCurve>> curves = new()
{
    new("secp160r1", SECPCurve.Get_SECP160R1()),
    new("secp192r1", SECPCurve.Get_SECP192R1()),
    new("secp224r1", SECPCurve.Get_SECP224R1()),
    new("secp256r1", SECPCurve.Get_SECP256R1()),
    new("secp384r1", SECPCurve.Get_SECP384R1()),
    new("secp521r1", SECPCurve.Get_SECP521R1()),
    new("secp256k1", SECPCurve.Get_SECP256K1()),
};

// Endless loop follows

loop:

foreach (var (name, algo) in curves)
{
    algo.GenerateRandomSecret(out ECPrivateKey secretKeyA, null);

    if (!secretKeyA.ComputePublicKey(out ECPublicKey publicKeyA))
    {
        throw new SystemException("Computation of the public key A has failed");
    }

    Span<byte> secret_key = new byte[algo.PrivateKeySize];
    Span<byte> public_key = new byte[algo.UncompressedPublicKeySize];
    Span<byte> public_key_compressed = new byte[algo.CompressedPublicKeySize];
    Span<byte> signature_der_buffer = new byte[algo.DERSignatureSize];

    if (!secretKeyA.Serialize(secret_key))
    {
        throw new SystemException("Secret key serialization failed");
    }

    if (!publicKeyA.Serialize(public_key))
    {
        throw new SystemException("Public key serialization failed");
    }

    if (!publicKeyA.Compress(public_key_compressed))
    {
        throw new SystemException("Public key compression failed");
    }

    Span<byte> random_message = new byte[algo.PrivateKeySize];
    algo.GenerateRandomSecret(random_message, null);

    ECPublicKey unserializedA = new(algo, public_key);
    ECPublicKey uncompressedA = new(algo);

    if (uncompressedA.Decompress(public_key))
    {
        throw new SystemException("Public key decompression suceeded while it shouldn't have");
    }

    if (uncompressedA.Parse(public_key_compressed))
    {
        throw new SystemException("Public key deserialization suceeded while it shouldn't have");
    }

    if (!uncompressedA.Decompress(public_key_compressed))
    {
        throw new SystemException("Public key decompression failed");
    }

    Console.WriteLine("{0} private key A: {1}", name, Convert.ToHexString(secret_key));
    Console.WriteLine("{0} public key A uncompressed: {1}\n", name, Convert.ToHexString(public_key));
    Console.WriteLine("{0} public key A compressed: {1}\n", name, Convert.ToHexString(public_key_compressed));
    Console.WriteLine("Message to sign: {0}", Convert.ToHexString(random_message));

    Span<byte> message_hash = new byte[32];
    SHA256.Hash(message_hash, random_message);

    secretKeyA.Sign(out DERSignature sig, message_hash);
    int sigSz = sig.Encode(signature_der_buffer);

    Console.WriteLine("DER signature: {0}", Convert.ToHexString(signature_der_buffer[..sigSz]));

    DERSignature decoded = new DERSignature(algo, signature_der_buffer[..sigSz]);

    if (!unserializedA.VerifySignature(decoded, message_hash))
    {
        throw new SystemException("Signature validation failed (1)");
    }

    if (!uncompressedA.VerifySignature(decoded, message_hash))
    {
        throw new SystemException("Signature validation failed (2)");
    }

    if (uncompressedA.VerifySignature(decoded, null))
    {
        throw new SystemException("Signature validation suceeded on null");
    }

    if (uncompressedA.VerifySignature(decoded, random_message))
    {
        throw new SystemException("Signature validation suceeded while it shouldn't have");
    }
}

goto loop;

