using System.Text;
using Wheel.Crypto.Elliptic.ECDSA;
using Wheel.Crypto.Elliptic.EllipticCommon;
using Wheel.Hashing.HMAC.SHA2;

string secret_seed = "The quick brown fox jumps over the lazy dog";
string personalization = "For ECDH tests";

List<Tuple<string, ECCurve>> curves = new()
{
    new("secp160r1", ECCurve.Get_SECP160R1()),
    new("secp192r1", ECCurve.Get_SECP192R1()),
    new("secp224r1", ECCurve.Get_SECP224R1()),
    new("secp256r1", ECCurve.Get_SECP256R1()),
    new("secp384r1", ECCurve.Get_SECP384R1()),
    new("secp521r1", ECCurve.Get_SECP521R1()),
    new("secp256k1", ECCurve.Get_SECP256K1()),
};

foreach (var (name, algo) in curves)
{
    algo.GenerateDeterministicSecret<HMAC_SHA512>(out ECPrivateKey secretKeyA, Encoding.ASCII.GetBytes(secret_seed), Encoding.ASCII.GetBytes(personalization), 1);
    algo.GenerateDeterministicSecret<HMAC_SHA512>(out ECPrivateKey secretKeyB, Encoding.ASCII.GetBytes(secret_seed), Encoding.ASCII.GetBytes(personalization), 2);

    if (!secretKeyA.ComputePublicKey(out ECPublicKey publicKeyA))
    {
        throw new SystemException("Computation of the public key A has failed");
    }

    if (!secretKeyB.ComputePublicKey(out ECPublicKey publicKeyB))
    {
        throw new SystemException("Computation of the public key B has failed");
    }

    Span<byte> secret_key = new byte[algo.PrivateKeySize];
    Span<byte> public_key = new byte[algo.UncompressedPublicKeySize];

    secretKeyA.Serialize(secret_key);
    publicKeyA.Serialize(public_key);
    Console.WriteLine("{0} private key A: {1}", name, Convert.ToHexString(secret_key));
    Console.WriteLine("{0} public key A: {1}\n", name, Convert.ToHexString(public_key));

    secretKeyB.Serialize(secret_key);
    publicKeyB.Serialize(public_key);
    Console.WriteLine("{0} private key B: {1}", name, Convert.ToHexString(secret_key));
    Console.WriteLine("{0} public key B: {1}\n", name, Convert.ToHexString(public_key));


    // Derive shared key twice

    bool resultA = secretKeyA.ECDH(publicKeyB, out ECPrivateKey shared1);
    bool resultB = secretKeyB.ECDH(publicKeyA, out ECPrivateKey shared2);

    if (!resultA || !resultB)
    {
        throw new SystemException("ECDH failure");
    }

    shared1.Serialize(secret_key);
    Console.WriteLine("Shared key 1: {0}", Convert.ToHexString(secret_key));

    shared2.Serialize(secret_key);
    Console.WriteLine("Shared key 2: {0}\n\n", Convert.ToHexString(secret_key));

}
