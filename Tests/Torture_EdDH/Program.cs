using Wheel.Crypto.Elliptic.EdDSA;

EdCurve curve = EdCurve.Get_EdCurve_SHA2();

Span<byte> secret_key = stackalloc byte[curve.PrivateKeySize];
Span<byte> public_key = stackalloc byte[curve.CompressedPublicKeySize];

Span<byte> shared_key_a = stackalloc byte[curve.PrivateKeySize];
Span<byte> shared_key_b = stackalloc byte[curve.PrivateKeySize];

// Endless loop follows

start:

// Create secret keys
curve.GenerateRandomSecret(out EdPrivateKey secretKeyA, null);
curve.GenerateRandomSecret(out EdPrivateKey secretKeyB, null);

if (!secretKeyA.ComputePublicKey(out EdPublicKey publicKeyA))
{
    throw new SystemException("Computation of the public key A has failed");
}

if (!secretKeyB.ComputePublicKey(out EdPublicKey publicKeyB))
{
    throw new SystemException("Computation of the public key B has failed");
}

secretKeyA.Serialize(secret_key);
publicKeyA.Serialize(public_key);
Console.WriteLine("ED25519 private key A: {0}", Convert.ToHexString(secret_key));
Console.WriteLine("ED25519 public key A: {0}\n", Convert.ToHexString(public_key));

secretKeyB.Serialize(secret_key);
publicKeyB.Serialize(public_key);
Console.WriteLine("ED25519 private key B: {0}", Convert.ToHexString(secret_key));
Console.WriteLine("ED25519 public key B: {0}\n", Convert.ToHexString(public_key));

// Derive shared key twice

bool resultA = secretKeyA.ECDH(publicKeyB, out EdPrivateKey shared1);
bool resultB = secretKeyB.ECDH(publicKeyA, out EdPrivateKey shared2);

if (!resultA || !resultB)
{
    throw new SystemException("EdDH failure");
}

shared1.Serialize(shared_key_a);
Console.WriteLine("Shared key 1: {0}", Convert.ToHexString(shared_key_a));

shared2.Serialize(shared_key_b);
Console.WriteLine("Shared key 2: {0}", Convert.ToHexString(shared_key_b));

if (!shared_key_b.SequenceEqual(shared_key_a))
{
    throw new SystemException("EdDH shared key mismatch!");
}

goto start;

