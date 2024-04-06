using Wheel.Crypto.Elliptic.EdDSA;

// Should give these results:
// Ed25519 private key: 58B5968C488E2722C0E0F511F69BC72CDAE887CD879C6BC2CDEAD88DF6AA9869
// Ed25519 public key: 8262C50CE735D9234664BD1A90DB48BA1A23F01FC6453E82BFFA537CBEE1A1D1
string ed25519_seed_a = "A4E872FF25D9C8848825FADC9E0FB369E570F10075B7E20CEE2671AED3C1001A";

// Should give these results:
// Ed25519 public key: E08C3BF52A6D8BDA9DB32EC8FFA17BA30FDB55CB949565CCC1D297C9FEE6C901
string ed25519_seed_b = "5A53B2605BC5ACE229453143DC7D31174DC7E40C8CFFFF586BEFB4052F2177CF";

EdCurve curve = EdCurve.Get_EdCurve_SHA2();

// Derive secret keys
curve.ExpandSeed(out EdPrivateKey secretKeyA, Convert.FromHexString(ed25519_seed_a));
curve.ExpandSeed(out EdPrivateKey secretKeyB, Convert.FromHexString(ed25519_seed_b));

if (!secretKeyA.ComputePublicKey(out EdPublicKey publicKeyA))
{
    throw new SystemException("Computation of the public key A has failed");
}

if (!secretKeyB.ComputePublicKey(out EdPublicKey publicKeyB))
{
    throw new SystemException("Computation of the public key B has failed");
}

Span<byte> secret_key = stackalloc byte[curve.PrivateKeySize];
Span<byte> public_key = stackalloc byte[curve.CompressedPublicKeySize];

secretKeyA.Serialize(secret_key);
publicKeyA.Serialize(public_key);
Console.WriteLine("ED25519 seed A: {0}", ed25519_seed_a);
Console.WriteLine("ED25519 private key A: {0}", Convert.ToHexString(secret_key));
Console.WriteLine("ED25519 public key A: {0}\n", Convert.ToHexString(public_key));

secretKeyB.Serialize(secret_key);
publicKeyB.Serialize(public_key);
Console.WriteLine("ED25519 seed B: {0}", ed25519_seed_b);
Console.WriteLine("ED25519 private key B: {0}", Convert.ToHexString(secret_key));
Console.WriteLine("ED25519 public key B: {0}\n", Convert.ToHexString(public_key));

// Derive shared key twice

bool resultA = secretKeyA.ECDH(publicKeyB, out EdPrivateKey shared1);
bool resultB = secretKeyB.ECDH(publicKeyA, out EdPrivateKey shared2);

if (!resultA || !resultB)
{
    throw new SystemException("EdDH failure");
}

Span<byte> shared_key_a = stackalloc byte[curve.PrivateKeySize];
Span<byte> shared_key_b = stackalloc byte[curve.PrivateKeySize];

shared1.Serialize(shared_key_a);
Console.WriteLine("Shared key 1: {0}", Convert.ToHexString(shared_key_a));

shared2.Serialize(shared_key_b);
Console.WriteLine("Shared key 2: {0}", Convert.ToHexString(shared_key_b));

if (!shared_key_b.SequenceEqual(shared_key_a))
{
    throw new SystemException("EdDH shared key mismatch!");
}
