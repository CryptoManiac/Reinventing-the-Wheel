namespace EdDSA_Mehdi.Internal.Curve25519;

/// <summary>
/// Blinding is a measure to protect against side channel attacks.
/// Blinding randomizes the scalar multiplier.
///
/// Instead of calculating a*P, calculate (a+b mod BPO)*P + B
/// Where b = random blinding and B = -b*P
/// </summary>
public static partial class ECP
{
    
}