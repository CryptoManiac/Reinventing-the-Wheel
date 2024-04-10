using EdDSA_Mehdi.Internal.BaseTypes;

namespace EdDSA_Mehdi.Internal.Curve25519;

/// <summary>
/// Conversion functions and constants
/// </summary>
public static class Const
{
    public const int K_BYTES = 32;
    public const int K_WORDS = (K_BYTES / sizeof(U_WORD));


}
