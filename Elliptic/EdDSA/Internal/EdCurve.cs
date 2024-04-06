using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Crypto.Elliptic.EdDSA.Internal;
using Wheel.Crypto.Elliptic.EllipticCommon;
using Wheel.Hashing;
using Wheel.Hashing.HMAC;
using Wheel.Hashing.HMAC.SHA2;
using Wheel.Hashing.SHA.SHA512;
using Wheel.Hashing.SHA3;

namespace Wheel.Crypto.Elliptic.EdDSA;

internal struct EdCurveConfig
{
    public unsafe fixed ulong scrambleKey[ModM.ModM_WORDS];
}

#pragma warning disable CS0660
#pragma warning disable CS0661
public readonly struct EdCurve : ICurve
#pragma warning restore CS0660
#pragma warning restore CS0661
{
    /// <summary>
    /// Curve point parameters
    /// </summary>
    private readonly EdCurveConfig curveConfig;

    /// <summary>
    /// Random instance identifier
    /// </summary>
    public readonly ulong randomId { get; }

    /// <summary>
    /// Configured hasher construct function
    /// </summary>
    private readonly unsafe delegate* managed<IHasher> _hasher;

    /// <summary>
    /// Size of encoded private key in bytes
    /// </summary>
    public int PrivateKeySize => EdPrivateKey.GetEncodedSize(this);

    /// <summary>
    /// Size of uncompressed public key in bytes
    /// </summary>
    public int UncompressedPublicKeySize => EdPublicKey.GetUncompressedSize(this);

    /// <summary>
    /// Size of compressed public key in bytes
    /// </summary>
    public int CompressedPublicKeySize => EdPublicKey.GetCompressedSize(this);

    /// <summary>
    /// Maximum size of DER signature in bytes
    /// </summary>
    public int DERSignatureSize => DERSignature.GetEncodedSize(this);

    /// <summary>
    /// Size of compact signature in bytes
    /// </summary>
    public int CompactSignatureSize => CompactSignature.GetEncodedSize(this);

    /// <summary>
    /// Returns instance of SHA-512 hasher
    /// </summary>
    /// <returns></returns>
    private static IHasher getSha2()
    {
        return new SHA512();
    }

    /// <summary>
    /// Returns instance of SHA3-512 hasher
    /// </summary>
    /// <returns></returns>
    private static IHasher getSha3()
    {
        return new SHA3_512();
    }

    /// <summary>
    /// Returns instance of Keccak-512 hasher
    /// </summary>
    /// <returns></returns>
    private static IHasher getKeccak()
    {
        return new Keccak_512();
    }

    public unsafe readonly ReadOnlySpan<ulong> ScrambleKey
    {
        get
        {
            fixed (ulong* ptr = &curveConfig.scrambleKey[0])
            {
                return new ReadOnlySpan<ulong>(ptr, ModM.ModM_WORDS);
            }
        }
    }

    /// <summary>
    /// Construct a new instance instance of the configured hasher
    /// </summary>
    public unsafe readonly IHasher makeHasher() => _hasher();

    private unsafe EdCurve(delegate* managed<IHasher> hasher)
    {
        Span<ulong> random = stackalloc ulong[1 + ModM.ModM_WORDS];
        RNG.Fill(random);

        randomId = random[0];

        fixed (ulong* ptr = &curveConfig.scrambleKey[0])
        {
            random[1..].CopyTo(new Span<ulong>(ptr, ModM.ModM_WORDS));
        }

        _hasher = hasher;
    }

    public unsafe static EdCurve Get_EdCurve_SHA2()
    {
        return new EdCurve(&getSha2);
    }

    public unsafe static EdCurve Get_EdCurve_SHA3()
    {
        return new EdCurve(&getSha3);
    }

    public unsafe static EdCurve Get_EdCurve_Keccak()
    {
        return new EdCurve(&getKeccak);
    }

    public static bool operator ==(EdCurve x, EdCurve y)
    {
        return x.randomId == y.randomId;
    }

    public static bool operator !=(EdCurve x, EdCurve y)
    {
        return !(x == y);
    }

    /// <summary>
    /// Generation of a random secret key on top of the .NET RandomNumberGenerator API. The security of this key will depend
    /// on the quality of the local RNG implementation and the quality of the entropy array being used as well. I suggest that
    /// you should treat these keys as unsecure by default, use this API with caution and never use the generated keys directly,
    /// without hashing. It will be a good idea to use the DeriveHMAC method to derive the children keys from them.
    /// </summary>
    /// <param name="result">Private key to be filled</param>
    /// <param name="entropy">Additional entropy</param>
    /// <returns>True on success</returns>
    [SkipLocalsInit]
    public void GenerateRandomSecret(out EdPrivateKey result, ReadOnlySpan<byte> entropy)
    {
        Span<byte> rnd = stackalloc byte[32];
        GenerateRandomSecret(rnd, entropy);
        rnd[0] &= 248;
        rnd[31] &= 127;
        rnd[31] |= 64;
        result = new(this, rnd);
    }

    /// <summary>
    /// Deterministically generate the new private key from seed, using HMAC-based generator
    /// </summary>
    /// <typeparam name="HMAC_IMPL">HMAC implementation to use</typeparam>
    /// <param name="result">Private key to be filled</param>
    /// <param name="seed">Secret seed to generate from</param>
    /// <param name="personalization">Personalization argument bytes (to generate more than one key from the same seed)</param>
    /// <param name="sequence">Generation sequence number (to generate more than one key from the same seed + personalization pair)</param>
    [SkipLocalsInit]
    public void GenerateDeterministicSecret<HMAC_IMPL>(out EdPrivateKey result, ReadOnlySpan<byte> seed, ReadOnlySpan<byte> personalization, int sequence) where HMAC_IMPL : unmanaged, IMac
    {
        Span<byte> rnd = stackalloc byte[32];
        GenerateDeterministicSecret<HMAC_IMPL>(rnd, seed, personalization, sequence);
        rnd[0] &= 248;
        rnd[31] &= 127;
        rnd[31] |= 64;
        result = new(this, rnd);
    }

    public readonly void GenerateDeterministicSecret<HMAC_IMPL>(Span<byte> result, ReadOnlySpan<byte> seed, ReadOnlySpan<byte> personalization, int sequence) where HMAC_IMPL : unmanaged, IMac
    {
        Span<byte> separator_00 = stackalloc byte[1] { 0x00 };
        Span<byte> separator_01 = stackalloc byte[1] { 0x00 };
        Span<byte> sequence_data = stackalloc byte[sizeof(int)];

        HMAC_IMPL hmac = new();
        hmac.Init(seed);
        hmac.Update(personalization);
        hmac.Update(separator_00);

        // Convert sequence to bytes
        MemoryMarshal.Cast<byte, int>(sequence_data)[0] = sequence;

        hmac.Update(sequence_data);

        // Allocate buffer for HMAC results
        Span<byte> K = stackalloc byte[hmac.HashSz];
        Span<byte> V = stackalloc byte[hmac.HashSz];

        hmac.Digest(K);

        // H
        int secret_byte_index = 0;
        Span<byte> secret_data = stackalloc byte[result.Length];

        while (true)
        {
            hmac.Init(K);
            hmac.Update(seed);
            hmac.Update(separator_01);
            hmac.Update(personalization);
            hmac.Update(separator_01);
            hmac.Digest(V);

            Span<byte> src = V[..Math.Min(V.Length, secret_data.Length - secret_byte_index)];
            Span<byte> target = secret_data[secret_byte_index..];
            src.CopyTo(target);
            secret_byte_index += src.Length;

            if (secret_byte_index >= result.Length)
            {
                secret_data[..result.Length].CopyTo(result);
                secret_data.Clear();
                return;
            }

            // H3
            hmac.Init(K);  // K = HMAC_K(V || 00 || seed || 00 || personalization)
            hmac.Update(V);
            hmac.Update(separator_00);
            hmac.Update(seed);
            hmac.Update(separator_00);
            hmac.Update(personalization);
            hmac.Digest(K);
        }
    }

    public void GenerateRandomSecret(Span<byte> result, ReadOnlySpan<byte> entropy)
    {
        Span<byte> rnd = stackalloc byte[32];
        RNG.Fill(rnd);
        GenerateDeterministicSecret<HMAC_SHA512>(result, rnd, entropy, 0);
    }

    /// <summary>
    /// Check whether the provided byte array contains a valid public key
    /// </summary>
    /// <param name="data">Public key bytes</param>
    /// <returns>True if valid</returns>
    public bool IsValidPublicKey(ReadOnlySpan<byte> data) => EdPublicKey.IsValidPublicKey(this, data);

    /// <summary>
    /// Check whether the provided byte array contains a valid private key
    /// </summary>
    /// <param name="data">Private key bytes</param>
    /// <returns>True if valid</returns>
    public bool IsValidPrivateKey(ReadOnlySpan<byte> data) => EdPrivateKey.IsValidPrivateKey(this, data);

}

