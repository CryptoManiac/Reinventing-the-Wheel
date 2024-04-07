using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Hashing.Hashing.HMAC;
using Wheel.Crypto.Elliptic.EdDSA.Internal;
using Wheel.Crypto.Elliptic.EllipticCommon;
using Wheel.Hashing.HMAC;
using Wheel.Hashing.SHA.SHA512;
using Wheel.Hashing.SHA3;

namespace Wheel.Crypto.Elliptic.EdDSA;

internal struct EdCurveConfig
{
    public unsafe fixed byte scrambleKey[32];
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

    public readonly int NUM_BYTES => EdPrivateKey.GetEncodedSize(this);

    /// <summary>
    /// Configured hRAM function
    /// </summary>
    private readonly unsafe delegate* managed<Span<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>, void> _getHRAM;

    /// <summary>
    /// Configured seed expand function
    /// </summary>
    private readonly unsafe delegate* managed<Span<byte>, ReadOnlySpan<byte>, void> _expandSeed;

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

    public unsafe readonly ReadOnlySpan<byte> ScrambleKey
    {
        get
        {
            fixed (byte* ptr = &curveConfig.scrambleKey[0])
            {
                return new ReadOnlySpan<byte>(ptr, 32);
            }
        }
    }

    private unsafe EdCurve(delegate* managed<Span<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>, void> get_hRAM, delegate* managed<Span<byte>, ReadOnlySpan<byte>, void> expandSeed)
    {
        Span<ulong> random = stackalloc ulong[1 + ModM.ModM_WORDS];
        RNG.Fill(random);

        randomId = random[0];

        fixed (byte* ptr = &curveConfig.scrambleKey[0])
        {
            var src = MemoryMarshal.Cast<ulong, byte>(random);
            src.Slice(8, 32).CopyTo(new Span<byte>(ptr, 32));
        }

        _getHRAM = get_hRAM;
        _expandSeed = expandSeed;
    }

    public unsafe static EdCurve Get_EdCurve_SHA2()
    {
        return new EdCurve(&Get_HRAM_SHA2, &Expand_Key_SHA2);
    }

    public unsafe static EdCurve Get_EdCurve_SHA3()
    {
        return new EdCurve(&Get_HRAM_SHA3, &Expand_Key_SHA3);
    }

    public unsafe static EdCurve Get_EdCurve_Keccak()
    {
        return new EdCurve(&Get_HRAM_Keccak, &Expand_Key_Keccak);
    }

    /// <summary>
    /// Calculate S value for signature
    /// </summary>
    /// <param name="hram"></param>
    /// <param name="r"></param>
    /// <param name="a"></param>
    /// <param name="m"></param>
    public unsafe void GetHRAM(Span<byte> hram, ReadOnlySpan<byte> r, ReadOnlySpan<byte> a, ReadOnlySpan<byte> m) => _getHRAM(hram, r, a, m);

    #region Hash function wrappers
    private static void Get_HRAM_SHA2(Span<byte> hram, ReadOnlySpan<byte> r, ReadOnlySpan<byte> a, ReadOnlySpan<byte> m) {
        SHA512 ctx = new();
        ctx.Update(r);
        ctx.Update(a);
        ctx.Update(m);
        ctx.Digest(hram);
    }

    private static void Get_HRAM_SHA3(Span<byte> hram, ReadOnlySpan<byte> r, ReadOnlySpan<byte> a, ReadOnlySpan<byte> m)
    {
        SHA3_512 ctx = new();
        ctx.Update(r);
        ctx.Update(a);
        ctx.Update(m);
        ctx.Digest(hram);
    }

    private static void Get_HRAM_Keccak(Span<byte> hram, ReadOnlySpan<byte> r, ReadOnlySpan<byte> a, ReadOnlySpan<byte> m)
    {
        SHA512 ctx = new();
        ctx.Update(r);
        ctx.Update(a);
        ctx.Update(m);
        ctx.Digest(hram);
    }

    private static void Expand_Key_SHA2(Span<byte> key, ReadOnlySpan<byte> seed)
    {
        SHA512 ctx = new();
        ctx.Update(seed);
        ctx.Digest(key);
    }

    private static void Expand_Key_SHA3(Span<byte> key, ReadOnlySpan<byte> seed)
    {
        SHA3_512 ctx = new();
        ctx.Update(seed);
        ctx.Digest(key);
    }

    private static void Expand_Key_Keccak(Span<byte> key, ReadOnlySpan<byte> seed)
    {
        SHA512 ctx = new();
        ctx.Update(seed);
        ctx.Digest(key);
    }
    #endregion

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
        result = new(this, rnd);
        rnd.Clear();
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
        result = new(this, rnd);
        rnd.Clear();
    }

    /// <summary>
    /// "Generate" key from the common ED25519 seed by hashing
    /// </summary>
    /// <param name="result">Private key to be filled</param>
    /// <param name="seed">Secret seed to generate from</param>
    public unsafe void ExpandSeed(out EdPrivateKey result, ReadOnlySpan<byte> seed)
    {
        Span<byte> key = stackalloc byte[64];
        _expandSeed(key, seed);
        key[0] &= 248;
        key[31] &= 127;
        key[31] |= 64;
        result = new(this, key[..32]);
        key.Clear();
    }

    /// <summary>
    /// Deterministically generate nonce for signing
    /// </summary>
    /// <typeparam name="HMAC_IMPL"></typeparam>
    public void GenerateDeterministicNonce<HMAC_IMPL>(Span<byte> result, ReadOnlySpan<byte> seed, ReadOnlySpan<byte> personalization, int sequence) where HMAC_IMPL : unmanaged, IMac
    {
        // See 3..2 of the RFC 6979 to get what is going on here
        // We're not following it to the letter, but our algorithm is very similar

        HMAC_IMPL hmac = new();
        Span<byte> separator_00 = stackalloc byte[1] { 0x00 };
        Span<byte> separator_01 = stackalloc byte[1] { 0x01 };

        Span<byte> sequence_data = stackalloc byte[sizeof(int)];

        // Convert sequence to bytes
        MemoryMarshal.Cast<byte, int>(sequence_data)[0] = sequence;

        // Allocate buffer for HMAC results
        Span<byte> K = stackalloc byte[hmac.HashSz];
        Span<byte> V = stackalloc byte[hmac.HashSz];

        // B
        K.Fill(0); // K = 00 00 00 ..

        // C
        V.Fill(0x01); // V = 01 01 01 ..

        // D
        hmac.Init(K); // K = HMAC_K(V || 00 || seed || 00 || personalization || 00 || sequence_data)
        hmac.Update(V);
        hmac.Update(separator_00);
        hmac.Update(seed);
        hmac.Update(separator_00);
        hmac.Update(personalization);
        hmac.Update(sequence_data);
        hmac.Digest(K);

        // E
        hmac.Init(K); // V = HMAC_K(V)
        hmac.Update(V);
        hmac.Digest(V);

        // F
        hmac.Init(K); // K = HMAC_K(V || 01 || seed || 01 || personalization || 01 || sequence_data)
        hmac.Update(V);
        hmac.Update(separator_01);
        hmac.Update(seed);
        hmac.Update(separator_01);
        hmac.Update(personalization);
        hmac.Update(sequence_data);
        hmac.Digest(K);

        // G
        hmac.Init(K); // V = HMAC_K(V)
        hmac.Update(V);
        hmac.Digest(V);

        // H
        int secret_byte_index = 0;
        Span<byte> secret_data = stackalloc byte[result.Length];

        while (true)
        {
            // H2
            hmac.Init(K); // V = HMAC_K(V)
            hmac.Update(V);
            hmac.Digest(V);

            // T = T || V
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

            hmac.Init(K); // V = HMAC_K(V)
            hmac.Update(V);
            hmac.Digest(V);
        }
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
    public void GenerateDeterministicSecret<HMAC_IMPL>(Span<byte> result, ReadOnlySpan<byte> seed, ReadOnlySpan<byte> personalization, int sequence) where HMAC_IMPL : unmanaged, IMac
    {
        // See 3..2 of the RFC 6979 to get what is going on here
        // We're not following it to the letter, but our algorithm is very similar

        HMAC_IMPL hmac = new();
        Span<byte> separator_00 = stackalloc byte[1] { 0x00 };
        Span<byte> separator_01 = stackalloc byte[1] { 0x01 };

        Span<byte> sequence_data = stackalloc byte[sizeof(int)];

        // Convert sequence to bytes
        MemoryMarshal.Cast<byte, int>(sequence_data)[0] = sequence;

        // Allocate buffer for HMAC results
        Span<byte> K = stackalloc byte[hmac.HashSz];
        Span<byte> V = stackalloc byte[hmac.HashSz];

        // B
        K.Fill(0); // K = 00 00 00 ..

        // C
        V.Fill(0x01); // V = 01 01 01 ..

        // D
        hmac.Init(K); // K = HMAC_K(V || 00 || seed || 00 || personalization || 00 || sequence_data)
        hmac.Update(V);
        hmac.Update(separator_00);
        hmac.Update(seed);
        hmac.Update(separator_00);
        hmac.Update(personalization);
        hmac.Update(sequence_data);
        hmac.Digest(K);

        // E
        hmac.Init(K); // V = HMAC_K(V)
        hmac.Update(V);
        hmac.Digest(V);

        // F
        hmac.Init(K); // K = HMAC_K(V || 01 || seed || 01 || personalization || 01 || sequence_data)
        hmac.Update(V);
        hmac.Update(separator_01);
        hmac.Update(seed);
        hmac.Update(separator_01);
        hmac.Update(personalization);
        hmac.Update(sequence_data);
        hmac.Digest(K);

        // G
        hmac.Init(K); // V = HMAC_K(V)
        hmac.Update(V);
        hmac.Digest(V);

        // H
        int secret_byte_index = 0;
        Span<byte> secret_data = stackalloc byte[NUM_BYTES];

        while (true)
        {
            // H2
            hmac.Init(K); // V = HMAC_K(V)
            hmac.Update(V);
            hmac.Digest(V);

            // T = T || V
            Span<byte> src = V[..Math.Min(V.Length, secret_data.Length - secret_byte_index)];
            Span<byte> target = secret_data[secret_byte_index..];
            src.CopyTo(target);
            secret_byte_index += src.Length;

            if (secret_byte_index >= NUM_BYTES)
            {
                if (IsValidPrivateKey(secret_data))
                {
                    secret_data[..result.Length].CopyTo(result);
                    secret_data.Clear();
                    return;
                }

                // Doesn't meet the curve criteria,
                // start filling from zero
                secret_data.Clear();
                secret_byte_index = 0;
            }

            // H3
            hmac.Init(K);  // K = HMAC_K(V || 00 || seed || 00 || personalization)
            hmac.Update(V);
            hmac.Update(separator_00);
            hmac.Update(seed);
            hmac.Update(separator_00);
            hmac.Update(personalization);
            hmac.Digest(K);

            hmac.Init(K); // V = HMAC_K(V)
            hmac.Update(V);
            hmac.Digest(V);
        }
    }

    public void GenerateRandomSecret(Span<byte> result, ReadOnlySpan<byte> entropy)
    {
        Span<byte> rnd = stackalloc byte[32];
        RNG.Fill(rnd);
        GenerateDeterministicSecret<HMAC<SHA512>>(result, rnd, entropy, rnd.Length);
    }

    public void GenerateRandomNonce(Span<byte> result, ReadOnlySpan<byte> entropy)
    {
        Span<byte> rnd = stackalloc byte[32];
        RNG.Fill(rnd);
        GenerateDeterministicNonce<HMAC<SHA512>>(result, rnd, entropy, rnd.Length);
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

