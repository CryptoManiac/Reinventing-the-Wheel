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
        Span<byte> secret_data = stackalloc byte[32];

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

            if (secret_byte_index >= 32)
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

    public bool IsValidPrivateKey(ReadOnlySpan<byte> data)
    {
        return data.Length == 32;
    }

    public bool IsValidPublicKey(ReadOnlySpan<byte> data)
    {
        return data.Length == 32;
    }
}

