using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Crypto.Elliptic.EllipticCommon;
using Wheel.Crypto.Elliptic.ECDSA.Internal;
using Wheel.Hashing.HMAC;
using Hashing.Hashing.HMAC;
using Wheel.Hashing.SHA.SHA512;

namespace Wheel.Crypto.Elliptic.ECDSA;

#region Curve points
/// <summary>
/// A set of ECC curve points is defined as the separate structure because you can't declare fixed buffer as readonly
/// </summary>
internal struct CurveBuffers
{
    public unsafe fixed ulong scrambleKey[VLI.ECC_MAX_WORDS];
    public unsafe fixed ulong p[VLI.ECC_MAX_WORDS];
    public unsafe fixed ulong n[VLI.ECC_MAX_WORDS];
    public unsafe fixed ulong half_n[VLI.ECC_MAX_WORDS];
    public unsafe fixed ulong b[VLI.ECC_MAX_WORDS];
    public unsafe fixed ulong G[2 * VLI.ECC_MAX_WORDS];
    public unsafe fixed char name[16];
}
#endregion

/// <summary>
/// Properties and methods every EC implementation must provide
/// </summary>
public readonly partial struct SECPCurve : IGenericCurve
{
    /// <summary>
    /// Curve point parameters
    /// </summary>
    private readonly CurveBuffers curveBuffers;

    /// <summary>
    /// Random instance identifier
    /// </summary>
    public readonly ulong randomId { get; }

    #region Curve's point coordinate size
    public readonly int NUM_WORDS { get; }
    public readonly int NUM_BYTES { get; }
    public readonly int NUM_N_BITS { get; }
    #endregion

    #region Implementation pointers

    //
    // NOTE: Pointers are used instead of delegates here on purpose. We cound use delegates but then the entire struct 
    //  and those types that are dependent on it would have been treated as the managed types and we don't want that.
    //

    private readonly unsafe delegate* managed<in SECPCurve, Span<ulong>, Span<ulong>, void> MMod_Impl;
    private readonly unsafe delegate* managed<in SECPCurve, Span<ulong>, void> ModSQRT_Impl;
    private readonly unsafe delegate* managed<in SECPCurve, Span<ulong>, ReadOnlySpan<ulong>, void> XSide_Impl;
    private readonly unsafe delegate* managed<in SECPCurve, Span<ulong>, Span<ulong>, Span<ulong>, void> DoubleJacobian_Impl;
    #endregion

    #region Implementation wrappers
    /// <summary>
    /// Computes result = left^2 % p
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public unsafe void ModSquare(Span<ulong> result, ReadOnlySpan<ulong> left)
    {
        int num_words = NUM_WORDS;
        Span<ulong> product = stackalloc ulong[2 * num_words];
        VLI.Square(product, left, num_words);
        //VLI.MMod(result, product, p, num_words);
        MMod_Impl(this, result, product);
    }

    /// <summary>
    /// Computes result = (left * right) % p
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public unsafe void ModMult(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right)
    {
        int num_words = NUM_WORDS;
        Span<ulong> product = stackalloc ulong[2 * num_words];
        VLI.Mult(product, left, right, num_words);
        //VLI.MMod(result, product, p, num_words);
        MMod_Impl(this, result, product);
    }

    /// <summary>
    /// Double in place
    /// https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates
    /// </summary>
    /// <param name="X1"></param>
    /// <param name="Y1"></param>
    /// <param name="Z1"></param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public unsafe void DoubleJacobian(Span<ulong> X1, Span<ulong> Y1, Span<ulong> Z1) => DoubleJacobian_Impl(this, X1, Y1, Z1);

    /// <summary>
    /// Compute a = sqrt(a) (mod curve_p)
    /// </summary>
    /// <param name="result"></param>
    /// <param name="left"></param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public unsafe void ModSQRT(Span<ulong> a) => ModSQRT_Impl(this, a);

    /// <summary>
    /// Computes result = x^3 + b. Result must not overlap x.
    /// </summary>
    /// <param name="result"></param>
    /// <param name="x"></param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public unsafe void XSide(Span<ulong> result, ReadOnlySpan<ulong> x) => XSide_Impl(this, result, x);
    #endregion

    #region Curve constant getters
    public unsafe readonly ReadOnlySpan<ulong> ScrambleKey
    {
        get
        {
            fixed (ulong* ptr = &curveBuffers.scrambleKey[0])
            {
                return new ReadOnlySpan<ulong>(ptr, NUM_WORDS);
            }
        }
    }

    public unsafe readonly ReadOnlySpan<ulong> P
    {
        get
        {
            fixed (ulong* ptr = &curveBuffers.p[0])
            {
                return new ReadOnlySpan<ulong>(ptr, NUM_WORDS);
            }
        }
    }

    public unsafe readonly ReadOnlySpan<ulong> N
    {
        get
        {
            fixed (ulong* ptr = &curveBuffers.n[0])
            {
                return new ReadOnlySpan<ulong>(ptr, NUM_WORDS);
            }
        }
    }
    public unsafe readonly ReadOnlySpan<ulong> Half_N
    {
        get
        {
            fixed (ulong* ptr = &curveBuffers.half_n[0])
            {
                return new ReadOnlySpan<ulong>(ptr, NUM_WORDS);
            }
        }
    }

    public unsafe readonly ReadOnlySpan<ulong> G
    {
        get
        {
            fixed (ulong* ptr = &curveBuffers.G[0])
            {
                return new ReadOnlySpan<ulong>(ptr, 2 * NUM_WORDS);
            }
        }
    }

    public unsafe readonly ReadOnlySpan<ulong> B
    {
        get
        {
            fixed (ulong* ptr = &curveBuffers.b[0])
            {
                return new ReadOnlySpan<ulong>(ptr, NUM_WORDS);
            }
        }
    }

    public unsafe readonly ReadOnlySpan<char> name
    {
        get
        {
            fixed (char* ptr = &curveBuffers.name[0])
            {
                return new Span<char>(ptr, 12);
            }
        }
    }
    #endregion

    private unsafe SECPCurve(ReadOnlySpan<char> name, int num_n_bits, ReadOnlySpan<ulong> p, ReadOnlySpan<ulong> n, ReadOnlySpan<ulong> half_n, ReadOnlySpan<ulong> G, ReadOnlySpan<ulong> b, delegate* managed<in SECPCurve, Span<ulong>, Span<ulong>, void> MMod, delegate* managed<in SECPCurve, Span<ulong>, ReadOnlySpan<ulong>, void> XSide, delegate* managed<in SECPCurve, Span<ulong>, void> ModSQRT, delegate* managed<in SECPCurve, Span<ulong>, Span<ulong>, Span<ulong>, void> DoubleJacobian)
    {
        Span<ulong> random = stackalloc ulong[1 + NUM_WORDS];
        RNG.Fill(random);

        randomId = random[0];

        #region Set curve constants
        NUM_N_BITS = num_n_bits;
        NUM_WORDS = VLI.BitsToWords(num_n_bits);
        NUM_BYTES = VLI.BitsToBytes(num_n_bits);


        fixed (char* ptr = &curveBuffers.name[0])
        {
            name.CopyTo(new Span<char>(ptr, 12));
        }

        fixed (ulong* ptr = &curveBuffers.scrambleKey[0])
        {
            random[1..].CopyTo(new Span<ulong>(ptr, NUM_WORDS));
        }

        fixed (ulong* ptr = &curveBuffers.p[0])
        {
            p.CopyTo(new Span<ulong>(ptr, NUM_WORDS));
        }

        fixed (ulong* ptr = &curveBuffers.n[0])
        {
            n.CopyTo(new Span<ulong>(ptr, NUM_WORDS));
        }

        fixed (ulong* ptr = &curveBuffers.half_n[0])
        {
            half_n.CopyTo(new Span<ulong>(ptr, NUM_WORDS));
        }

        fixed (ulong* ptr = &curveBuffers.G[0])
        {
            G.CopyTo(new Span<ulong>(ptr, 2 * NUM_WORDS));
        }

        fixed (ulong* ptr = &curveBuffers.b[0])
        {
            b.CopyTo(new Span<ulong>(ptr, NUM_WORDS));
        }
        #endregion

        MMod_Impl = MMod;
        XSide_Impl = XSide;
        ModSQRT_Impl = ModSQRT;
        DoubleJacobian_Impl = DoubleJacobian;
    }

    public static bool operator ==(SECPCurve x, SECPCurve y)
    {
        return x.randomId == y.randomId;
    }

    public static bool operator !=(SECPCurve x, SECPCurve y)
    {
        return !(x == y);
    }

    /// <summary>
    /// Size of encoded private key in bytes
    /// </summary>
    public int PrivateKeySize => ECPrivateKey.GetEncodedSize(this);

    /// <summary>
    /// Size of uncompressed public key in bytes
    /// </summary>
    public int UncompressedPublicKeySize => ECPublicKey.GetUncompressedSize(this);

    /// <summary>
    /// Size of compressed public key in bytes
    /// </summary>
    public int CompressedPublicKeySize => ECPublicKey.GetCompressedSize(this);

    /// <summary>
    /// Maximum size of DER signature in bytes
    /// </summary>
    public int DERSignatureSize => DERSignature.GetEncodedSize(this);

    /// <summary>
    /// Size of compact signature in bytes
    /// </summary>
    public int CompactSignatureSize => CompactSignature.GetEncodedSize(this);

    /// <summary>
    /// Check whether the provided byte array contains a valid public key
    /// </summary>
    /// <param name="data">Public key bytes</param>
    /// <returns>True if valid</returns>
    public bool IsValidPublicKey(ReadOnlySpan<byte> data) => ECPublicKey.IsValidPublicKey(this, data);

    /// <summary>
    /// Check whether the provided byte array contains a valid private key
    /// </summary>
    /// <param name="data">Private key bytes</param>
    /// <returns>True if valid</returns>
    public bool IsValidPrivateKey(ReadOnlySpan<byte> data) => ECPrivateKey.IsValidPrivateKey(this, data);

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
    public void GenerateRandomSecret(out ECPrivateKey result, ReadOnlySpan<byte> entropy)
    {
        Span<ulong> rnd = stackalloc ulong[NUM_WORDS];
        GenerateRandomSecret(rnd, entropy);
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
    public void GenerateDeterministicSecret<HMAC_IMPL>(out ECPrivateKey result, ReadOnlySpan<byte> seed, ReadOnlySpan<byte> personalization, int sequence) where HMAC_IMPL : unmanaged, IMac
    {
        Span<ulong> rnd = stackalloc ulong[NUM_WORDS];
        GenerateDeterministicSecret<HMAC_IMPL>(rnd, seed, personalization, sequence);
        result = new(this, rnd);
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
    public void GenerateRandomSecret(Span<ulong> result, ReadOnlySpan<byte> entropy)
    {
        Span<byte> rnd = stackalloc byte[NUM_BYTES];
        GenerateRandomSecret(rnd, entropy);
        VLI.BytesToNative(result, rnd, NUM_BYTES);
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
    public void GenerateDeterministicSecret<HMAC_IMPL>(Span<ulong> result, ReadOnlySpan<byte> seed, ReadOnlySpan<byte> personalization, int sequence) where HMAC_IMPL : unmanaged, IMac
    {
        Span<byte> rnd = stackalloc byte[NUM_BYTES];
        GenerateDeterministicSecret<HMAC_IMPL>(rnd, seed, personalization, sequence);
        VLI.BytesToNative(result, rnd, NUM_BYTES);
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
    public void GenerateRandomSecret(Span<byte> result, ReadOnlySpan<byte> entropy)
    {
        Span<byte> rnd = stackalloc byte[NUM_BYTES];
        RNG.Fill(rnd);
        GenerateDeterministicSecret<HMAC<SHA512>>(result, rnd, entropy, 0);
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
}
