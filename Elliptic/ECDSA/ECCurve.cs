using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Wheel.Crypto.Elliptic.ECDSA.Internal.Curves;
using Wheel.Crypto.Elliptic.EllipticCommon;
using Wheel.Crypto.Elliptic.EllipticCommon.VeryLongInt;
using Wheel.Hashing.HMAC;

namespace Wheel.Crypto.Elliptic.ECDSA
{
    #region Random number generator
    internal static class RNG
    {
        private static RandomNumberGenerator gen = RandomNumberGenerator.Create();
        private static object LockGuard = new();

        public static void Fill(Span<ulong> rnd)
        {
            lock (LockGuard)
            {
                Span<byte> byteView = MemoryMarshal.Cast<ulong, byte>(rnd);
                RNG.gen.GetBytes(byteView);
            }
        }
    }
    #endregion

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
        private const int BuferSize = VLI.ECC_MAX_WORDS * VLI.WORD_SIZE;
        private const int DoubleBuferSize = 2 * VLI.ECC_MAX_WORDS * VLI.WORD_SIZE;
        public const int TotalSize = 5 * BuferSize + DoubleBuferSize;
    }
    #endregion

    /// <summary>
    /// Properties and methods every EC implementation must provide
    /// </summary>
#pragma warning disable CS0661
#pragma warning disable CS0660
    public readonly struct ECCurve : ICurve
#pragma warning restore CS0660
#pragma warning restore CS0661
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
        #region Calculated lengths
        public readonly int NUM_WORDS => VLI.BitsToWords(NUM_N_BITS);
        public readonly int NUM_BYTES => VLI.BitsToBytes(NUM_N_BITS);
        #endregion

        public readonly int NUM_N_BITS { get; }
        #endregion

        #region Implementation pointers
        /*
         * NOTE: Pointers are used instead of delegates here on purpose. We cound use delegates but then the entire struct 
         *  and those types that are dependent on it would have been treated as the managed types and we don't want that.
         */

        private readonly unsafe delegate* managed<Span<ulong>, ReadOnlySpan<ulong>, void> XSide_Impl;
        private readonly unsafe delegate* managed<Span<ulong>, ReadOnlySpan<ulong>, void> ModSquare_Impl;
        private readonly unsafe delegate* managed<Span<ulong>, void> ModSQRT_Impl;
        private readonly unsafe delegate* managed<Span<ulong>, ReadOnlySpan<ulong>, ReadOnlySpan<ulong>, void> ModMult_Impl;
        private readonly unsafe delegate* managed<Span<ulong>, Span<ulong>, Span<ulong>, void> DoubleJacobian_Impl;
        #endregion

        #region Implementation wrappers
        /// <summary>
        /// Computes result = x^3 + b. Result must not overlap x.
        /// </summary>
        /// <param name="result"></param>
        /// <param name="x"></param>
        public unsafe void XSide(Span<ulong> result, ReadOnlySpan<ulong> x) => XSide_Impl(result, x);

        /// <summary>
        /// Computes result = left^2 % p
        /// </summary>
        /// <param name="result"></param>
        /// <param name="left"></param>
        public unsafe void ModSquare(Span<ulong> result, ReadOnlySpan<ulong> left) => ModSquare_Impl(result, left);

        /// <summary>
        /// Compute a = sqrt(a) (mod curve_p)
        /// </summary>
        /// <param name="result"></param>
        /// <param name="left"></param>
        public unsafe void ModSQRT(Span<ulong> a) => ModSQRT_Impl(a);

        /// <summary>
        /// Computes result = (left * right) % p
        /// </summary>
        /// <param name="result"></param>
        /// <param name="left"></param>
        /// <param name="right"></param>
        public unsafe void ModMult(Span<ulong> result, Span<ulong> left, ReadOnlySpan<ulong> right) => ModMult_Impl(result, left, right);

        /// <summary>
        /// Double in place
        /// https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates
        /// </summary>
        /// <param name="X1"></param>
        /// <param name="Y1"></param>
        /// <param name="Z1"></param>
        public unsafe void DoubleJacobian(Span<ulong> X1, Span<ulong> Y1, Span<ulong> Z1) => DoubleJacobian_Impl(X1, Y1, Z1);
        #endregion

        #region Curve constant getters
        public unsafe readonly ReadOnlySpan<ulong> scrambleKey
        {
            get
            {
                fixed (ulong* ptr = &curveBuffers.scrambleKey[0])
                {
                    return new ReadOnlySpan<ulong>(ptr, NUM_WORDS);
                }
            }
        }

        public unsafe readonly ReadOnlySpan<ulong> p
        {
            get
            {
                fixed (ulong* ptr = &curveBuffers.p[0])
                {
                    return new ReadOnlySpan<ulong>(ptr, NUM_WORDS);
                }
            }
        }

        public unsafe readonly ReadOnlySpan<ulong> n
        {
            get
            {
                fixed (ulong* ptr = &curveBuffers.n[0])
                {
                    return new ReadOnlySpan<ulong>(ptr, NUM_WORDS);
                }
            }
        }
        public unsafe readonly ReadOnlySpan<ulong> half_n
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

        public unsafe readonly ReadOnlySpan<ulong> b
        {
            get
            {
                fixed (ulong* ptr = &curveBuffers.b[0])
                {
                    return new ReadOnlySpan<ulong>(ptr, NUM_WORDS);
                }
            }
        }
        #endregion

        private unsafe ECCurve(int num_n_bits, ulong[] p, ulong[] n, ulong[] half_n, ulong[] G, ulong[] b, delegate* managed<Span<ulong>, ReadOnlySpan<ulong>, void> XSide, delegate* managed<Span<ulong>, ReadOnlySpan<ulong>, void> ModSquare, delegate* managed<Span<ulong>, void> ModSQRT, delegate* managed<Span<ulong>, ReadOnlySpan<ulong>, ReadOnlySpan<ulong>, void> ModMult, delegate* managed<Span<ulong>, Span<ulong>, Span<ulong>, void> DoubleJacobian)
        {
            Span<ulong> random = stackalloc ulong[1 + VLI.BitsToWords(NUM_N_BITS)];
            RNG.Fill(random);

            randomId = random[0];

            #region Set curve constants
            NUM_N_BITS = num_n_bits;

            fixed (ulong* ptr = &curveBuffers.scrambleKey[0])
            {
                random.Slice(1).CopyTo(new Span<ulong>(ptr, NUM_WORDS));
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

            XSide_Impl = XSide;
            ModSquare_Impl = ModSquare;
            ModSQRT_Impl = ModSQRT;
            ModMult_Impl = ModMult;
            DoubleJacobian_Impl = DoubleJacobian;
        }

        /// <summary>
        /// Construct a new instance of the secp256k1 context.
        /// <returns></returns>
        public static unsafe ECCurve Get_SECP256K1()
        {
            return new ECCurve(
                SECP256K1.NUM_N_BITS,
                SECP256K1.p,
                SECP256K1.n,
                SECP256K1.half_n,
                SECP256K1.G,
                SECP256K1.b,
                &SECP256K1.XSide,
                &SECP256K1.ModSquare,
                &SECP256K1.ModSQRT,
                &SECP256K1.ModMult,
                &SECP256K1.DoubleJacobian
            );
        }

        /// <summary>
        /// Construct a new instance of the secp256r1 context.
        /// <returns></returns>
        public static unsafe ECCurve Get_SECP256R1()
        {
            return new ECCurve(
                SECP256R1.NUM_N_BITS,
                SECP256R1.p,
                SECP256R1.n,
                SECP256R1.half_n,
                SECP256R1.G,
                SECP256R1.b,
                &SECP256R1.XSide,
                &SECP256R1.ModSquare,
                &SECP256R1.ModSQRT,
                &SECP256R1.ModMult,
                &SECP256R1.DoubleJacobian
            );
        }

        /// <summary>
        /// Construct a new instance of the secp224r1 context.
        /// <returns></returns>
        public static unsafe ECCurve Get_SECP224R1()
        {
            return new ECCurve(
                SECP224R1.NUM_N_BITS,
                SECP224R1.p,
                SECP224R1.n,
                SECP224R1.half_n,
                SECP224R1.G,
                SECP224R1.b,
                &SECP224R1.XSide,
                &SECP224R1.ModSquare,
                &SECP224R1.ModSQRT,
                &SECP224R1.ModMult,
                &SECP224R1.DoubleJacobian
            );
        }

        public static bool operator ==(ECCurve x, ECCurve y)
        {
            return x.randomId == y.randomId;
        }

        public static bool operator !=(ECCurve x, ECCurve y)
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
        /// Sise of DER signature in bytes
        /// </summary>
        public int DERSignatureSize => DERSignature.GetEncodedSize(this);

        /// <summary>
        /// Size of compact signature in bytes
        /// </summary>
        public int CompactSignatureSize => CompactSignature.GetEncodedSize(this);

        /// <summary>
        /// Make an empty (invalid) private key for this curve
        /// </summary>
        /// <returns>A zero-initialized private key</returns>
        public IPublicKey MakePublicKey() => new ECPublicKey(this);

        /// <summary>
        /// Make an empty (invalid) private key for this curve
        /// </summary>
        /// <returns>A zero-initialized private key</returns>
        public IPrivateKey MakePrivateKey() => new ECPrivateKey(this);

        /// <summary>
        /// Make an empty (invalid) DER signature for this curve
        /// </summary>
        /// <returns>A zero-initialized DER signature</returns>
        public DERSignature MakeDERSignature() => new(this);

        /// <summary>
        /// Make an empty (invalid) compact signature for this curve
        /// </summary>
        /// <returns>A zero-initialized compact signature</returns>
        public CompactSignature MakeCompactSignature() => new(this);

        /// <summary>
        /// Parse public key bytes and construct new instance from them
        /// </summary>
        /// <param name="data">Public key bytes</param>
        /// <returns>A new copy of public key structure</returns>
        public IPublicKey MakePublicKey(ReadOnlySpan<byte> data) => new ECPublicKey(this, data);

        /// <summary>
        /// Parse private key bytes and construct new instance from them
        /// </summary>
        /// <param name="data">Private key bytes</param>
        /// <returns>A new copy of private key structure</returns>
        public IPrivateKey MakePrivateKey(ReadOnlySpan<byte> data) => new ECPrivateKey(this, data);

        /// <summary>
        /// Parse DER signature bytes and construct new instance from them
        /// </summary>
        /// <param name="data">DER signature bytes</param>
        /// <returns>A new copy of DER signature structure</returns>
        public DERSignature MakeDERSignature(ReadOnlySpan<byte> data) => new(this, data);

        /// <summary>
        /// Parse DER signature bytes and construct new instance from them
        /// </summary>
        /// <param name="data">DER signature bytes</param>
        /// <param name="nonCanonical">Allow negative R and S values</param>
        /// <returns>A new copy of DER signature structure</returns>
        public DERSignature MakeDERSignature(ReadOnlySpan<byte> data, bool nonCanonical) => new(this, data, nonCanonical);

        /// <summary>
        /// Parse compact signature bytes and construct new instance from them
        /// </summary>
        /// <param name="data">Compact signature bytes</param>
        /// <returns>A new copy of compact signature structure</returns>
        public CompactSignature MakeCompactSignature(ReadOnlySpan<byte> data) => new(this, data);

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
        /// Deterministically generate the new private key from seed, using HMAC-based generator
        /// </summary>
        /// <typeparam name="HMAC_IMPL">HMAC implementation to use</typeparam>
        /// <param name="result">Private key to be filled</param>
        /// <param name="seed">Secret seed to generate from</param>
        /// <param name="personalization">Personalization argument bytes (to generate more than one key from the same seed)</param>
        /// <param name="sequence">Generation sequence number (to generate more than one key from the same seed + personalization pair)</param>
        public void GenerateSecret<HMAC_IMPL>(out IPrivateKey result, ReadOnlySpan<byte> seed, ReadOnlySpan<byte> personalization, int sequence) where HMAC_IMPL : unmanaged, IMac
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
                Span<byte> src = V.Slice(0, Math.Min(V.Length, secret_data.Length - secret_byte_index));
                Span<byte> target = secret_data.Slice(secret_byte_index);
                src.CopyTo(target);
                secret_byte_index += src.Length;

                if (secret_byte_index >= NUM_BYTES)
                {
                    if (IsValidPrivateKey(secret_data))
                    {
                        result = MakePrivateKey(secret_data);
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
}
