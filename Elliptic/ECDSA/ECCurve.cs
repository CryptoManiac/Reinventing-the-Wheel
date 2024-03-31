using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
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

        public static void Fill(Span<byte> rnd)
        {
            lock (LockGuard)
            {
                RNG.gen.GetBytes(rnd);
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
    public readonly partial struct ECCurve : ICurve
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
        public readonly int NUM_WORDS { get; }
        public readonly int NUM_BYTES { get; }
        public readonly int NUM_N_BITS { get; }
        #endregion

        #region Implementation pointers
        /*
         * NOTE: Pointers are used instead of delegates here on purpose. We cound use delegates but then the entire struct 
         *  and those types that are dependent on it would have been treated as the managed types and we don't want that.
         */

        private readonly unsafe delegate* managed<in ECCurve, Span<ulong>, Span<ulong>, void> MMod_Impl;
        private readonly unsafe delegate* managed<in ECCurve, Span<ulong>, void> ModSQRT_Impl;
        private readonly unsafe delegate* managed<in ECCurve, Span<ulong>, ReadOnlySpan<ulong>, void> XSide_Impl;
        private readonly unsafe delegate* managed<in ECCurve, Span<ulong>, Span<ulong>, Span<ulong>, void> DoubleJacobian_Impl;
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
        #endregion

        private unsafe ECCurve(int num_n_bits, ReadOnlySpan<ulong> p, ReadOnlySpan<ulong> n, ReadOnlySpan<ulong> half_n, ReadOnlySpan<ulong> G, ReadOnlySpan<ulong> b, delegate* managed<in ECCurve, Span<ulong>, Span<ulong>, void> MMod, delegate* managed<in ECCurve, Span<ulong>, ReadOnlySpan<ulong>, void> XSide, delegate* managed<in ECCurve, Span<ulong>, void> ModSQRT, delegate* managed<in ECCurve, Span<ulong>, Span<ulong>, Span<ulong>, void> DoubleJacobian)
        {
            Span<ulong> random = stackalloc ulong[1 + NUM_WORDS];
            RNG.Fill(random);

            randomId = random[0];

            #region Set curve constants
            NUM_N_BITS = num_n_bits;
            NUM_WORDS = VLI.BitsToWords(num_n_bits);
            NUM_BYTES = VLI.BitsToBytes(num_n_bits);

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

            MMod_Impl = MMod;
            XSide_Impl = XSide;
            ModSQRT_Impl = ModSQRT;
            DoubleJacobian_Impl = DoubleJacobian;
        }

        /// <summary>
        /// Construct a new instance of the secp192r1 context.
        /// <returns></returns>
        public static unsafe ECCurve Get_SECP192R1()
        {
            return new ECCurve(
                192,
                stackalloc ulong[] { 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF },
                stackalloc ulong[] { 0x146BC9B1B4D22831, 0xFFFFFFFF99DEF836, 0xFFFFFFFFFFFFFFFF },
                stackalloc ulong[] { 0x0a35e4d8da691418, 0xffffffffccef7c1b, 0x7fffffffffffffff },
                stackalloc ulong[] { 0xF4FF0AFD82FF1012, 0x7CBF20EB43A18800, 0x188DA80EB03090F6, 0x73F977A11E794811, 0x631011ED6B24CDD5, 0x07192B95FFC8DA78 },
                stackalloc ulong[] { 0xFEB8DEECC146B9B1, 0x0FA7E9AB72243049, 0x64210519E59C80E7 },
                &MMod_SECP192R1,
                &XSide_Generic,
                &ModSQRT_Generic,
                &DoubleJacobian_Generic
            );
        }

        /// <summary>
        /// Construct a new instance of the secp224r1 context.
        /// <returns></returns>
        public static unsafe ECCurve Get_SECP224R1()
        {
            return new ECCurve(
                224,
                stackalloc ulong[] { 0x0000000000000001, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF },
                stackalloc ulong[] { 0x13DD29455C5C2A3D, 0xFFFF16A2E0B8F03E, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF },
                stackalloc ulong[] { 0x09ee94a2ae2e151e, 0xffff8b51705c781f, 0xffffffffffffffff, 0x7fffffff },
                stackalloc ulong[] { 0x343280D6115C1D21, 0x4A03C1D356C21122, 0x6BB4BF7F321390B9, 0xB70E0CBD, 0x44D5819985007E34, 0xCD4375A05A074764, 0xB5F723FB4C22DFE6, 0xBD376388 },
                stackalloc ulong[] { 0x270B39432355FFB4, 0x5044B0B7D7BFD8BA, 0x0C04B3ABF5413256, 0xB4050A85 },
                &MMod_SECP224R1,
                &XSide_Generic,
                &ModSQRT_SECP224R1,
                &DoubleJacobian_Generic
            );
        }

        /// <summary>
        /// Construct a new instance of the secp256r1 context.
        /// <returns></returns>
        public static unsafe ECCurve Get_SECP256R1()
        {
            return new ECCurve(
                256,
                stackalloc ulong[] { 0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF, 0x0000000000000000, 0xFFFFFFFF00000001 },
                stackalloc ulong[] { 0xF3B9CAC2FC632551, 0xBCE6FAADA7179E84, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF00000000 },
                stackalloc ulong[] { 0x79dce5617e3192a8, 0xde737d56d38bcf42, 0x7fffffff80000000, 0x7fffffff80000000 },
                stackalloc ulong[] { 0xF4A13945D898C296, 0x77037D812DEB33A0, 0xF8BCE6E563A440F2, 0x6B17D1F2E12C4247, 0xCBB6406837BF51F5, 0x2BCE33576B315ECE, 0x8EE7EB4A7C0F9E16, 0x4FE342E2FE1A7F9B },
                stackalloc ulong[] { 0x3BCE3C3E27D2604B, 0x651D06B0CC53B0F6, 0xB3EBBD55769886BC, 0x5AC635D8AA3A93E7 },
                &MMod_SECP256R1,
                &XSide_Generic,
                &ModSQRT_Generic,
                &DoubleJacobian_Generic
            );
        }

        /// <summary>
        /// Construct a new instance of the secp384r1 context.
        /// <returns></returns>
        public static unsafe ECCurve Get_SECP384R1()
        {
            return new ECCurve(
                384,
                stackalloc ulong[] { 0x00000000FFFFFFFF, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF },
                stackalloc ulong[] { 0xECEC196ACCC52973, 0x581A0DB248B0A77A, 0xC7634D81F4372DDF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF },
                stackalloc ulong[] { 0x76760cb5666294b9, 0xac0d06d9245853bd, 0xe3b1a6c0fa1b96ef, 0xffffffffffffffff, 0xffffffffffffffff, 0x7fffffffffffffff },
                stackalloc ulong[] {
                    0x3A545E3872760AB7, 0x5502F25DBF55296C, 0x59F741E082542A38, 0x6E1D3B628BA79B98, 0x8EB1C71EF320AD74, 0xAA87CA22BE8B0537,
                    0x7A431D7C90EA0E5F, 0x0A60B1CE1D7E819D, 0xE9DA3113B5F0B8C0, 0xF8F41DBD289A147C, 0x5D9E98BF9292DC29, 0x3617DE4A96262C6F
                },
                stackalloc ulong[] { 0x2A85C8EDD3EC2AEF, 0xC656398D8A2ED19D, 0x0314088F5013875A, 0x181D9C6EFE814112, 0x988E056BE3F82D19, 0xB3312FA7E23EE7E4 },
                &MMod_SECP384R1,
                &XSide_Generic,
                &ModSQRT_Generic,
                &DoubleJacobian_Generic
            );
        }

        /// <summary>
        /// Construct a new instance of the secp521r1 context.
        /// <returns></returns>
        public static unsafe ECCurve Get_SECP521R1()
        {
            return new ECCurve(
                521,
                stackalloc ulong[] {
                    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                    0x000001FF },
                stackalloc ulong[] {
                    0xBB6FB71E91386409, 0x3BB5C9B8899C47AE, 0x7FCC0148F709A5D0, 0x51868783BF2F966B,
                    0xFFFFFFFFFFFFFFFA, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                    0x000001FF },
                stackalloc ulong[] {
                    0x5db7db8f489c3204, 0x1ddae4dc44ce23d7, 0xbfe600a47b84d2e8, 0x28c343c1df97cb35,
                    0xfffffffffffffffd, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
                    0x00000ff
                },
                stackalloc ulong[] {
                    0xF97E7E31C2E5BD66, 0x3348B3C1856A429B, 0xFE1DC127A2FFA8DE, 0xA14B5E77EFE75928,
                    0xF828AF606B4D3DBA, 0x9C648139053FB521, 0x9E3ECB662395B442, 0x858E06B70404E9CD,
                    0x000000C6,
                    0x88BE94769FD16650, 0x353C7086A272C240, 0xC550B9013FAD0761, 0x97EE72995EF42640,
                    0x17AFBD17273E662C, 0x98F54449579B4468, 0x5C8A5FB42C7D1BD9, 0x39296A789A3BC004,
                    0x00000118
                },
                stackalloc ulong[] {
                    0xEF451FD46B503F00, 0x3573DF883D2C34F1, 0x1652C0BD3BB1BF07, 0x56193951EC7E937B,
                    0xB8B489918EF109E1, 0xA2DA725B99B315F3, 0x929A21A0B68540EE, 0x953EB9618E1C9A1F,
                    0x00000051
                },
                &MMod_SECP521R1,
                &XSide_Generic,
                &ModSQRT_Generic,
                &DoubleJacobian_Generic
            );
        }

        /// <summary>
        /// Construct a new instance of the secp256k1 context.
        /// <returns></returns>
        public static unsafe ECCurve Get_SECP256K1()
        {
            return new ECCurve(
                256,
                stackalloc ulong[] { 0xFFFFFFFEFFFFFC2F, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF },
                stackalloc ulong[] { 0xBFD25E8CD0364141, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF },
                stackalloc ulong[] { 0xdfe92f46681b20a0, 0x5d576e7357a4501d, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF },
                stackalloc ulong[] { 0x59F2815B16F81798, 0x029BFCDB2DCE28D9, 0x55A06295CE870B07, 0x79BE667EF9DCBBAC, 0x9C47D08FFB10D4B8, 0xFD17B448A6855419, 0x5DA4FBFC0E1108A8, 0x483ADA7726A3C465 },
                stackalloc ulong[] { 0x0000000000000007, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 },
                &MMod_SECP256K1,
                &XSide_SECP256K1,
                &ModSQRT_Generic,
                &DoubleJacobian_SECP256K1
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
        /// Maximum size of DER signature in bytes
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
        /// Generation of a random secret key on top of the .NET RandomNumberGenerator API. The security of this key will depend
        /// on the quality of the local RNG implementation. I suggest that you should treat these keys as unsecure by default,
        /// use this API with caution and never use the generated keys directly, without hashing. It will be a good idea to use
        /// the DeriveHMAC method to derive the children keys from them.
        /// </summary>
        /// <param name="result">Private key to be filled</param>
        /// <returns>True on success</returns>
        public bool GenerateRandomSecret(out IPrivateKey result)
        {
            // NOTE: There is some dark magic involved. The reason is that for shorter curve
            // lengths there is no guarantee that NUM_BYTES / sizeof(ulong) == NUM_WORDS holds true.
            Span<byte> random_key_bytes = stackalloc byte[NUM_BYTES];
            Span<ulong> random_key_words = stackalloc ulong[NUM_WORDS];
            RNG.Fill(random_key_bytes);
            // Convert to native and wrap, returning the result of attempt
            VLI.BytesToNative(random_key_words, random_key_bytes, NUM_BYTES);
            result = new ECPrivateKey(this);
            return result.Wrap(random_key_words);
        }

        /// <summary>
        /// Deterministically generate the new private key from seed, using HMAC-based generator
        /// </summary>
        /// <typeparam name="HMAC_IMPL">HMAC implementation to use</typeparam>
        /// <param name="result">Private key to be filled</param>
        /// <param name="seed">Secret seed to generate from</param>
        /// <param name="personalization">Personalization argument bytes (to generate more than one key from the same seed)</param>
        /// <param name="sequence">Generation sequence number (to generate more than one key from the same seed + personalization pair)</param>
        public void GenerateDeterministicSecret<HMAC_IMPL>(out IPrivateKey result, ReadOnlySpan<byte> seed, ReadOnlySpan<byte> personalization, int sequence) where HMAC_IMPL : unmanaged, IMac
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
