using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Wheel.Crypto.Elliptic.Internal.Curves;
using Wheel.Crypto.Elliptic.Internal.VeryLongInt;

namespace Wheel.Crypto.Elliptic
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
    public readonly struct ECCurve
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
        public readonly ulong randomId;

        #region Curve's point coordinate size
        public readonly int NUM_BITS;
        public readonly int NUM_N_BITS;

        #region Calculated lengths
        public readonly int NUM_WORDS => NUM_BITS / VLI.WORD_BITS;
        public readonly int NUM_N_WORDS => NUM_N_BITS / VLI.WORD_BITS;
        public readonly int NUM_BYTES => NUM_BITS / 8;
        public readonly int NUM_N_BYTES => NUM_N_BITS / 8;
        #endregion
        #endregion

        #region Implementation pointers
        /*
         * NOTE: Pointers are used instead of delegates here on purpose. We cound use delegates but then the entire struct 
         *  and those types that are dependent on it would have been treated as the managed types and we don't want that.
         */

        private readonly unsafe delegate* managed<Span<ulong>, ReadOnlySpan<ulong>, void> XSide_Impl;
        private readonly unsafe delegate* managed<Span<ulong>, ReadOnlySpan<ulong>, void> ModSquare_Impl;
        private readonly unsafe delegate* managed<Span<ulong>, Span<ulong>, ReadOnlySpan<ulong>, void> ModMult_Impl;
        private readonly unsafe delegate* managed<Span<ulong>, Span<ulong>, Span<ulong>, void> DoubleJacobian_Impl;
        #endregion

        #region Implementation wrappers
        public unsafe void XSide(Span<ulong> result, ReadOnlySpan<ulong> x) => XSide_Impl(result, x);
        public unsafe void ModSquare(Span<ulong> result, ReadOnlySpan<ulong> left) => ModSquare_Impl(result, left);
        public unsafe void ModMult(Span<ulong> result, Span<ulong> left, ReadOnlySpan<ulong> right) => ModMult_Impl(result, left, right);
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

        private unsafe ECCurve(int num_bits, int num_n_bits, ulong[] p, ulong[] n, ulong[] half_n, ulong[] G, ulong[] b, delegate* managed<Span<ulong>, ReadOnlySpan<ulong>, void> XSide, delegate* managed<Span<ulong>, ReadOnlySpan<ulong>, void> ModSquare, delegate* managed<Span<ulong>, Span<ulong>, ReadOnlySpan<ulong>, void> ModMult, delegate* managed<Span<ulong>, Span<ulong>, Span<ulong>, void> DoubleJacobian)
        {
            Span<ulong> random = stackalloc ulong[1 + SECP256K1.NUM_BITS / VLI.WORD_BITS];
            RNG.Fill(random);

            randomId = random[0];

            #region Set curve constants
            NUM_BITS = num_bits;
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
            ModMult_Impl = ModMult;
            DoubleJacobian_Impl = DoubleJacobian;
        }

        /// <summary>
        /// Construct a new instance of the secp256k1 context.
        /// <returns></returns>
        public static unsafe ECCurve Get_SECP256K1()
        {
            return new ECCurve(
                SECP256K1.NUM_BITS,
                SECP256K1.NUM_N_BITS,
                SECP256K1.p,
                SECP256K1.n,
                SECP256K1.half_n,
                SECP256K1.G,
                SECP256K1.b,
                &SECP256K1.XSide,
                &SECP256K1.ModSquare,
                &SECP256K1.ModMult,
                &SECP256K1.DoubleJacobian
            );
        }

        public static bool operator ==( ECCurve x, ECCurve y )
        {
            return x.randomId == y.randomId;
        }

        public static bool operator != ( ECCurve x, ECCurve y )
        {
            return !(x == y);
        }
    }
}
