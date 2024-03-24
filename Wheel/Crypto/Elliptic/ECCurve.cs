using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Wheel.Crypto.Elliptic.Internal.Curves;
using Wheel.Crypto.Elliptic.Internal.VeryLongInt;

namespace Wheel.Crypto.Elliptic
{
    /// <summary>
    /// Properties and methods every EC implementation must provide
    /// </summary>
    public readonly struct ECCurve
    {
        private static readonly RandomNumberGenerator RNG = RandomNumberGenerator.Create();
        private static object RNG_LOCK = new();

        public delegate void XSide_IMPL(Span<ulong> result, ReadOnlySpan<ulong> x);
        public delegate void ModSquare_IMPL(Span<ulong> result, ReadOnlySpan<ulong> left);
        public delegate void ModMult_IMPL(Span<ulong> result, Span<ulong> left, ReadOnlySpan<ulong> right);
        public delegate void DoubleJacobian_IMPL(Span<ulong> X1, Span<ulong> Y1, Span<ulong> Z1);

        private readonly ulong[] _scrambleKey;
        private readonly ulong[] _p;
        private readonly ulong[] _n;
        private readonly ulong[] _half_n;
        private readonly ulong[] _G;
        private readonly ulong[] _b;

        private readonly XSide_IMPL _XSide;
        private readonly ModSquare_IMPL _ModSquare;
        private readonly ModMult_IMPL _ModMult;
        private readonly DoubleJacobian_IMPL _DoubleJacobian;

        public readonly ulong randomId { get; }
        public readonly int NUM_BITS { get; }
        public readonly int NUM_WORDS => NUM_BITS / VLI.WORD_BITS; 
        public readonly int NUM_BYTES => NUM_BITS / 8;
        public readonly int NUM_N_BITS { get; }
        public readonly int NUM_N_WORDS => NUM_N_BITS / VLI.WORD_BITS; 
        public readonly int NUM_N_BYTES => NUM_N_BITS / 8;

        public readonly ReadOnlySpan<ulong> scrambleKey => _scrambleKey;

        public readonly ReadOnlySpan<ulong> p => _p;
        public readonly ReadOnlySpan<ulong> n => _n;
        public readonly ReadOnlySpan<ulong> half_n => _half_n;
        public readonly ReadOnlySpan<ulong> G => _G;
        public readonly ReadOnlySpan<ulong> b => _b;

        public readonly XSide_IMPL XSide => _XSide;
        public readonly ModSquare_IMPL ModSquare => _ModSquare;
        public readonly ModMult_IMPL ModMult => _ModMult;
        public readonly DoubleJacobian_IMPL DoubleJacobian => _DoubleJacobian;

        private ECCurve(int num_bits, int num_n_bits, ulong[] p, ulong[] n, ulong[] half_n, ulong[] G, ulong[] b, XSide_IMPL XSide, ModSquare_IMPL ModSquare, ModMult_IMPL ModMult, DoubleJacobian_IMPL DoubleJacobian)
        {
            // It's okay to allocate this in heap here since the lifetime of this value is not deterministic
            ulong[] random = new ulong[1 + SECP256K1.NUM_BITS / VLI.WORD_BITS];

            lock (RNG_LOCK)
            {
                Span<byte> byteView = MemoryMarshal.Cast<ulong, byte>(random);
                RNG.GetBytes(byteView);
            }

            this.randomId = random[0];
            NUM_BITS = num_bits;
            NUM_N_BITS = num_n_bits;
            _scrambleKey = random.Skip(1).ToArray();
            _p = p;
            _n = n;
            _half_n = half_n;
            _G = G;
            _b = b;
            _XSide = XSide;
            _ModSquare = ModSquare;
            _ModMult = ModMult;
            _DoubleJacobian = DoubleJacobian;
        }

        public static ECCurve Get_SECP256K1()
        {
            return new ECCurve(
                SECP256K1.NUM_BITS,
                SECP256K1.NUM_N_BITS,
                SECP256K1.p,
                SECP256K1.n,
                SECP256K1.half_n,
                SECP256K1.G,
                SECP256K1.b,
                SECP256K1.XSide,
                SECP256K1.ModSquare,
                SECP256K1.ModMult,
                SECP256K1.DoubleJacobian
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
