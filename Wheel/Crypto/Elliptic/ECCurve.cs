using Wheel.Crypto.Elliptic.Internal.Curves;
using Wheel.Crypto.Elliptic.Internal.VeryLongInt;

namespace Wheel.Crypto.Elliptic
{
    /// <summary>
    /// Properties and methods every EC implementation must provide
    /// </summary>
    public struct ECCurve
    {
        public delegate void XSide_IMPL(Span<ulong> result, ReadOnlySpan<ulong> x);
        public delegate void ModSquare_IMPL(Span<ulong> result, ReadOnlySpan<ulong> left);
        public delegate void ModMult_IMPL(Span<ulong> result, Span<ulong> left, ReadOnlySpan<ulong> right);
        public delegate void DoubleJacobian_IMPL(Span<ulong> X1, Span<ulong> Y1, Span<ulong> Z1);

        private readonly ulong[] _p;
        private readonly ulong[] _n;
        private readonly ulong[] _half_n;
        private readonly ulong[] _G;
        private readonly ulong[] _b;

        private readonly XSide_IMPL _XSide;
        private readonly ModSquare_IMPL _ModSquare;
        private readonly ModMult_IMPL _ModMult;
        private readonly DoubleJacobian_IMPL _DoubleJacobian;

        public readonly string name { get; }
        public readonly int NUM_BITS { get; }
        public readonly int NUM_WORDS { get { return NUM_BITS / VLI_Common.WORD_BITS; } }
        public readonly int NUM_BYTES { get { return NUM_BITS / 8; } }
        public readonly int NUM_N_BITS { get; }
        public readonly int NUM_N_WORDS { get { return NUM_N_BITS / VLI_Common.WORD_BITS; } }
        public readonly int NUM_N_BYTES { get { return NUM_N_BITS / 8; } }

        public readonly ReadOnlySpan<ulong> p { get { return _p; } }
        public readonly ReadOnlySpan<ulong> n { get { return _n; } }
        public readonly ReadOnlySpan<ulong> half_n { get { return _half_n; } }
        public readonly ReadOnlySpan<ulong> G { get { return _G; } }
        public readonly ReadOnlySpan<ulong> b { get { return _b; } }

        public readonly XSide_IMPL XSide { get { return _XSide; } }
        public readonly ModSquare_IMPL ModSquare { get { return _ModSquare; } }
        public readonly ModMult_IMPL ModMult { get { return _ModMult; } }
        public readonly DoubleJacobian_IMPL DoubleJacobian { get { return _DoubleJacobian; } }

        private ECCurve(string name, int num_bits, int num_n_bits, ulong[] p, ulong[] n, ulong[] half_n, ulong[] G, ulong[] b, XSide_IMPL XSide, ModSquare_IMPL ModSquare, ModMult_IMPL ModMult, DoubleJacobian_IMPL DoubleJacobian)
        {
            this.name = name;
            NUM_BITS = num_bits;
            NUM_N_BITS = num_n_bits;
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
                "secp256k1",
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
    }
}
