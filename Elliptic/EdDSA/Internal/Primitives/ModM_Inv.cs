using System.Runtime.CompilerServices;

namespace  Wheel.Crypto.Elliptic.EdDSA.Internal;

public static partial class ModM
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void sq256(Span<ulong> s, ReadOnlySpan<ulong> a)
    {
        mul256(s, a, a);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void sqmul256(Span<ulong> s, int n, ReadOnlySpan<ulong> a)
    {
        for (int i = 0; i < n; i++) {
            sq256(s, s);
        }
        mul256(s, s, a);
    }
    
    [SkipLocalsInit]
    public static void invert256(Span<ulong> recip, ReadOnlySpan<ulong> s)
    {
        // https://github.com/dalek-cryptography/curve25519-dalek/blob/main/curve25519-dalek/src/scalar.rs#L1148
        Span<ulong> _10 = stackalloc ulong[ModM_WORDS];
        Span<ulong> _100 = stackalloc ulong[ModM_WORDS];
        Span<ulong> _11 = stackalloc ulong[ModM_WORDS];
        Span<ulong> _101 = stackalloc ulong[ModM_WORDS];
        Span<ulong> _111 = stackalloc ulong[ModM_WORDS];
        Span<ulong> _1001 = stackalloc ulong[ModM_WORDS];
        Span<ulong> _1011 = stackalloc ulong[ModM_WORDS];
        Span<ulong> _1111 = stackalloc ulong[ModM_WORDS];

        sq256(_10, s);
        sq256(_100, _10);
        mul256(_11, _10, s);
        mul256(_101, _10, _11);
        mul256(_111, _10, _101);
        mul256(_1001, _10, _111);
        mul256(_1011, _10, _1001);
        mul256(_1111, _100, _1011);
        mul256(recip, _1111, s);

        sqmul256(recip, 123 + 3, _101);
        sqmul256(recip, 2 + 2, _11);
        sqmul256(recip, 1 + 4, _1111);
        sqmul256(recip, 1 + 4, _1111);
        sqmul256(recip, 4, _1001);
        sqmul256(recip, 2, _11);
        sqmul256(recip, 1 + 4, _1111);
        sqmul256(recip, 1 + 3, _101);
        sqmul256(recip, 3 + 3, _101);
        sqmul256(recip, 3, _111);
        sqmul256(recip, 1 + 4, _1111);
        sqmul256(recip, 2 + 3, _111);
        sqmul256(recip, 2 + 2, _11);
        sqmul256(recip, 1 + 4, _1011);
        sqmul256(recip, 2 + 4, _1011);
        sqmul256(recip, 6 + 4, _1001);
        sqmul256(recip, 2 + 2, _11);
        sqmul256(recip, 3 + 2, _11);
        sqmul256(recip, 3 + 2, _11);
        sqmul256(recip, 1 + 4, _1001);
        sqmul256(recip, 1 + 3, _111);
        sqmul256(recip, 2 + 4, _1111);
        sqmul256(recip, 1 + 4, _1011);
        sqmul256(recip, 3, _101);
        sqmul256(recip, 2 + 4, _1111);
        sqmul256(recip, 3, _101);
        sqmul256(recip, 1 + 2, _11);
    }
}
