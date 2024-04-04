using System;

namespace EdDSA.Internal;

public static class ModM
{
    public const int ModM_WORDS = 5;

    static readonly ulong[] modm_m = [
        0x12631a5cf5d3ed,
        0xf9dea2f79cd658,
        0x000000000014de,
        0x00000000000000,
        0x00000010000000
    ];

    static readonly ulong[] modm_mu = [
        0x9ce5a30a2c131b,
        0x215d086329a7ed,
        0xffffffffeb2106,
        0xffffffffffffff,
        0x00000fffffffff
    ];


    public static ulong lt(ulong a, ulong b)
    {
        return (a - b) >> 63;
    }


    public static void reduce256(Span<ulong> r)
    {
        Span<ulong> t = stackalloc ulong[ModM_WORDS];
        ulong b = 0, pb, mask;

        /* t = r - m */
        pb = 0;
        pb += modm_m[0]; b = lt(r[0], pb); t[0] = (r[0] - pb + (b << 56)); pb = b;
        pb += modm_m[1]; b = lt(r[1], pb); t[1] = (r[1] - pb + (b << 56)); pb = b;
        pb += modm_m[2]; b = lt(r[2], pb); t[2] = (r[2] - pb + (b << 56)); pb = b;
        pb += modm_m[3]; b = lt(r[3], pb); t[3] = (r[3] - pb + (b << 56)); pb = b;
        pb += modm_m[4]; b = lt(r[4], pb); t[4] = (r[4] - pb + (b << 32));

        /* keep r if r was smaller than m */
        mask = b - 1;

        r[0] ^= mask & (r[0] ^ t[0]);
        r[1] ^= mask & (r[1] ^ t[1]);
        r[2] ^= mask & (r[2] ^ t[2]);
        r[3] ^= mask & (r[3] ^ t[3]);
        r[4] ^= mask & (r[4] ^ t[4]);
    }

    public static void barrett_reduce256(Span<ulong> r, ReadOnlySpan<ulong> q1, ReadOnlySpan<ulong> r1) {

        Span<ulong> q3 = stackalloc ulong[ModM_WORDS];
        Span<ulong> r2 = stackalloc ulong[ModM_WORDS];

        UInt128 c, mul;
        ulong f, b, pb;

        /* q1 = x >> 248 = 264 bits = 5 56 bit elements
           q2 = mu * q1
           q3 = (q2 / 256(32+1)) = q2 / (2^8)^(32+1) = q2 >> 264 */
        ASM.mul64x64_128(out c, modm_mu[0], q1[3]);
        ASM.mul64x64_128(out mul, modm_mu[3], q1[0]);
        ASM.add128(ref c, mul);
        ASM.mul64x64_128(out mul, modm_mu[1], q1[2]);
        ASM.add128(ref c, mul);
        ASM.mul64x64_128(out mul, modm_mu[2], q1[1]);
        ASM.add128(ref c, mul);
        ASM.shr128(out f, c, 56);
        ASM.mul64x64_128(out c, modm_mu[0], q1[4]);
        ASM.add128_64(ref c, f);
        ASM.mul64x64_128(out mul, modm_mu[4], q1[0]);
        ASM.add128(ref c, mul);
        ASM.mul64x64_128(out mul, modm_mu[3], q1[1]);
        ASM.add128(ref c, mul);
        ASM.mul64x64_128(out mul, modm_mu[1], q1[3]);
        ASM.add128(ref c, mul);
        ASM.mul64x64_128(out mul, modm_mu[2], q1[2]);
        ASM.add128(ref c, mul);

        f = ASM.lo128(c); q3[0] = (f >> 40) & 0xffff;
        ASM.shr128(out f, c, 56);
        ASM.mul64x64_128(out c, modm_mu[4], q1[1]);
        ASM.add128_64(ref c, f);
        ASM.mul64x64_128(out mul, modm_mu[1], q1[4]);
        ASM.add128(ref c, mul);
        ASM.mul64x64_128(out mul, modm_mu[2], q1[3]);
        ASM.add128(ref c, mul);
        ASM.mul64x64_128(out mul, modm_mu[3], q1[2]);
        ASM.add128(ref c, mul);

        f = ASM.lo128(c); q3[0] |= (f << 16) & 0xffffffffffffff;
        q3[1] = (f >> 40) & 0xffff;
        ASM.shr128(out f, c, 56);
        ASM.mul64x64_128(out c, modm_mu[4], q1[2]);
        ASM.add128_64(ref c, f);
        ASM.mul64x64_128(out mul, modm_mu[2], q1[4]);
        ASM.add128(ref c, mul);
        ASM.mul64x64_128(out mul, modm_mu[3], q1[3]);
        ASM.add128(ref c, mul);

        f = ASM.lo128(c);
        q3[1] |= (f << 16) & 0xffffffffffffff;
        q3[2] = (f >> 40) & 0xffff;
        ASM.shr128(out f, c, 56);
        ASM.mul64x64_128(out c, modm_mu[4], q1[3]);
        ASM.add128_64(ref c, f);
        ASM.mul64x64_128(out mul, modm_mu[3], q1[4]);
        ASM.add128(ref c, mul);

        f = ASM.lo128(c);
        q3[2] |= (f << 16) & 0xffffffffffffff;
        q3[3] = (f >> 40) & 0xffff;
        ASM.shr128(out f, c, 56);
        ASM.mul64x64_128(out c, modm_mu[4], q1[4]);
        ASM.add128_64(ref c, f);

        f = ASM.lo128(c); q3[3] |= (f << 16) & 0xffffffffffffff;
        q3[4] = (f >> 40) & 0xffff;
        ASM.shr128(out f, c, 56);
        q3[4] |= (f << 16);

        ASM.mul64x64_128(out c, modm_m[0], q3[0]);

        r2[0] = ASM.lo128(c) & 0xffffffffffffff;
        ASM.shr128(out f, c, 56);
        ASM.mul64x64_128(out c, modm_m[0], q3[1]);
        ASM.add128_64(ref c, f);
        ASM.mul64x64_128(out mul, modm_m[1], q3[0]);
        ASM.add128(ref c, mul);

        r2[1] = ASM.lo128(c) & 0xffffffffffffff;
        ASM.shr128(out f, c, 56);
        ASM.mul64x64_128(out c, modm_m[0], q3[2]);
        ASM.add128_64(ref c, f);
        ASM.mul64x64_128(out mul, modm_m[2], q3[0]);
        ASM.add128(ref c, mul);
        ASM.mul64x64_128(out mul, modm_m[1], q3[1]);
        ASM.add128(ref c, mul);

        r2[2] = ASM.lo128(c) & 0xffffffffffffff;
        ASM.shr128(out f, c, 56);
        ASM.mul64x64_128(out c, modm_m[0], q3[3]);
        ASM.add128_64(ref c, f);
        ASM.mul64x64_128(out mul, modm_m[3], q3[0]);
        ASM.add128(ref c, mul);
        ASM.mul64x64_128(out mul, modm_m[1], q3[2]);
        ASM.add128(ref c, mul);
        ASM.mul64x64_128(out mul, modm_m[2], q3[1]);
        ASM.add128(ref c, mul);

        r2[3] = ASM.lo128(c) & 0xffffffffffffff;
        ASM.shr128(out f, c, 56);
        ASM.mul64x64_128(out c, modm_m[0], q3[4]);
        ASM.add128_64(ref c, f);
        ASM.mul64x64_128(out mul, modm_m[4], q3[0]);
        ASM.add128(ref c, mul);
        ASM.mul64x64_128(out mul, modm_m[3], q3[1]);
        ASM.add128(ref c, mul);
        ASM.mul64x64_128(out mul, modm_m[1], q3[3]);
        ASM.add128(ref c, mul);
        ASM.mul64x64_128(out mul, modm_m[2], q3[2]);
        ASM.add128(ref c, mul);

        r2[4] = ASM.lo128(c) & 0x0000ffffffffff;

        pb = 0;
        pb += r2[0]; b = lt(r1[0], pb); r[0] = (r1[0] - pb + (b << 56)); pb = b;
        pb += r2[1]; b = lt(r1[1], pb); r[1] = (r1[1] - pb + (b << 56)); pb = b;
        pb += r2[2]; b = lt(r1[2], pb); r[2] = (r1[2] - pb + (b << 56)); pb = b;
        pb += r2[3]; b = lt(r1[3], pb); r[3] = (r1[3] - pb + (b << 56)); pb = b;
        pb += r2[4]; b = lt(r1[4], pb); r[4] = (r1[4] - pb + (b << 40));

        reduce256(r);
        reduce256(r);
    }

    public static void add256(Span<ulong> r, ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y) {

        ulong c;

        c = x[0] + y[0];
        r[0] = c & 0xffffffffffffff;
        c >>= 56;

        c += x[1] + y[1];
        r[1] = c & 0xffffffffffffff;
        c >>= 56;

        c += x[2] + y[2];
        r[2] = c & 0xffffffffffffff;
        c >>= 56;

        c += x[3] + y[3];
        r[3] = c & 0xffffffffffffff;
        c >>= 56;

        c += x[4] + y[4];
        r[4] = c;

        reduce256(r);
    }

    public static void mul256(Span<ulong> r, ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y) {

        Span<ulong> q1 = stackalloc ulong[ModM_WORDS];
        Span<ulong> r1 = stackalloc ulong[ModM_WORDS];
        UInt128 c, mul;
        ulong f;

        ASM.mul64x64_128(out c, x[0], y[0]);

        f = ASM.lo128(c);
        r1[0] = f & 0xffffffffffffff;
        ASM.shr128(out f, c, 56);
        ASM.mul64x64_128(out c, x[0], y[1]);
        ASM.add128_64(ref c, f);
        ASM.mul64x64_128(out mul, x[1], y[0]);
        ASM.add128(ref c, mul);

        f = ASM.lo128(c);
        r1[1] = f & 0xffffffffffffff;
        ASM.shr128(out f, c, 56);
        ASM.mul64x64_128(out c, x[0], y[2]);
        ASM.add128_64(ref c, f);
        ASM.mul64x64_128(out mul, x[2], y[0]);
        ASM.add128(ref c, mul);
        ASM.mul64x64_128(out mul, x[1], y[1]);
        ASM.add128(ref c, mul);

        f = ASM.lo128(c);
        r1[2] = f & 0xffffffffffffff;
        ASM.shr128(out f, c, 56);
        ASM.mul64x64_128(out c, x[0], y[3]);
        ASM.add128_64(ref c, f);
        ASM.mul64x64_128(out mul, x[3], y[0]);
        ASM.add128(ref c, mul);
        ASM.mul64x64_128(out mul, x[1], y[2]);
        ASM.add128(ref c, mul);
        ASM.mul64x64_128(out mul, x[2], y[1]);
        ASM.add128(ref c, mul);

        f = ASM.lo128(c);
        r1[3] = f & 0xffffffffffffff;
        ASM.shr128(out f, c, 56);
        ASM.mul64x64_128(out c, x[0], y[4]);
        ASM.add128_64(ref c, f);
        ASM.mul64x64_128(out mul, x[4], y[0]);
        ASM.add128(ref c, mul);
        ASM.mul64x64_128(out mul, x[3], y[1]);
        ASM.add128(ref c, mul);
        ASM.mul64x64_128(out mul, x[1], y[3]);
        ASM.add128(ref c, mul);
        ASM.mul64x64_128(out mul, x[2], y[2]);
        ASM.add128(ref c, mul);

        f = ASM.lo128(c);
        r1[4] = f & 0x0000ffffffffff;
        q1[0] = (f >> 24) & 0xffffffff;
        ASM.shr128(out f, c, 56);
        ASM.mul64x64_128(out c, x[4], y[1]);
        ASM.add128_64(ref c, f);
        ASM.mul64x64_128(out mul, x[1], y[4]);
        ASM.add128(ref c, mul);
        ASM.mul64x64_128(out mul, x[2], y[3]);
        ASM.add128(ref c, mul);
        ASM.mul64x64_128(out mul, x[3], y[2]);
        ASM.add128(ref c, mul);

        f = ASM.lo128(c); q1[0] |= (f << 32) & 0xffffffffffffff;
        q1[1] = (f >> 24) & 0xffffffff;
        ASM.shr128(out f, c, 56);
        ASM.mul64x64_128(out c, x[4], y[2]);
        ASM.add128_64(ref c, f);
        ASM.mul64x64_128(out mul, x[2], y[4]);
        ASM.add128(ref c, mul);
        ASM.mul64x64_128(out mul, x[3], y[3]);
        ASM.add128(ref c, mul);

        f = ASM.lo128(c); q1[1] |= (f << 32) & 0xffffffffffffff;
        q1[2] = (f >> 24) & 0xffffffff;
        ASM.shr128(out f, c, 56);
        ASM.mul64x64_128(out c, x[4], y[3]);
        ASM.add128_64(ref c, f);
        ASM.mul64x64_128(out mul, x[3], y[4]);
        ASM.add128(ref c, mul);

        f = ASM.lo128(c); q1[2] |= (f << 32) & 0xffffffffffffff;
        q1[3] = (f >> 24) & 0xffffffff;
        ASM.shr128(out f, c, 56);
        ASM.mul64x64_128(out c, x[4], y[4]);
        ASM.add128_64(ref c, f);

        f = ASM.lo128(c); q1[3] |= (f << 32) & 0xffffffffffffff;
        q1[4] = (f >> 24) & 0xffffffff;
        ASM.shr128(out f, c, 56);
        q1[4] |= (f << 32);

        barrett_reduce256(r, q1, r1);
    }

    public static void expand256(Span<ulong> @out, ReadOnlySpan<byte> @in, int len) {

        Span<byte> work = stackalloc byte[64] {
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        };
        Span<ulong> x = stackalloc ulong[16];
        Span<ulong> q1 = stackalloc ulong[ModM_WORDS];

        @in[..len].CopyTo(work);

        x[0] = Conv.U8TO64_LE(work);
        x[1] = Conv.U8TO64_LE(work[8..]);
        x[2] = Conv.U8TO64_LE(work[16..]);
        x[3] = Conv.U8TO64_LE(work[24..]);
        x[4] = Conv.U8TO64_LE(work[32..]);
        x[5] = Conv.U8TO64_LE(work[40..]);
        x[6] = Conv.U8TO64_LE(work[48..]);
        x[7] = Conv.U8TO64_LE(work[56..]);

        /* r1 = (x mod 256^(32+1)) = x mod (2^8)(31+1) = x & ((1 << 264) - 1) */
        @out[0] = (x[0]) & 0xffffffffffffff;
        @out[1] = ((x[0] >> 56) | (x[1] << 8)) & 0xffffffffffffff;
        @out[2] = ((x[1] >> 48) | (x[2] << 16)) & 0xffffffffffffff;
        @out[3] = ((x[2] >> 40) | (x[3] << 24)) & 0xffffffffffffff;
        @out[4] = ((x[3] >> 32) | (x[4] << 32)) & 0x0000ffffffffff;

        /* under 252 bits, no need to reduce */
        if (len < 32)
        {
            return;
        }

        /* q1 = x >> 248 = 264 bits */
        q1[0] = ((x[3] >> 56) | (x[4] << 8)) & 0xffffffffffffff;
        q1[1] = ((x[4] >> 48) | (x[5] << 16)) & 0xffffffffffffff;
        q1[2] = ((x[5] >> 40) | (x[6] << 24)) & 0xffffffffffffff;
        q1[3] = ((x[6] >> 32) | (x[7] << 32)) & 0xffffffffffffff;
        q1[4] = ((x[7] >> 24));

        barrett_reduce256(@out, q1, @out);
    }


    public static void expand_raw256(Span<ulong> @out, ReadOnlySpan<byte> @in) {
        Span<ulong> x = stackalloc ulong[4];

        x[0] = Conv.U8TO64_LE(@in[0..]);
        x[1] = Conv.U8TO64_LE(@in[8..]);
        x[2] = Conv.U8TO64_LE(@in[16..]);
        x[3] = Conv.U8TO64_LE(@in[24..]);

        @out[0] = (x[0]) & 0xffffffffffffff;
        @out[1] = ((x[0] >> 56) | (x[1] << 8)) & 0xffffffffffffff;
        @out[2] = ((x[1] >> 48) | (x[2] << 16)) & 0xffffffffffffff;
        @out[3] = ((x[2] >> 40) | (x[3] << 24)) & 0xffffffffffffff;
        @out[4] = ((x[3] >> 32)) & 0x000000ffffffff;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="out"></param>
    /// <param name="in">32 bytes long</param>
    public static void contract256(Span<byte> @out, ReadOnlySpan<ulong> @in) {

        Conv.U64TO8_LE(@out[0..], (@in[0]) | (@in[1] << 56));
        Conv.U64TO8_LE(@out[8..], (@in[1] >> 8) | (@in[2] << 48));
        Conv.U64TO8_LE(@out[16..], (@in[2] >> 16) | (@in[3] << 40));
        Conv.U64TO8_LE(@out[24..], (@in[3] >> 24) | (@in[4] << 32));
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="r">64 bytes long</param>
    /// <param name=""></param>
    public unsafe static void contract256_window4(Span<sbyte> r, ReadOnlySpan<ulong> @in)
    {
        fixed (sbyte* ptr = &r[0])
        {
            contract256_window4(ptr, @in);
        }
    }

    /// TODO: Consider reimplementing from scratch
    private unsafe static void contract256_window4(sbyte* r, ReadOnlySpan<ulong> @in)
    {
        sbyte carry;
        sbyte* quads = r;

        for (int i = 0; i < 5; i++)
        {
            ulong v = @in[i];
            int m = (i == 4) ? 8 : 14;
            for (int j = 0; j < m; j++)
            {
                *quads++ = (sbyte)(v & 15);
                v >>= 4;
            }
        }

        /* making it signed */
        carry = 0;
        for (int i = 0; i < 63; i++)
        {
            r[i] += carry;
            r[i + 1] += (sbyte)(r[i] >> 4);
            r[i] &= 15;
            carry = (sbyte)(r[i] >> 3);
            r[i] -= (sbyte)(carry << 4);
        }
        r[63] += carry;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="r">256 bytes long</param>
    /// <param name="s"></param>
    /// <param name="windowsize"></param>
    public static unsafe void contract256_slidingwindow(Span<sbyte> r, ReadOnlySpan<ulong> s, int windowsize)
    {
        fixed (sbyte* ptr = &r[0])
        {
            contract256_slidingwindow(ptr, s, windowsize);
        }
    }

    /// TODO: Consider reimplementing from scratch
    private unsafe static void contract256_slidingwindow(sbyte* r, ReadOnlySpan<ulong> s, int windowsize) {

        int i, j, k, b;
        int m = (1 << (windowsize - 1)) - 1, soplen = 256;
        sbyte* bits = r;
        ulong v;

        /* first put the binary expansion into r  */
        for (i = 0; i < 4; i++) {
            v = s[i];
            for (j = 0; j < 56; j++, v >>= 1)
                *bits++ = (sbyte)(v & 1);
        }

        v = s[4];

        for (j = 0; j < 32; j++, v >>= 1)
        {
            *bits++ = (sbyte)(v & 1);
        }

        /* Making it sliding window */
        for (j = 0; j < soplen; j++) {

            if (!Convert.ToBoolean(r[j]))
            {
                continue;
            }

            for (b = 1; (b < (soplen - j)) && (b <= 6); b++) {
                if ((r[j] + (r[j + b] << b)) <= m) {
                    r[j] += (sbyte)(r[j + b] << b);
                    r[j + b] = 0;
                }
                else if ((r[j] - (r[j + b] << b)) >= -m)
                {
                    r[j] -= (sbyte)(r[j + b] << b);
                    for (k = j + b; k < soplen; k++)
                    {
                        if (!Convert.ToBoolean(r[k]))
                        {
                            r[k] = 1;
                            break;
                        }
                        r[k] = 0;
                    }
                }
                else if (Convert.ToBoolean(r[j + b]))
                {
                    break;
                }
            }
        }
    }

    /// <summary>
    /// out = a - b, a must be larger than b
    /// </summary>
    /// <param name="out"></param>
    /// <param name="a"></param>
    /// <param name="b"></param>
    /// <param name="limbsize"></param>
    public static void sub256_modm_batch(Span<ulong> @out, ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, int limbsize) {
        int i = 0;
        ulong carry = 0;
        switch (limbsize) {
            case 4: @out[i] = (a[i] - b[i]); carry = (@out[i] >> 63); @out[i] &= 0xffffffffffffff; i++;
                goto case 3;
            case 3: @out[i] = (a[i] - b[i]) - carry; carry = (@out[i] >> 63); @out[i] &= 0xffffffffffffff; i++;
                goto case 2;
            case 2: @out[i] = (a[i] - b[i]) - carry; carry = (@out[i] >> 63); @out[i] &= 0xffffffffffffff; i++;
                goto case 1;
            case 1: @out[i] = (a[i] - b[i]) - carry; carry = (@out[i] >> 63); @out[i] &= 0xffffffffffffff; i++;
                goto case 0;
            case 0:
                goto default;
            default: @out[i] = (a[i] - b[i]) - carry;
                break;
        }
    }

    /// is a < b
    public static int lt256_modm_batch(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, int limbsize)
    {
        int i = 0;
        ulong t, carry = 0;
        switch (limbsize)
        {
            case 4: t = (a[i] - b[i]); carry = (t >> 63); i++;
                goto case 3;
            case 3: t = (a[i] - b[i]) - carry; carry = (t >> 63); i++;
                goto case 2;
            case 2: t = (a[i] - b[i]) - carry; carry = (t >> 63); i++;
                goto case 1;
            case 1: t = (a[i] - b[i]) - carry; carry = (t >> 63); i++;
                goto case 0;
            case 0: t = (a[i] - b[i]) - carry; carry = (t >> 63);
                break;
        }
        return (int)carry;
    }

    /// is a <= b
    public static bool lte256_modm_batch(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, int limbsize)
    {
        int i = 0;
        ulong t, carry = 0;
        switch (limbsize)
        {
            case 4: t = (b[i] - a[i]); carry = (t >> 63); i++;
                goto case 3;
            case 3: t = (b[i] - a[i]) - carry; carry = (t >> 63); i++;
                goto case 2;
            case 2: t = (b[i] - a[i]) - carry; carry = (t >> 63); i++;
                goto case 1;
            case 1: t = (b[i] - a[i]) - carry; carry = (t >> 63); i++;
                goto case 0;
            case 0: t = (b[i] - a[i]) - carry; carry = (t >> 63);
                break;
        }
        return !Convert.ToBoolean(carry);
    }

    /// <summary>
    /// is a == 0 
    /// </summary>
    /// <param name="a"></param>
    /// <returns></returns>
    public static bool iszero256_batch(ReadOnlySpan<ulong> a)
    {
        for (int i = 0; i < 5; i++)
        {
            if (0 != a[i])
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// is a == 1 
    /// </summary>
    /// <param name="a"></param>
    /// <returns></returns>
    public static bool isone256_batch(ReadOnlySpan<ulong> a)
    {
        for (int i = 0; i < 5; i++)
        {
            if (a[i] != (Convert.ToBoolean(i) ? 0u : 1u))
            {
                return false;
            }
        }
        return true;
    }

    /* can a fit in to (at most) 128 bits */
    public static bool isatmost128bits256_batch(ReadOnlySpan<ulong> a)
    {
        ulong mask =
            ((a[4]) | /*  32 */
             (a[3]) | /*  88 */
             (a[2] & 0xffffffffff0000));

        return (mask == 0);
    }
}
