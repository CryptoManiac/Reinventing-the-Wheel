using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Crypto.Elliptic.EdDSA.Internal.Platform;

namespace Wheel.Crypto.Elliptic.EdDSA.Internal.Curve25519;

internal static class EdMath
{
	private const ulong reduce_mask_40 = ((ulong)1 << 40) - 1;
	private const ulong reduce_mask_51 = ((ulong)1 << 51) - 1;
	private const ulong reduce_mask_56 = ((ulong)1 << 56) - 1;

    /// <summary>
    /// out = in
    /// </summary>
    /// <param name="_out"></param>
    /// <param name="_in"></param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void curve25519_copy(Span<ulong> _out, ReadOnlySpan<ulong> _in)
	{
		_out[0] = _in[0];
		_out[1] = _in[1];
		_out[2] = _in[2];
		_out[3] = _in[3];
		_out[4] = _in[4];
	}

    /// <summary>
    /// _out = a + b
    /// </summary>
    /// <param name="_out"></param>
    /// <param name="a"></param>
    /// <param name="b"></param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void curve25519_add(Span<ulong> _out, ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b)
	{
		_out[0] = a[0] + b[0];
		_out[1] = a[1] + b[1];
		_out[2] = a[2] + b[2];
		_out[3] = a[3] + b[3];
		_out[4] = a[4] + b[4];
	}

    /// <summary>
    /// _out = a + b, where a and/or b are the result of a basic op (add,sub)
    /// </summary>
    /// <param name="_out"></param>
    /// <param name="a"></param>
    /// <param name="b"></param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void curve25519_add_after_basic(Span<ulong> _out, ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b)
	{
		_out[0] = a[0] + b[0];
		_out[1] = a[1] + b[1];
		_out[2] = a[2] + b[2];
		_out[3] = a[3] + b[3];
		_out[4] = a[4] + b[4];
	}

    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void curve25519_add_reduce(Span<ulong> _out, ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b)
	{
		ulong c;
		_out[0] = a[0] + b[0]; c = (_out[0] >> 51); _out[0] &= reduce_mask_51;
		_out[1] = a[1] + b[1] + c; c = (_out[1] >> 51); _out[1] &= reduce_mask_51;
		_out[2] = a[2] + b[2] + c; c = (_out[2] >> 51); _out[2] &= reduce_mask_51;
		_out[3] = a[3] + b[3] + c; c = (_out[3] >> 51); _out[3] &= reduce_mask_51;
		_out[4] = a[4] + b[4] + c; c = (_out[4] >> 51); _out[4] &= reduce_mask_51;
		_out[0] += c * 19;
	}

	/* multiples of p */
	private const ulong twoP0 = 0x0fffffffffffda;
	private const ulong twoP1234 = 0x0ffffffffffffe;
	private const ulong fourP0 = 0x1fffffffffffb4;
	private const ulong fourP1234 = 0x1ffffffffffffc;

    /// <summary>
    /// _out = a - b
    /// </summary>
    /// <param name="_out"></param>
    /// <param name="a"></param>
    /// <param name="b"></param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void curve25519_sub(Span<ulong> _out, ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b)
	{
		_out[0] = a[0] + twoP0 - b[0];
		_out[1] = a[1] + twoP1234 - b[1];
		_out[2] = a[2] + twoP1234 - b[2];
		_out[3] = a[3] + twoP1234 - b[3];
		_out[4] = a[4] + twoP1234 - b[4];
	}

    /// <summary>
    /// _out = a - b, where a and/or b are the result of a basic op (add,sub)
    /// </summary>
    /// <param name="_out"></param>
    /// <param name="a"></param>
    /// <param name="b"></param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void curve25519_sub_after_basic(Span<ulong> _out, ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b)
	{
		_out[0] = a[0] + fourP0 - b[0];
		_out[1] = a[1] + fourP1234 - b[1];
		_out[2] = a[2] + fourP1234 - b[2];
		_out[3] = a[3] + fourP1234 - b[3];
		_out[4] = a[4] + fourP1234 - b[4];
	}

    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void curve25519_sub_reduce(Span<ulong> _out, ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b)
	{
		ulong c;
		_out[0] = a[0] + fourP0 - b[0]; c = (_out[0] >> 51); _out[0] &= reduce_mask_51;
		_out[1] = a[1] + fourP1234 - b[1] + c; c = (_out[1] >> 51); _out[1] &= reduce_mask_51;
		_out[2] = a[2] + fourP1234 - b[2] + c; c = (_out[2] >> 51); _out[2] &= reduce_mask_51;
		_out[3] = a[3] + fourP1234 - b[3] + c; c = (_out[3] >> 51); _out[3] &= reduce_mask_51;
		_out[4] = a[4] + fourP1234 - b[4] + c; c = (_out[4] >> 51); _out[4] &= reduce_mask_51;
		_out[0] += c * 19;
	}

    /// <summary>
    /// _out = -a
    /// </summary>
    /// <param name="_out"></param>
    /// <param name="a"></param>
    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void curve25519_neg(Span<ulong> _out, ReadOnlySpan<ulong> a)
	{
		ulong c;
		_out[0] = twoP0 - a[0]; c = (_out[0] >> 51); _out[0] &= reduce_mask_51;
		_out[1] = twoP1234 - a[1] + c; c = (_out[1] >> 51); _out[1] &= reduce_mask_51;
		_out[2] = twoP1234 - a[2] + c; c = (_out[2] >> 51); _out[2] &= reduce_mask_51;
		_out[3] = twoP1234 - a[3] + c; c = (_out[3] >> 51); _out[3] &= reduce_mask_51;
		_out[4] = twoP1234 - a[4] + c; c = (_out[4] >> 51); _out[4] &= reduce_mask_51;
		_out[0] += c * 19;
	}

    /// <summary>
    /// out = a * b
    /// </summary>
    /// <param name="_out"></param>
    /// <param name="_in2"></param>
    /// <param name="_in"></param>
    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void curve25519_mul(Span<ulong> _out, ReadOnlySpan<ulong> _in2, ReadOnlySpan<ulong> _in)
	{
		Span<UInt128> t = stackalloc UInt128[5];
		ulong r0, r1, r2, r3, r4, s0, s1, s2, s3, s4, c;

		r0 = _in[0];
		r1 = _in[1];
		r2 = _in[2];
		r3 = _in[3];
		r4 = _in[4];

		s0 = _in2[0];
		s1 = _in2[1];
		s2 = _in2[2];
		s3 = _in2[3];
		s4 = _in2[4];

		t[0] = ((UInt128)r0) * s0;
		t[1] = ((UInt128)r0) * s1 + ((UInt128)r1) * s0;
		t[2] = ((UInt128)r0) * s2 + ((UInt128)r2) * s0 + ((UInt128)r1) * s1;
		t[3] = ((UInt128)r0) * s3 + ((UInt128)r3) * s0 + ((UInt128)r1) * s2 + ((UInt128)r2) * s1;
		t[4] = ((UInt128)r0) * s4 + ((UInt128)r4) * s0 + ((UInt128)r3) * s1 + ((UInt128)r1) * s3 + ((UInt128)r2) * s2;

		r1 *= 19;
		r2 *= 19;
		r3 *= 19;
		r4 *= 19;

		t[0] += ((UInt128)r4) * s1 + ((UInt128)r1) * s4 + ((UInt128)r2) * s3 + ((UInt128)r3) * s2;
		t[1] += ((UInt128)r4) * s2 + ((UInt128)r2) * s4 + ((UInt128)r3) * s3;
		t[2] += ((UInt128)r4) * s3 + ((UInt128)r3) * s4;
		t[3] += ((UInt128)r4) * s4;


		r0 = ASM.lo128(t[0]) & reduce_mask_51;
		ASM.shr128(out c, t[0], 51);
		ASM.add128_64(ref t[1], c);
		r1 = ASM.lo128(t[1]) & reduce_mask_51;
		ASM.shr128(out c, t[1], 51);
		ASM.add128_64(ref t[2], c);
		r2 = ASM.lo128(t[2]) & reduce_mask_51;
		ASM.shr128(out c, t[2], 51);
		ASM.add128_64(ref t[3], c);
		r3 = ASM.lo128(t[3]) & reduce_mask_51;
		ASM.shr128(out c, t[3], 51);
		ASM.add128_64(ref t[4], c);
		r4 = ASM.lo128(t[4]) & reduce_mask_51;
		ASM.shr128(out c, t[4], 51);
		r0 += c * 19; c = r0 >> 51;
		r0 = r0 & reduce_mask_51;
		r1 += c;

		_out[0] = r0;
		_out[1] = r1;
		_out[2] = r2;
		_out[3] = r3;
		_out[4] = r4;
	}


    /// <summary>
    /// out = in^(2 * count)
    /// </summary>
    /// <param name="_out"></param>
    /// <param name="_in"></param>
    /// <param name="count"></param>
    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void curve25519_square_times(Span<ulong> _out, ReadOnlySpan<ulong> _in, ulong count)
	{
		Span<UInt128> t = stackalloc UInt128[5];
		ulong r0, r1, r2, r3, r4, c;
		ulong d0, d1, d2, d4, d419;

		r0 = _in[0];
		r1 = _in[1];
		r2 = _in[2];
		r3 = _in[3];
		r4 = _in[4];

		do
		{
			d0 = r0 * 2;
			d1 = r1 * 2;
			d2 = r2 * 2 * 19;
			d419 = r4 * 19;
			d4 = d419 * 2;

			t[0] = ((UInt128)r0) * r0 + ((UInt128)d4) * r1 + (((UInt128)d2) * (r3));
			t[1] = ((UInt128)d0) * r1 + ((UInt128)d4) * r2 + (((UInt128)r3) * (r3 * 19));
			t[2] = ((UInt128)d0) * r2 + ((UInt128)r1) * r1 + (((UInt128)d4) * (r3));
			t[3] = ((UInt128)d0) * r3 + ((UInt128)d1) * r2 + (((UInt128)r4) * (d419));
			t[4] = ((UInt128)d0) * r4 + ((UInt128)d1) * r3 + (((UInt128)r2) * (r2));

			r0 = ASM.lo128(t[0]) & reduce_mask_51;
			r1 = ASM.lo128(t[1]) & reduce_mask_51;
			ASM.shl128(out c, t[0], 13); r1 += c;
			r2 = ASM.lo128(t[2]) & reduce_mask_51;
			ASM.shl128(out c, t[1], 13); r2 += c;
			r3 = ASM.lo128(t[3]) & reduce_mask_51;
			ASM.shl128(out c, t[2], 13); r3 += c;
			r4 = ASM.lo128(t[4]) & reduce_mask_51;
			ASM.shl128(out c, t[3], 13); r4 += c;
			ASM.shl128(out c, t[4], 13); r0 += c * 19;
			c = r0 >> 51; r0 &= reduce_mask_51;
			r1 += c; c = r1 >> 51; r1 &= reduce_mask_51;
			r2 += c; c = r2 >> 51; r2 &= reduce_mask_51;
			r3 += c; c = r3 >> 51; r3 &= reduce_mask_51;
			r4 += c; c = r4 >> 51; r4 &= reduce_mask_51;
			r0 += c * 19;
		} while (Convert.ToBoolean(--count));

		_out[0] = r0;
		_out[1] = r1;
		_out[2] = r2;
		_out[3] = r3;
		_out[4] = r4;
	}

    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void curve25519_square(Span<ulong> _out, ReadOnlySpan<ulong> _in)
	{
		Span<UInt128> t = stackalloc UInt128[5];

		ulong r0, r1, r2, r3, r4, c;
		ulong d0, d1, d2, d4, d419;

		r0 = _in[0];
		r1 = _in[1];
		r2 = _in[2];
		r3 = _in[3];
		r4 = _in[4];

		d0 = r0 * 2;
		d1 = r1 * 2;
		d2 = r2 * 2 * 19;
		d419 = r4 * 19;
		d4 = d419 * 2;

		t[0] = ((UInt128)r0) * r0 + ((UInt128)d4) * r1 + (((UInt128)d2) * (r3));
		t[1] = ((UInt128)d0) * r1 + ((UInt128)d4) * r2 + (((UInt128)r3) * (r3 * 19));
		t[2] = ((UInt128)d0) * r2 + ((UInt128)r1) * r1 + (((UInt128)d4) * (r3));
		t[3] = ((UInt128)d0) * r3 + ((UInt128)d1) * r2 + (((UInt128)r4) * (d419));
		t[4] = ((UInt128)d0) * r4 + ((UInt128)d1) * r3 + (((UInt128)r2) * (r2));

		r0 = ASM.lo128(t[0]) & reduce_mask_51;
		ASM.shr128(out c, t[0], 51);
		ASM.add128_64(ref t[1], c);
		r1 = ASM.lo128(t[1]) & reduce_mask_51;
		ASM.shr128(out c, t[1], 51);
		ASM.add128_64(ref t[2], c);
		r2 = ASM.lo128(t[2]) & reduce_mask_51;
		ASM.shr128(out c, t[2], 51);
		ASM.add128_64(ref t[3], c);
		r3 = ASM.lo128(t[3]) & reduce_mask_51;
		ASM.shr128(out c, t[3], 51);
		ASM.add128_64(ref t[4], c);
		r4 = ASM.lo128(t[4]) & reduce_mask_51;
		ASM.shr128(out c, t[4], 51);
		r0 += c * 19; c = r0 >> 51;
		r0 = r0 & reduce_mask_51;
		r1 += c;

		_out[0] = r0;
		_out[1] = r1;
		_out[2] = r2;
		_out[3] = r3;
		_out[4] = r4;
	}

    /// <summary>
    /// Take a little-endian, 32-byte number and expand it into polynomial form
    /// </summary>
    /// <param name="_out"></param>
    /// <param name="_in"></param>
    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void curve25519_expand(Span<ulong> _out, ReadOnlySpan<byte> _in)
	{
		ReadOnlySpan<ulong> data = MemoryMarshal.Cast<byte, ulong>(_in);

		ulong x0, x1, x2, x3;

		x0 = data[0];
		x1 = data[1];
		x2 = data[2];
		x3 = data[3];

		_out[0] = x0 & reduce_mask_51;
		x0 = (x0 >> 51) | (x1 << 13);
		_out[1] = x0 & reduce_mask_51;
		x1 = (x1 >> 38) | (x2 << 26);
		_out[2] = x1 & reduce_mask_51;
		x2 = (x2 >> 25) | (x3 << 39);
		_out[3] = x2 & reduce_mask_51;
		x3 = (x3 >> 12);
		_out[4] = x3 & reduce_mask_51;
	}

    /// <summary>
    /// Take a fully reduced polynomial form number and contract it into a little-endian, 32-byte array
    /// </summary>
    /// <param name="_out"></param>
    /// <param name="input"></param>
    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void curve25519_contract(Span<byte> _out, ReadOnlySpan<ulong> input)
	{
		ulong f, i;
		Span<ulong> t = stackalloc ulong[ModM.ModM_WORDS];

		t[0] = input[0];
		t[1] = input[1];
		t[2] = input[2];
		t[3] = input[3];
		t[4] = input[4];

		t[1] += t[0] >> 51; t[0] &= reduce_mask_51;
		t[2] += t[1] >> 51; t[1] &= reduce_mask_51;
		t[3] += t[2] >> 51; t[2] &= reduce_mask_51;
		t[4] += t[3] >> 51; t[3] &= reduce_mask_51;
		t[0] += 19 * (t[4] >> 51);
		t[4] &= reduce_mask_51;

		t[1] += t[0] >> 51; t[0] &= reduce_mask_51;
		t[2] += t[1] >> 51; t[1] &= reduce_mask_51;
		t[3] += t[2] >> 51; t[2] &= reduce_mask_51;
		t[4] += t[3] >> 51; t[3] &= reduce_mask_51;
		t[0] += 19 * (t[4] >> 51);
		t[4] &= reduce_mask_51;

		/* now t is between 0 and 2^255-1, properly carried. */
		/* case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1. */
		t[0] += 19;
		t[1] += t[0] >> 51;
		t[0] &= reduce_mask_51;
		t[2] += t[1] >> 51;
		t[1] &= reduce_mask_51;
		t[3] += t[2] >> 51;
		t[2] &= reduce_mask_51;
		t[4] += t[3] >> 51;
		t[3] &= reduce_mask_51;
		t[0] += 19 * (t[4] >> 51);
		t[4] &= reduce_mask_51;

		/* now between 19 and 2^255-1 in both cases, and offset by 19. */
		t[0] += (reduce_mask_51 + 1) - 19;
		t[1] += (reduce_mask_51 + 1) - 1;
		t[2] += (reduce_mask_51 + 1) - 1;
		t[3] += (reduce_mask_51 + 1) - 1;
		t[4] += (reduce_mask_51 + 1) - 1;

		/* now between 2^255 and 2^256-20, and offset by 2^255. */
		t[1] += t[0] >> 51;
		t[0] &= reduce_mask_51;
		t[2] += t[1] >> 51;
		t[1] &= reduce_mask_51;
		t[3] += t[2] >> 51;
		t[2] &= reduce_mask_51;
		t[4] += t[3] >> 51;
		t[3] &= reduce_mask_51;
		t[4] &= reduce_mask_51;

		int outIdx = 0;

		f = ((t[0] >> 13 * 0) | (t[0 + 1] << (51 - 13 * 0)));
		for (i = 0; i < 8; i++, f >>= 8)
		{
			_out[outIdx++] = (byte)f;
		}

		f = ((t[1] >> 13 * 1) | (t[1 + 1] << (51 - 13 * 1)));
		for (i = 0; i < 8; i++, f >>= 8)
		{
			_out[outIdx++] = (byte)f;
		}

		f = ((t[2] >> 13 * 2) | (t[2 + 1] << (51 - 13 * 2)));
		for (i = 0; i < 8; i++, f >>= 8)
		{
			_out[outIdx++] = (byte)f;
		}

		f = ((t[3] >> 13 * 3) | (t[3 + 1] << (51 - 13 * 3)));
		for (i = 0; i < 8; i++, f >>= 8)
		{
			_out[outIdx++] = (byte)f;
		}
	}

    /// <summary>
    /// out = (flag) ? in : out
    /// </summary>
    /// <param name="_out">96 bytes long</param>
    /// <param name="_in">96 bytes long</param>
    /// <param name="flag"></param>
    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void curve25519_move_conditional_bytes(Span<byte> _out, ReadOnlySpan<byte> _in, ulong flag)
	{

		ulong nb = flag - 1, b = ~nb;

		ReadOnlySpan<ulong> inq = MemoryMarshal.Cast<byte, ulong>(_in);
		Span<ulong> outq = MemoryMarshal.Cast<byte, ulong>(_out);

		outq[0] = (outq[0] & nb) | (inq[0] & b);
		outq[1] = (outq[1] & nb) | (inq[1] & b);
		outq[2] = (outq[2] & nb) | (inq[2] & b);
		outq[3] = (outq[3] & nb) | (inq[3] & b);
		outq[4] = (outq[4] & nb) | (inq[4] & b);
		outq[5] = (outq[5] & nb) | (inq[5] & b);
		outq[6] = (outq[6] & nb) | (inq[6] & b);
		outq[7] = (outq[7] & nb) | (inq[7] & b);
		outq[8] = (outq[8] & nb) | (inq[8] & b);
		outq[9] = (outq[9] & nb) | (inq[9] & b);
		outq[10] = (outq[10] & nb) | (inq[10] & b);
		outq[11] = (outq[11] & nb) | (inq[11] & b);
	}

    /// <summary>
    /// if (iswap) swap(a, b)
    /// </summary>
    /// <param name="a"></param>
    /// <param name="b"></param>
    /// <param name="iswap"></param>
    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void curve25519_swap_conditional(Span<ulong> a, Span<ulong> b, ulong iswap)
	{
		ulong swap = (ulong)(-(long)iswap);
		ulong x0, x1, x2, x3, x4;

		x0 = swap & (a[0] ^ b[0]); a[0] ^= x0; b[0] ^= x0;
		x1 = swap & (a[1] ^ b[1]); a[1] ^= x1; b[1] ^= x1;
		x2 = swap & (a[2] ^ b[2]); a[2] ^= x2; b[2] ^= x2;
		x3 = swap & (a[3] ^ b[3]); a[3] ^= x3; b[3] ^= x3;
		x4 = swap & (a[4] ^ b[4]); a[4] ^= x4; b[4] ^= x4;
    }

    /// <summary>
    /// In:  b =   2^5 - 2^0
    /// Out: b = 2^250 - 2^0
    /// </summary>
    /// <param name="b"></param>
    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void curve25519_pow_two5mtwo0_two250mtwo0(Span<ulong> b)
	{
		Span<ulong> t0 = stackalloc ulong[ModM.ModM_WORDS];
		Span<ulong> c = stackalloc ulong[ModM.ModM_WORDS];

		/* 2^5  - 2^0 */ /* b */
		/* 2^10 - 2^5 */
		curve25519_square_times(t0, b, 5);
		/* 2^10 - 2^0 */
		curve25519_mul(b, t0, b);
		/* 2^20 - 2^10 */
		curve25519_square_times(t0, b, 10);
		/* 2^20 - 2^0 */
		curve25519_mul(c, t0, b);
		/* 2^40 - 2^20 */
		curve25519_square_times(t0, c, 20);
		/* 2^40 - 2^0 */
		curve25519_mul(t0, t0, c);
		/* 2^50 - 2^10 */
		curve25519_square_times(t0, t0, 10);
		/* 2^50 - 2^0 */
		curve25519_mul(b, t0, b);
		/* 2^100 - 2^50 */
		curve25519_square_times(t0, b, 50);
		/* 2^100 - 2^0 */
		curve25519_mul(c, t0, b);
		/* 2^200 - 2^100 */
		curve25519_square_times(t0, c, 100);
		/* 2^200 - 2^0 */
		curve25519_mul(t0, t0, c);
		/* 2^250 - 2^50 */
		curve25519_square_times(t0, t0, 50);
		/* 2^250 - 2^0 */
		curve25519_mul(b, t0, b);
	}

    /// <summary>
    /// z^(p - 2) = z(2^255 - 21)
    /// </summary>
    /// <param name="_out"></param>
    /// <param name="z"></param>
    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void curve25519_recip(Span<ulong> _out, ReadOnlySpan<ulong> z)
	{
		Span<ulong> a = stackalloc ulong[ModM.ModM_WORDS];
		Span<ulong> t0 = stackalloc ulong[ModM.ModM_WORDS];
		Span<ulong> b = stackalloc ulong[ModM.ModM_WORDS];

		/* 2 */
		curve25519_square_times(a, z, 1); /* a = 2 */
		/* 8 */
		curve25519_square_times(t0, a, 2);
		/* 9 */
		curve25519_mul(b, t0, z); /* b = 9 */
		/* 11 */
		curve25519_mul(a, b, a); /* a = 11 */
		/* 22 */
		curve25519_square_times(t0, a, 1);
		/* 2^5 - 2^0 = 31 */
		curve25519_mul(b, t0, b);
		/* 2^250 - 2^0 */
		curve25519_pow_two5mtwo0_two250mtwo0(b);
		/* 2^255 - 2^5 */
		curve25519_square_times(b, b, 5);
		/* 2^255 - 21 */
		curve25519_mul(_out, b, a);
	}

    /// <summary>
    /// z^((p-5)/8) = z^(2^252 - 3)
    /// </summary>
    /// <param name="two252m3"></param>
    /// <param name="z"></param>
    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void curve25519_pow_two252m3(Span<ulong> two252m3, ReadOnlySpan<ulong> z)
	{

		Span<ulong> b = stackalloc ulong[ModM.ModM_WORDS];
		Span<ulong> c = stackalloc ulong[ModM.ModM_WORDS];
		Span<ulong> t0 = stackalloc ulong[ModM.ModM_WORDS];

		/* 2 */
		curve25519_square_times(c, z, 1); /* c = 2 */
		/* 8 */
		curve25519_square_times(t0, c, 2); /* t0 = 8 */
		/* 9 */
		curve25519_mul(b, t0, z); /* b = 9 */
		/* 11 */
		curve25519_mul(c, b, c); /* c = 11 */
		/* 22 */
		curve25519_square_times(t0, c, 1);
		/* 2^5 - 2^0 = 31 */
		curve25519_mul(b, t0, b);
		/* 2^250 - 2^0 */
		curve25519_pow_two5mtwo0_two250mtwo0(b);
		/* 2^252 - 2^2 */
		curve25519_square_times(b, b, 2);
		/* 2^252 - 3 */
		curve25519_mul(two252m3, b, z);
	}
}
