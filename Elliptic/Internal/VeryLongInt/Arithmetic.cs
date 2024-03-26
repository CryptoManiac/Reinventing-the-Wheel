using System;

namespace Wheel.Crypto.Elliptic.Internal.VeryLongInt
{
    /// <summary>
    /// Arithmetic operations with very long integers (aka VLI)
    /// </summary>
    internal static partial class VLI
    {
        /// <summary>
        /// Sets dest = src
        /// </summary>
        /// <param name="dest"></param>
        /// <param name="src"></param>
        /// <param name="num_words"></param>
        public static void Set(Span<ulong> result, ReadOnlySpan<ulong> right, int num_words)
        {
            var dest = result.Slice(0, num_words);
            var src = right.Slice(0, num_words);
            src.CopyTo(dest);
        }

        /// <summary>
        /// Set num_words to zero
        /// </summary>
        /// <param name="vli"></param>
        /// <param name="num_words"></param>
        public static void Clear(Span<ulong> vli, int num_words)
        {
            vli.Slice(0, num_words).Clear();
        }

        /// <summary>
        /// Computes result = left + right, returning carry. Can modify in place.
        /// </summary>
        /// <param name="result"></param>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <param name="num_words"></param>
        /// <returns></returns>
        public static ulong Add(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, int num_words)
        {
            ulong carry = 0;
            for (int i = 0; i < num_words; ++i)
            {
                ulong sum = left[i] + right[i] + carry;
                if (sum != left[i])
                {
                    carry = Convert.ToUInt64(sum < left[i]);
                }
                result[i] = sum;
            }
            return carry;
        }

        /// <summary>
        /// Computes result = left - right, returning borrow. Can modify in place.
        /// </summary>
        public static ulong Sub(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, int num_words)
        {
            ulong borrow = 0;
            for (int i = 0; i < num_words; ++i)
            {
                ulong diff = left[i] - right[i] - borrow;
                if (diff != left[i])
                {
                    borrow = Convert.ToUInt64(diff > left[i]);
                }
                result[i] = diff;
            }
            return borrow;
        }

        /// <summary>
        /// Apply XOR
        /// </summary>
        /// <param name="words"></param>
        /// <param name="vli"></param>
        /// <param name="num_words"></param>
        public static void XorWith(Span<ulong> words, ReadOnlySpan<ulong> vli, int num_words)
        {
            for (int i = 0; i < num_words; ++i)
            {
                words[i] ^= vli[i];
            }
        }

        /// <summary>
        /// Computes result = left * right. Result must be 2 * num_words long.
        /// </summary>
        /// <param name="result"></param>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <param name="num_words"></param>
        public static void Mult(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, int num_words)
        {
            ulong r0 = 0;
            ulong r1 = 0;
            ulong r2 = 0;
            int i, k;

            /* Compute each digit of result in sequence, maintaining the carries. */
            for (k = 0; k < num_words; ++k)
            {
                for (i = 0; i <= k; ++i)
                {
                    muladd(left[i], right[k - i], ref r0, ref r1, ref r2);
                }
                result[k] = r0;
                r0 = r1;
                r1 = r2;
                r2 = 0;
            }
            for (k = num_words; k < num_words * 2 - 1; ++k)
            {
                for (i = (k + 1) - num_words; i < num_words; ++i)
                {
                    muladd(left[i], right[k - i], ref r0, ref r1, ref r2);
                }
                result[k] = r0;
                r0 = r1;
                r1 = r2;
                r2 = 0;
            }
            result[num_words * 2 - 1] = r0;
        }

        /// <summary>
        /// Computes result = left^2. Result must be 2 * num_words long.
        /// </summary>
        /// <param name="result"></param>
        /// <param name="left"></param>
        /// <param name="num_words"></param>
        public static void Square(Span<ulong> result, ReadOnlySpan<ulong> left, int num_words)
        {
            ulong r0 = 0;
            ulong r1 = 0;
            ulong r2 = 0;

            int i, k;

            for (k = 0; k < num_words * 2 - 1; ++k)
            {
                int min = (k < num_words ? 0 : (k + 1) - num_words);
                for (i = min; i <= k && i <= k - i; ++i)
                {
                    if (i < k - i)
                    {
                        mul2add(left[i], left[k - i], ref r0, ref r1, ref r2);
                    }
                    else
                    {
                        muladd(left[i], left[k - i], ref r0, ref r1, ref r2);
                    }
                }
                result[k] = r0;
                r0 = r1;
                r1 = r2;
                r2 = 0;
            }

            result[num_words * 2 - 1] = r0;
        }

        /// <summary>
        /// Computes vli = vli >> 1
        /// </summary>
        /// <param name="words"></param>
        /// <param name="num_words"></param>
        public static unsafe void RShift1(Span<ulong> words, int num_words)
        {
            ulong carry = 0;
            for (int i = num_words - 1; i >= 0; --i)
            {
                ulong temp = words[i];
                words[i] = (temp >> 1) | carry;
                carry = temp << (WORD_BITS - 1);
            }
        }

        /// <summary>
        /// Computes result = (left + right) % mod.
        /// Assumes that left < mod and right < mod, and that result does not overlap mod.
        /// </summary>
        /// <param name="result"></param>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <param name="mod"></param>
        /// <param name="num_words"></param>
        public static void ModAdd(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, ReadOnlySpan<ulong> mod, int num_words)
        {
            ulong carry = Add(result, left, right, num_words);
            if (0 != carry || CmpUnsafe(mod, result, num_words) != 1)
            {
                /* result > mod (result = mod + remainder), so subtract mod to get remainder. */
                Sub(result, result, mod, num_words);
            }
        }

        /// <summary>
        /// Computes result = (left - right) % mod.
        /// Assumes that left < mod and right < mod, and that result does not overlap mod.
        /// </summary>
        /// <param name="result"></param>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <param name="mod"></param>
        /// <param name="num_words"></param>
        public static void ModSub(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, ReadOnlySpan<ulong> mod, int num_words)
        {
            ulong l_borrow = Sub(result, left, right, num_words);
            if (0 != l_borrow)
            {
                /* In this case, result == -diff == (max int) - diff. Since -x % d == d - x,
                   we can get the correct result from result + mod (with overflow). */
                Add(result, result, mod, num_words);
            }
        }

        /// <summary>
        /// Computes result = product % mod, where product is 2N words long.
        /// Currently only designed to work for curve_p or curve_n.
        /// </summary>
        /// <param name="result"></param>
        /// <param name="product"></param>
        /// <param name="mod"></param>
        /// <param name="num_words"></param>
        public static void MMod(Span<ulong> result, Span<ulong> product, ReadOnlySpan<ulong> mod, int num_words)
        {
            Span<ulong> mod_multiple = stackalloc ulong[2 * ECC_MAX_WORDS];
            Span<ulong> tmp = stackalloc ulong[2 * ECC_MAX_WORDS];
            Picker<ulong> v = new(tmp, product);
            ulong index;

            /* Shift mod so its highest set bit is at the maximum position. */
            int shift = (num_words * 2 * WORD_BITS) - NumBits(mod, num_words);
            int word_shift = shift / WORD_BITS;
            int bit_shift = shift % WORD_BITS;
            ulong carry = 0;
            Clear(mod_multiple, word_shift);
            if (bit_shift > 0)
            {
                for (index = 0; index < (ulong)num_words; ++index)
                {
                    mod_multiple[word_shift + (int)index] = (mod[(int)index] << bit_shift) | carry;
                    carry = mod[(int)index] >> (WORD_BITS - bit_shift);
                }
            }
            else
            {
                Set(mod_multiple.Slice(word_shift), mod, num_words);
            }

            for (index = 1; shift >= 0; --shift)
            {
                ulong borrow = 0;
                int i;
                for (i = 0; i < num_words * 2; ++i)
                {
                    ulong diff = v[index][i] - mod_multiple[i] - borrow;
                    if (diff != v[index][i])
                    {
                        borrow = (diff > v[index][i]) ? 1u : 0;
                    }
                    v[1 - index][i] = diff;
                }
                index = Convert.ToUInt64(!Convert.ToBoolean(index ^ borrow)); /* Swap the index if there was no borrow */
                RShift1(mod_multiple, num_words);
                mod_multiple[num_words - 1] |= mod_multiple[num_words] << (WORD_BITS - 1);
                RShift1(mod_multiple.Slice(num_words), num_words);
            }
            Set(result, v[index], num_words);
        }

        /// <summary>
        /// Computes result = (left * right) % mod.
        /// Currently only designed to work for mod == curve_secp256k1.p or curve_n.
        /// </summary>
        /// <param name="result"></param>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <param name="mod"></param>
        /// <param name="num_words"></param>
        public static void ModMult(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, ReadOnlySpan<ulong> mod, int num_words)
        {
            Span<ulong> product = stackalloc ulong[2 * ECC_MAX_WORDS];
            Mult(product, left, right, num_words);
            MMod(result, product, mod, num_words);
        }

        /// <summary>
        /// Computes result = left^2 % mod.
        /// Currently only designed to work for mod == curve_secp256k1.p or curve_n.
        /// </summary>
        /// <param name="result"></param>
        /// <param name="left"></param>
        /// <param name="mod"></param>
        /// <param name="num_words"></param>
        public static void ModSquare(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> mod, int num_words)
        {
            Span<ulong> product = stackalloc ulong[2 * ECC_MAX_WORDS];
            Square(product, left, num_words);
            MMod(result, product, mod, num_words);
        }

        /// <summary>
        /// Computes result = (1 / input) % mod. All VLIs are the same size.
        /// See "From Euclid's GCD to Montgomery Multiplication to the Great Divide"
        /// </summary>
        /// <param name="result"></param>
        /// <param name="input"></param>
        /// <param name="mod"></param>
        /// <param name="num_words"></param>
        public static void ModInv(Span<ulong> result, ReadOnlySpan<ulong> input, ReadOnlySpan<ulong> mod, int num_words)
        {
            Span<ulong> a = stackalloc ulong[ECC_MAX_WORDS];
            Span<ulong> b = stackalloc ulong[ECC_MAX_WORDS];
            Span<ulong> u = stackalloc ulong[ECC_MAX_WORDS];
            Span<ulong> v = stackalloc ulong[ECC_MAX_WORDS];

            if (IsZero(input, num_words))
            {
                Clear(result, num_words);
                return;
            }

            Set(a, input, num_words);
            Set(b, mod, num_words);
            Clear(u, num_words);
            u[0] = 1;
            Clear(v, num_words);

            int cmpResult;
            while ((cmpResult = CmpUnsafe(a, b, num_words)) != 0)
            {
                if (IsEven(a))
                {
                    RShift1(a, num_words);
                    modInv_update(u, mod, num_words);
                }
                else if (IsEven(b))
                {
                    RShift1(b, num_words);
                    modInv_update(v, mod, num_words);
                }
                else if (cmpResult > 0)
                {
                    Sub(a, a, b, num_words);
                    RShift1(a, num_words);
                    if (CmpUnsafe(u, v, num_words) < 0)
                    {
                        Add(u, u, mod, num_words);
                    }
                    Sub(u, u, v, num_words);
                    modInv_update(u, mod, num_words);
                }
                else
                {
                    Sub(b, b, a, num_words);
                    RShift1(b, num_words);
                    if (CmpUnsafe(v, u, num_words) < 0)
                    {
                        Add(v, v, mod, num_words);
                    }
                    Sub(v, v, u, num_words);
                    modInv_update(v, mod, num_words);
                }
            }
            Set(result, u, num_words);
        }

        public static void muladd(ulong a, ulong b, ref ulong r0, ref ulong r1, ref ulong r2)
        {
            UInt128 p = (UInt128)a * b;
            UInt128 r01 = ((UInt128)(r1) << WORD_BITS) | r0;

            r01 += p;
            r2 += Convert.ToUInt64(r01 < p);
            r1 = (ulong)(r01 >> WORD_BITS);
            r0 = (ulong)r01;

            /*
            ulong a0 = a & 0xffffffff;
            ulong a1 = a >> 32;
            ulong b0 = b & 0xffffffff;
            ulong b1 = b >> 32;

            ulong i0 = a0 * b0;
            ulong i1 = a0 * b1;
            ulong i2 = a1 * b0;
            ulong i3 = a1 * b1;

            ulong p0, p1;

            i2 += (i0 >> 32);
            i2 += i1;
            if (i2 < i1)
            {
                // overflow
                i3 += 0x100000000;
            }

            p0 = (i0 & 0xffffffff) | (i2 << 32);
            p1 = i3 + (i2 >> 32);

            r0 += p0;
            r1 += p1 + Convert.ToUInt64(r0 < p0);
            r2 += Convert.ToUInt64((r1 < p1) || (r1 == p1 && r0 < p0));
            */
        }

        public static void mul2add(ulong a, ulong b, ref ulong r0, ref ulong r1, ref ulong r2)
        {
            UInt128 p = (UInt128)a * b;
            UInt128 r01 = ((UInt128)(r1) << WORD_BITS) | r0;
            r2 += (ulong)(p >> (WORD_BITS * 2 - 1));
            p *= 2;
            r01 += p;
            r2 += Convert.ToUInt64(r01 < p);
            r1 = (ulong)(r01 >> WORD_BITS);
            r0 = (ulong)r01;

            /*
            ulong a0 = a & 0xffffffff;
            ulong a1 = a >> 32;
            ulong b0 = b & 0xffffffff;
            ulong b1 = b >> 32;

            ulong i0 = a0 * b0;
            ulong i1 = a0 * b1;
            ulong i2 = a1 * b0;
            ulong i3 = a1 * b1;

            ulong p0, p1;

            i2 += (i0 >> 32);
            i2 += i1;
            if (i2 < i1)
            {
                // overflow
                i3 += 0x100000000;
            }

            p0 = (i0 & 0xffffffff) | (i2 << 32);
            p1 = i3 + (i2 >> 32);

            r2 += (p1 >> 63);
            p1 = (p1 << 1) | (p0 >> 63);
            p0 <<= 1;

            r0 += p0;
            r1 += p1 + Convert.ToUInt64(r0 < p0);
            r2 += Convert.ToUInt64((r1 < p1) || (r1 == p1 && r0 < p0));
            */
        }

        private static void modInv_update(Span<ulong> uv, ReadOnlySpan<ulong> mod, int num_words)
        {
            ulong carry = 0;
            if (!IsEven(uv))
            {
                carry = Add(uv, uv, mod, num_words);
            }
            RShift1(uv, num_words);
            if (carry != 0)
            {
                uv[num_words - 1] |= HIGH_BIT_SET;
            }
        }
    }

}
