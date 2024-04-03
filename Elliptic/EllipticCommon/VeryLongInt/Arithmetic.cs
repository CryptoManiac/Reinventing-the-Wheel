using System;
using System.Runtime.CompilerServices;

namespace Wheel.Crypto.Elliptic.EllipticCommon.VeryLongInt
{
    /// <summary>
    /// Arithmetic operations with very long integers (aka VLI)
    /// </summary>
    public static partial class VLI
    {
        /// <summary>
        /// Sets result = right
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
        /// Sets value of result to right
        /// </summary>
        /// <param name="result"></param>
        /// <param name="right"></param>
        /// <param name="num_words"></param>
        public static void Set(Span<ulong> result, ulong right, int num_words)
        {
            Clear(result, num_words);
            result[0] = right;
        }

        /// <summary>
        /// Sets every word of result to right
        /// </summary>
        /// <param name="result"></param>
        /// <param name="right"></param>
        /// <param name="num_words"></param>
        public static void Fill(Span<ulong> result, ulong right, int num_words)
        {
            result.Slice(0, num_words).Fill(right);
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
        /// Apply XOR in-place:
        ///  left ^= right
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <param name="num_words"></param>
        public static void Xor(Span<ulong> left, ReadOnlySpan<ulong> right, int num_words)
        {
            for (int i = 0; i < num_words; ++i)
            {
                left[i] ^= right[i];
            }
        }

        /// <summary>
        /// Calculate XOR for every word:
        ///  result[i] = left[i] ^ right
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <param name="num_words"></param>
        public static void Xor(Span<ulong> result, ReadOnlySpan<ulong> left, ulong right, int num_words)
        {
            for (int i = 0; i < num_words; ++i)
            {
                result[i] = left[i] ^ right;
            }
        }

        /// <summary>
        /// Apply XOR in-place for every word:
        ///  left[i] ^= right
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <param name="num_words"></param>
        public static void Xor(Span<ulong> left, ulong right, int num_words)
        {
            for (int i = 0; i < num_words; ++i)
            {
                left[i] ^= right;
            }
        }

        /// <summary>
        /// Apply AND in-place:
        ///  left &= right
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <param name="num_words"></param>
        public static void And(Span<ulong> left, ReadOnlySpan<ulong> right, int num_words)
        {
            for (int i = 0; i < num_words; ++i)
            {
                left[i] &= right[i];
            }
        }

        /// <summary>
        /// Apply AND in-place for every word:
        ///  left[i] &= right
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <param name="num_words"></param>
        public static void And(Span<ulong> left, ulong right, int num_words)
        {
            for (int i = 0; i < num_words; ++i)
            {
                left[i] &= right;
            }
        }

        /// <summary>
        /// Calculate XOR:
        ///  result = left ^ right
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <param name="num_words"></param>
        public static void Xor(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, int num_words)
        {
            for (int i = 0; i < num_words; ++i)
            {
                result[i] = left[i] ^ right[i];
            }
        }

        /// <summary>
        /// Calculate AND:
        ///  result = left & right
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <param name="num_words"></param>
        public static void And(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, int num_words)
        {
            for (int i = 0; i < num_words; ++i)
            {
                result[i] = left[i] & right[i];
            }
        }

        /// <summary>
        /// Calculate AND for every word:
        ///  result = left[i] & right
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <param name="num_words"></param>
        public static void And(Span<ulong> result, ReadOnlySpan<ulong> left, ulong right, int num_words)
        {
            for (int i = 0; i < num_words; ++i)
            {
                result[i] = left[i] & right;
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
        /// Computes result = left * right. Result must be 2 * num_words long.
        /// </summary>
        /// <param name="result"></param>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <param name="num_words"></param>
        [SkipLocalsInit]
        public static void Mult(Span<ulong> result, ReadOnlySpan<ulong> left, ulong right, int num_words)
        {
            Span<ulong> tmp = stackalloc ulong[num_words];
            Set(tmp, right, num_words);
            Mult(result, result, tmp, num_words);
        }

        /// <summary>
        /// Computes result = right^2. Result must be 2 * num_words long.
        /// </summary>
        /// <param name="result"></param>
        /// <param name="right"></param>
        /// <param name="num_words"></param>
        public static void Square(Span<ulong> result, ReadOnlySpan<ulong> right, int num_words)
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
                        mul2add(right[i], right[k - i], ref r0, ref r1, ref r2);
                    }
                    else
                    {
                        muladd(right[i], right[k - i], ref r0, ref r1, ref r2);
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
        /// Computes result = 2 * right^2. Result must be 2 * num_words long.
        /// </summary>
        /// <param name="result"></param>
        /// <param name="right"></param>
        /// <param name="num_words"></param>
        public static void DoubleSquare(Span<ulong> result, ReadOnlySpan<ulong> right, int num_words)
        {
            Square(result, right, num_words);
            Mult(result, result, 2, num_words);
        }

        /// <summary>
        ///  Computes result = left << c, returning carry. Can modify in place (if result == left). 0 < shift < 64.
        /// </summary>
        public static ulong LShift(Span<ulong> result, Span<ulong> left, int shift, int num_words)
        {
            ulong carry = 0;
            for (int i = 0; i < num_words; ++i)
            {
                ulong temp = left[i];
                result[i] = (temp << shift) | carry;
                carry = temp >> (WORD_BITS - shift);
            }

            return carry;
        }

        /// <summary>
        /// Computes vli = vli >> 1
        /// </summary>
        /// <param name="words"></param>
        /// <param name="num_words"></param>
        public static void RShift1(Span<ulong> words, int num_words)
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
            if (0 != carry || VarTimeCmp(mod, result, num_words) != 1)
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
                // In this case, result == -diff == (max int) - diff. Since -x % d == d - x,
                //   we can get the correct result from result + mod (with overflow).
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
        [SkipLocalsInit]
        public static void MMod(Span<ulong> result, Span<ulong> product, ReadOnlySpan<ulong> mod, int num_words)
        {
            Span<ulong> mod_multiple = stackalloc ulong[2 * ECC_MAX_WORDS];
            Span<ulong> tmp = stackalloc ulong[2 * ECC_MAX_WORDS];
            Picker v = new(tmp, product);
            ulong index;

            // Shift mod so its highest set bit is at the maximum position.
            int shift = (num_words * 2 * WORD_BITS) - NumBits(mod, num_words);
            int word_shift = shift / WORD_BITS;
            int bit_shift = shift % WORD_BITS;
            ulong carry = 0;

            Clear(mod_multiple, 2 * num_words);

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

                // Swap the index if there was no borrow
                index = Convert.ToUInt64(!Convert.ToBoolean(index ^ borrow));

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
        [SkipLocalsInit]
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
        [SkipLocalsInit]
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
        [SkipLocalsInit]
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
            Set(u, 1, num_words);
            Clear(v, num_words);

            int cmpResult;
            while ((cmpResult = VarTimeCmp(a, b, num_words)) != 0)
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
                    if (VarTimeCmp(u, v, num_words) < 0)
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
                    if (VarTimeCmp(v, u, num_words) < 0)
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
