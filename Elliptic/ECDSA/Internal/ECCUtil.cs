using Wheel.Crypto.Elliptic.EllipticCommon.VeryLongInt;

namespace Wheel.Crypto.Elliptic.ECDSA
{
    /// <summary>
    /// Curve-specific arithmetic methods
    /// </summary>
    public readonly partial struct ECCurve
    {
        internal ulong RegularizeK(ReadOnlySpan<ulong> k, Span<ulong> k0, Span<ulong> k1)
        {
            ulong carry = VLI.Add(k0, k, N, NUM_WORDS);
            if (!Convert.ToBoolean(carry))
            {
                carry = Convert.ToUInt64(NUM_N_BITS < (NUM_WORDS * VLI.WORD_SIZE * 8) && VLI.TestBit(k0, NUM_N_BITS));
            }
            VLI.Add(k1, k0, N, NUM_WORDS);
            return carry;
        }

        /// <summary>
        /// Modify (x1, y1) => (x1 * z^2, y1 * z^3)
        /// </summary>
        /// <param name="X1"></param>
        /// <param name="Y1"></param>
        /// <param name="Z"></param>
        internal void ApplyZ(Span<ulong> X1, Span<ulong> Y1, ReadOnlySpan<ulong> Z)
        {
            Span<ulong> t1 = stackalloc ulong[NUM_WORDS];
            ModSquare(t1, Z);    // z^2
            ModMult(X1, X1, t1); // x1 * z^2
            ModMult(t1, t1, Z);  // z^3
            ModMult(Y1, Y1, t1); // y1 * z^3
        }

        // P = (x1, y1) => 2P, (x2, y2) => P'
        internal void XYcZ_Initial_Double(Span<ulong> X1, Span<ulong> Y1, Span<ulong> X2, Span<ulong> Y2, ReadOnlySpan<ulong> initial_Z)
        {
            Span<ulong> z = stackalloc ulong[NUM_WORDS];

            // Setting Z as it is provided
            VLI.Set(z, initial_Z, NUM_WORDS);

            VLI.Set(X2, X1, NUM_WORDS);
            VLI.Set(Y2, Y1, NUM_WORDS);

            ApplyZ(X1, Y1, z);
            DoubleJacobian(X1, Y1, z);
            ApplyZ(X2, Y2, z);
        }

        // P = (x1, y1) => 2P, (x2, y2) => P'
        internal void XYcZ_Double(Span<ulong> X1, Span<ulong> Y1, Span<ulong> X2, Span<ulong> Y2)
        {
            Span<ulong> z = stackalloc ulong[NUM_WORDS];

            // Version without initial_Z
            VLI.Set(z, 1, NUM_WORDS);
            VLI.Set(X2, X1, NUM_WORDS);
            VLI.Set(Y2, Y1, NUM_WORDS);

            ApplyZ(X1, Y1, z);
            DoubleJacobian(X1, Y1, z);
            ApplyZ(X2, Y2, z);
        }

        // Input P = (x1, y1, Z), Q = (x2, y2, Z)
        //   Output P' = (x1', y1', Z3), P + Q = (x3, y3, Z3)
        //   or P => P', Q => P + Q
        internal void XYcZ_Add(Span<ulong> X1, Span<ulong> Y1, Span<ulong> X2, Span<ulong> Y2)
        {
            // t1 = X1, t2 = Y1, t3 = X2, t4 = Y2
            Span<ulong> t5 = stackalloc ulong[NUM_WORDS];

            VLI.ModSub(t5, X2, X1, P, NUM_WORDS); // t5 = x2 - x1
            ModSquare(t5, t5);                  // t5 = (x2 - x1)^2 = A
            ModMult(X1, X1, t5);                // t1 = x1*A = B
            ModMult(X2, X2, t5);                // t3 = x2*A = C
            VLI.ModSub(Y2, Y2, Y1, P, NUM_WORDS); // t4 = y2 - y1
            ModSquare(t5, Y2);                  // t5 = (y2 - y1)^2 = D

            VLI.ModSub(t5, t5, X1, P, NUM_WORDS); // t5 = D - B
            VLI.ModSub(t5, t5, X2, P, NUM_WORDS); // t5 = D - B - C = x3
            VLI.ModSub(X2, X2, X1, P, NUM_WORDS); // t3 = C - B
            ModMult(Y1, Y1, X2);                // t2 = y1*(C - B)
            VLI.ModSub(X2, X1, t5, P, NUM_WORDS); // t3 = B - x3
            ModMult(Y2, Y2, X2);                // t4 = (y2 - y1)*(B - x3)
            VLI.ModSub(Y2, Y2, Y1, P, NUM_WORDS); // t4 = y3
            VLI.Set(X2, t5, NUM_WORDS);
        }

        // Input P = (x1, y1, Z), Q = (x2, y2, Z)
        //   Output P + Q = (x3, y3, Z3), P - Q = (x3', y3', Z3)
        //   or P => P - Q, Q => P + Q
        internal void XYcZ_addC(Span<ulong> X1, Span<ulong> Y1, Span<ulong> X2, Span<ulong> Y2)
        {
            // t1 = X1, t2 = Y1, t3 = X2, t4 = Y2
            Span<ulong> t5 = stackalloc ulong[NUM_WORDS];
            Span<ulong> t6 = stackalloc ulong[NUM_WORDS];
            Span<ulong> t7 = stackalloc ulong[NUM_WORDS];

            VLI.ModSub(t5, X2, X1, P, NUM_WORDS); // t5 = x2 - x1
            ModSquare(t5, t5);                  // t5 = (x2 - x1)^2 = A
            ModMult(X1, X1, t5);                // t1 = x1*A = B
            ModMult(X2, X2, t5);                // t3 = x2*A = C
            VLI.ModAdd(t5, Y2, Y1, P, NUM_WORDS); // t5 = y2 + y1
            VLI.ModSub(Y2, Y2, Y1, P, NUM_WORDS); // t4 = y2 - y1

            VLI.ModSub(t6, X2, X1, P, NUM_WORDS); // t6 = C - B
            ModMult(Y1, Y1, t6);                // t2 = y1 * (C - B) = E
            VLI.ModAdd(t6, X1, X2, P, NUM_WORDS); // t6 = B + C
            ModSquare(X2, Y2);                  // t3 = (y2 - y1)^2 = D
            VLI.ModSub(X2, X2, t6, P, NUM_WORDS); // t3 = D - (B + C) = x3

            VLI.ModSub(t7, X1, X2, P, NUM_WORDS); // t7 = B - x3
            ModMult(Y2, Y2, t7);                // t4 = (y2 - y1)*(B - x3)
            VLI.ModSub(Y2, Y2, Y1, P, NUM_WORDS); // t4 = (y2 - y1)*(B - x3) - E = y3
            ModSquare(t7, t5);                  // t7 = (y2 + y1)^2 = F
            VLI.ModSub(t7, t7, t6, P, NUM_WORDS); // t7 = F - (B + C) = x3'
            VLI.ModSub(t6, t7, X1, P, NUM_WORDS); // t6 = x3' - B
            ModMult(t6, t6, t5);                // t6 = (y2+y1)*(x3' - B)
            VLI.ModSub(Y1, t6, Y1, P, NUM_WORDS); // t2 = (y2+y1)*(x3' - B) - E = y3'

            VLI.Set(X1, t7, NUM_WORDS);
        }

        internal void BitsToInt(Span<ulong> native, ReadOnlySpan<byte> bits, int bits_size)
        {
            if (bits_size > NUM_BYTES)
            {
                bits_size = NUM_BYTES;
            }

            VLI.Clear(native, NUM_WORDS);
            VLI.BytesToNative(native, bits, bits_size);
            if (bits_size * 8 <= NUM_N_BITS)
            {
                return;
            }

            ulong carry = 0;
            int shift = bits_size * 8 - NUM_N_BITS;
            for (int index = NUM_WORDS - 1; index >= 0; --index)
            {
                ulong temp = native[index];
                native[index] = (temp >> shift) | carry;
                carry = temp << (VLI.WORD_BITS - shift);
            }

            // Reduce mod curve_n
            if (VLI.VarTimeCmp(N, native, NUM_WORDS) != 1)
            {
                VLI.Sub(native, native, N, NUM_WORDS);
            }
        }
    }
}
