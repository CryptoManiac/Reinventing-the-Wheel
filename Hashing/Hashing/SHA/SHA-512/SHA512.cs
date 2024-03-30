using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Hashing.SHA.SHA512.Internal;

namespace Wheel.Hashing.SHA.SHA512
{
    [StructLayout(LayoutKind.Explicit)]
    internal struct SHA512Base : IHasher
    {
        /// <summary>
        /// Current data block length in bytes
        /// </summary>
        [FieldOffset(0)]
        private uint blockLen = 0;

        /// <summary>
        /// Output length
        /// </summary>
        [FieldOffset(4)]
        private int digestSz;

        /// <summary>
        /// Total input length in bits
        /// </summary>
        [FieldOffset(8)]
        private ulong bitLen = 0;

        /// <summary>
        /// Pending block data to transform
        /// </summary>
        [FieldOffset(16)]
        private InternalSHA512Block pendingBlock = new();

        /// <summary>
        /// Current hashing state
        /// </summary>
        [FieldOffset(16 + InternalSHA512Block.TypeByteSz)]
        private InternalSHA512State state = new();

        /// <summary>
        /// Initial state to be used by Reset()
        /// </summary>
        [FieldOffset(16 + InternalSHA512Block.TypeByteSz + InternalSHA512State.TypeByteSz)]
        private InternalSHA512State initState;

        /// <summary>
        /// Size of structure in bytes
        /// </summary>
        public const int TypeByteSz = 2 * sizeof(uint) + sizeof(ulong) + InternalSHA512Block.TypeByteSz + InternalSHA512State.TypeByteSz * 2;

        public int HashSz => digestSz;

        public SHA512Base(in InternalSHA512State constants, int outSz)
        {
            initState = constants;
            digestSz = outSz;
            Reset();
        }

        /// <summary>
        /// Reset to initial state
        /// </summary>
        public void Reset()
        {
            blockLen = 0;
            bitLen = 0;
            pendingBlock.Reset();
            state = initState;
        }

        /// <summary>
        /// Update hasher with new data bytes
        /// </summary>
        /// <param name="input">Input bytes to update hasher with</param>
        /// <exception cref="InvalidOperationException"></exception>
        public void Update(ReadOnlySpan<byte> input)
        {
            for (int i = 0; i < input.Length;)
            {
                // How many bytes are left unprocessed
                int remaining = input.Length - i;

                // How many bytes are needed to complete this block
                int needed = 128 - (int)blockLen;

                // Either entire remaining byte stream or merely a needed chunk of it
                ReadOnlySpan<byte> toWrite = input.Slice(i, (remaining < needed) ? remaining : needed);

                // Write data at current index
                pendingBlock.Write(toWrite, blockLen);

                i += toWrite.Length;
                blockLen += (uint)toWrite.Length;

                if (blockLen == 128)
                {
                    // End of the block
                    Transform();
                    bitLen += 1024;
                    blockLen = 0;
                }
            }
        }

        /// <summary>
        /// Write hash into given byte array
        /// </summary>
        /// <param name="hash">Byte array to write into</param>
        public void Digest(Span<byte> hash)
        {
            if (hash.Length != digestSz)
            {
                throw new InvalidOperationException("Target buffer size doesn't match the expected " + digestSz + " bytes");
            }

            Finish();
            state.Store(hash);
            Reset();
        }

        /// <summary>
        /// Get hash as a new byte array
        /// </summary>
        /// <returns></returns>
        public byte[] Digest()
        {
            Finish();
            byte[] hash = new byte[digestSz];
            state.Store(hash);
            Reset();
            return hash;
        }

        private void Transform()
        {
            // Initialize with first 16 words filled from the
            // pending block and reverted to big endian
            InternalSHA512Round wordPad = new(pendingBlock);

            // Remaining blocks
            for (int i = 16; i < 80; ++i)
            {
                wordPad.registers[i] = InternalSHA512Ops.SIG1(wordPad.registers[i - 2]) + wordPad.registers[i - 7] + InternalSHA512Ops.SIG0(wordPad.registers[i - 15]) + wordPad.registers[i - 16];
            }

            InternalSHA512State loc = state;

            for (int i = 0; i < InternalSHA512Round.TypeUlongSz; ++i)
            {
                ulong t1 = loc.h + InternalSHA512Ops.SIGMA1(loc.e) + InternalSHA512Ops.CHOOSE(loc.e, loc.f, loc.g) + InternalSHA512Constants.K.registers[i] + wordPad.registers[i];
                ulong t2 = InternalSHA512Ops.SIGMA0(loc.a) + InternalSHA512Ops.MAJ(loc.a, loc.b, loc.c);

                loc.h = loc.g;
                loc.g = loc.f;
                loc.f = loc.e;
                loc.e = loc.d + t1;
                loc.d = loc.c;
                loc.c = loc.b;
                loc.b = loc.a;
                loc.a = t1 + t2;
            }

            state.Add(loc);
        }

        private void Finish()
        {
            uint i = blockLen;
            uint end = (blockLen < 112u) ? 112u : 128u;
            pendingBlock.bytes[(int)i++] = 0x80; // Append a bit 1
            pendingBlock.Wipe(i, end - i); // Fill with zeros

            if (blockLen >= 112)
            {
                Transform();
                ulong lastWord = pendingBlock.lastLong;
                pendingBlock.Reset();
                pendingBlock.lastLong = lastWord;
            }

            // Append to the padding the total message's
            // length in bits and transform.
            bitLen += blockLen * 8;
            pendingBlock.lastQWord = bitLen;
            REVERT(ref pendingBlock.lastQWord);
            Transform();

            // Reverse byte ordering to get final hashing result
            state.Revert();
        }

        /// <summary>
        /// Revert 128-bit integer in place
        /// </summary>
        /// <param name="value"></param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe static void REVERT(ref UInt128 value)
        {
            fixed (void* ptr = &value)
            {
                long* lo = (long*)ptr;
                long* hi = lo + 1;

                (*lo, *hi) = (IPAddress.HostToNetworkOrder(*hi), IPAddress.HostToNetworkOrder(*lo));
            }
        }

        public void Dispose()
        {
            Reset();
        }
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct SHA512 : IHasher
	{
        [FieldOffset(0)]
        private SHA512Base ctx = new SHA512Base(InternalSHA512Constants.init_state_512, 64);

        /// <summary>
        /// Size of structure in bytes
        /// </summary>
        public const int TypeByteSz = SHA512Base.TypeByteSz;

        public SHA512()
        {
        }

        #region Pass-through methods
        public int HashSz => ctx.HashSz;
        public byte[] Digest() => ctx.Digest();
        public void Digest(Span<byte> hash) => ctx.Digest(hash);
        public void Reset() => ctx.Reset();
        public void Update(ReadOnlySpan<byte> input) => ctx.Update(input);
        public void Dispose() => ctx.Dispose();
        #endregion

        #region Static methods
        public static byte[] Hash(ReadOnlySpan<byte> input)
        {
            SHA512 hasher = new();
            hasher.Update(input);
            return hasher.Digest();
        }

        public static void Hash(Span<byte> digest, ReadOnlySpan<byte> input)
        {
            SHA512 hasher = new();
            hasher.Update(input);
            Span<byte> hash = stackalloc byte[hasher.HashSz];
            hasher.Digest(hash);
            hash.Slice(0, digest.Length).CopyTo(digest);
        }
        #endregion
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct SHA384 : IHasher
    {
        [FieldOffset(0)]
        private SHA512Base ctx = new SHA512Base(InternalSHA512Constants.init_state_384, 48);

        /// <summary>
        /// Size of structure in bytes
        /// </summary>
        public const int TypeByteSz = SHA512Base.TypeByteSz;

        public SHA384()
        {
        }

        #region Pass-through methods
        public int HashSz => ctx.HashSz;
        public byte[] Digest() => ctx.Digest();
        public void Digest(Span<byte> hash) => ctx.Digest(hash);
        public void Reset() => ctx.Reset();
        public void Update(ReadOnlySpan<byte> input) => ctx.Update(input);
        public void Dispose() => ctx.Dispose();
        #endregion

        #region Static methods
        public static byte[] Hash(ReadOnlySpan<byte> input)
        {
            SHA384 hasher = new();
            hasher.Update(input);
            return hasher.Digest();
        }

        public static void Hash(Span<byte> digest, ReadOnlySpan<byte> input)
        {
            SHA384 hasher = new();
            hasher.Update(input);
            Span<byte> hash = stackalloc byte[hasher.HashSz];
            hasher.Digest(hash);
            hash.Slice(0, digest.Length).CopyTo(digest);
        }
        #endregion
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct SHA512_256 : IHasher
    {
        [FieldOffset(0)]
        private SHA512Base ctx = new SHA512Base(InternalSHA512Constants.init_state_256, 32);

        /// <summary>
        /// Size of structure in bytes
        /// </summary>
        public const int TypeByteSz = SHA512Base.TypeByteSz;

        public SHA512_256()
        {
        }

        #region Pass-through methods
        public int HashSz => ctx.HashSz;
        public byte[] Digest() => ctx.Digest();
        public void Digest(Span<byte> hash) => ctx.Digest(hash);
        public void Reset() => ctx.Reset();
        public void Update(ReadOnlySpan<byte> input) => ctx.Update(input);
        public void Dispose() => ctx.Dispose();
        #endregion

        #region Static methods
        public static byte[] Hash(ReadOnlySpan<byte> input)
        {
            SHA512_256 hasher = new();
            hasher.Update(input);
            return hasher.Digest();
        }

        public static void Hash(Span<byte> digest, ReadOnlySpan<byte> input)
        {
            SHA512_256 hasher = new();
            hasher.Update(input);
            Span<byte> hash = stackalloc byte[hasher.HashSz];
            hasher.Digest(hash);
            hash.Slice(0, digest.Length).CopyTo(digest);
        }
        #endregion
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct SHA512_224 : IHasher
    {
        [FieldOffset(0)]
        private SHA512Base ctx = new SHA512Base(InternalSHA512Constants.init_state_224, 28);

        /// <summary>
        /// Size of structure in bytes
        /// </summary>
        public const int TypeByteSz = SHA512Base.TypeByteSz;

        public SHA512_224()
        {
        }

        #region Pass-through methods
        public int HashSz => ctx.HashSz;
        public byte[] Digest() => ctx.Digest();
        public void Digest(Span<byte> hash) => ctx.Digest(hash);
        public void Reset() => ctx.Reset();
        public void Update(ReadOnlySpan<byte> input) => ctx.Update(input);
        public void Dispose() => ctx.Dispose();
        #endregion

        #region Static methods
        public static byte[] Hash(ReadOnlySpan<byte> input)
        {
            SHA512_224 hasher = new();
            hasher.Update(input);
            return hasher.Digest();
        }

        public static void Hash(Span<byte> digest, ReadOnlySpan<byte> input)
        {
            SHA512_224 hasher = new();
            hasher.Update(input);
            Span<byte> hash = stackalloc byte[hasher.HashSz];
            hasher.Digest(hash);
            hash.Slice(0, digest.Length).CopyTo(digest);
        }
        #endregion
    }
}
