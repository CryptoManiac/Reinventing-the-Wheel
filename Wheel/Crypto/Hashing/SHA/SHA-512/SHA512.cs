using System.Runtime.CompilerServices;
using Wheel.Crypto.Hashing.SHA.SHA512.Internal;
using Wheel.Crypto.Miscellaneous.Support;

namespace Wheel.Crypto.Hashing.SHA.SHA512
{
    public abstract class SHA512Base : IHasher
    {
        /// <summary>
        /// Current data block length in bytes
        /// </summary>
        protected uint blockLen;

        /// <summary>
        /// Total input length in bits
        /// </summary>
        protected ulong bitLen;

        /// <summary>
        /// Pending block data to transform
        /// </summary>
        protected InternalSHA512Block pendingBlock = new();

        /// <summary>
        /// Current hashing state
        /// </summary>
        protected InternalSHA512State state = new();

        public SHA512Base()
        {
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
            SetInitState();
        }

        protected abstract void SetInitState();
        protected abstract int GetHashLength();

        /// <summary>
        /// Update hasher with new data bytes
        /// </summary>
        /// <param name="input">Input bytes to update hasher with</param>
        /// <exception cref="InvalidOperationException"></exception>
        public void Update(byte[] input)
        {

            for (int i = 0; i < input.Length;)
            {
                // How many bytes are left unprocessed
                int remaining = input.Length - i;

                // How many bytes are needed to complete this block
                int needed = 128 - (int)blockLen;

                // Either entire remaining byte stream or merely a needed chunk of it
                Span<byte> toWrite = new(input, i, (remaining < needed) ? remaining : needed);

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
            if (hash.Length != GetHashLength())
            {
                throw new InvalidOperationException("Target buffer size doesn't match the expected " + GetHashLength() + " bytes");
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
            byte[] hash = new byte[GetHashLength()];
            state.Store(hash);
            Reset();
            return hash;
        }

        protected unsafe void Transform()
        {
            // Block mixing is done here
            InternalSHA512Round wordPad = new();

            // Split data in 64 bit blocks for the first 16 words
            wordPad.SetBlock(pendingBlock);

            // SHA uses big endian byte ordering
            wordPad.RevertBlock();

            // Remaining blocks
            for (uint i = 16; i < 80; ++i)
            {
                wordPad[i] = InternalSHA512Ops.SIG1(wordPad[i - 2]) + wordPad[i - 7] + InternalSHA512Ops.SIG0(wordPad[i - 15]) + wordPad[i - 16];
            }

            InternalSHA512State loc = new(state);

            for (uint i = 0; i < InternalSHA512Round.TypeUlongSz; ++i)
            {
                ulong t1 = loc.h + InternalSHA512Ops.SIGMA1(loc.e) + InternalSHA512Ops.CHOOSE(loc.e, loc.f, loc.g) + InternalSHA512Constants.K[i] + wordPad[i];
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

        protected void Finish()
        {
            uint i = blockLen;
            uint end = (blockLen < 112u) ? 112u : 128u;
            pendingBlock.bytes[i++] = 0x80; // Append a bit 1
            pendingBlock.Wipe(i, end - i); // Fill with zeros

            if (blockLen >= 112)
            {
                Transform();
                ulong lastWord = pendingBlock[15];
                pendingBlock.Reset();
                pendingBlock[15] = lastWord;
            }

            // Append to the padding the total message's
            // length in bits and transform.
            bitLen += blockLen * 8;
            pendingBlock.lastQWord = bitLen;
            Common.REVERT(ref pendingBlock.lastQWord);
            Transform();

            // Reverse byte ordering to get final hashing result
            state.Revert();
        }
    }

    public class SHA512 : SHA512Base
	{
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected override int GetHashLength()
        {
            return 64;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected override void SetInitState()
        {
            state.Set(InternalSHA512Constants.init_state_512);
        }

        public static byte[] Hash(byte[] input)
        {
            SHA512 hasher = new();
            hasher.Update(input);
            return hasher.Digest();
        }

        public static void Hash(Span<byte> digest, byte[] input)
        {
            SHA512 hasher = new();
            hasher.Update(input);
            hasher.Digest(digest);
        }

    }

    public class SHA384 : SHA512Base
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected override int GetHashLength()
        {
            return 48;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected override void SetInitState()
        {
            state.Set(InternalSHA512Constants.init_state_384);
        }

        public static byte[] Hash(byte[] input)
        {
            SHA384 hasher = new();
            hasher.Update(input);
            return hasher.Digest();
        }

        public static void Hash(Span<byte> digest, byte[] input)
        {
            SHA384 hasher = new();
            hasher.Update(input);
            hasher.Digest(digest);
        }
    }

    public class SHA512_256 : SHA512Base
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected override int GetHashLength()
        {
            return 32;
        }

        protected override void SetInitState()
        {
            state.Set(InternalSHA512Constants.init_state_256);
        }

        public static byte[] Hash(byte[] input)
        {
            SHA512_256 hasher = new();
            hasher.Update(input);
            return hasher.Digest();
        }

        public static void Hash(Span<byte> digest, byte[] input)
        {
            SHA512_256 hasher = new();
            hasher.Update(input);
            hasher.Digest(digest);
        }
    }

    public class SHA512_224 : SHA512Base
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected override int GetHashLength()
        {
            return 28;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected override void SetInitState()
        {
            state.Set(InternalSHA512Constants.init_state_224);
        }

        public static byte[] Hash(byte[] input)
        {
            SHA512_224 hasher = new();
            hasher.Update(input);
            return hasher.Digest();
        }

        public static void Hash(Span<byte> digest, byte[] input)
        {
            SHA512_224 hasher = new();
            hasher.Update(input);
            hasher.Digest(digest);
        }
    }
}
