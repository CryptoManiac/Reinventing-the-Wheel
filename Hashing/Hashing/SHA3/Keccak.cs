using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Wheel.Hashing.SHA3.Internal;

[SkipLocalsInit]
[StructLayout(LayoutKind.Explicit)]
internal struct Keccak : IHasher
{
    /// <summary>
    /// 0..7--the next byte after the set one
    /// (starts from 0; 0--none are buffered)
    /// </summary>
    [FieldOffset(0)]
    public int byteIndex;

    /// <summary>
    /// 0..24--the next word to integrate input
    /// (starts from 0)
    /// </summary>
    [FieldOffset(4)]
    public int wordIndex;

    /// <summary>
    /// the portion of the input message that we didn't consume yet
    /// </summary>
    [FieldOffset(8)]
    public ulong saved;

    /// <summary>
    /// Keccak data mixer
    /// </summary>
    [FieldOffset(16)]
    private unsafe fixed ulong words[SHA3_SPONGE_WORDS];

    /// <summary>
    /// the double size of the hash output in
    /// words (e.g. 16 for Keccak 512)
    /// </summary>
    [FieldOffset(216)]
    public readonly int capacityWords;

    /// <summary>
    /// Keccak is a little different from the standard SHA3
    /// </summary>
    [FieldOffset(220)]
    public readonly bool IsKeccak;

    /// <summary>
    /// To avoid the unsafe blocks where the performance is not critical
    /// </summary>
    private readonly unsafe Span<ulong> registers
    {
        get
        {
            fixed (ulong* ptr = &words[0])
            {
                return new Span<ulong>(ptr, SHA3_SPONGE_WORDS);
            }
        }
    }

    /// <summary>
    /// Keccak round constants array
    /// </summary>
    private static readonly ulong[] rndc = new ulong[24] {
            0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
            0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
            0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
            0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
            0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
            0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
            0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
            0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    };

    public const int SHA3_SPONGE_WORDS = 25; // Calculated as 1600 / 8 / sizeof(ulong)

    public readonly int HashSz => capacityWords * 4;

    public Keccak(int bitSize, bool isKeccak)
    {
        if (bitSize != 256 && bitSize != 384 && bitSize != 512)
        {
            throw new InvalidOperationException("Valid bitSize values are: 256, 384 or 512");
        }

        capacityWords = bitSize / 32;
        IsKeccak = isKeccak;
    }

    public void Reset()
    {
        byteIndex = 0;
        wordIndex = 0;
        saved = 0;
        registers.Clear();
    }

    public void Update(ReadOnlySpan<byte> input)
    {
        // 0...7 -- how much is needed to have a word
        int offset = WriteTail(input);
        int words = (input.Length - offset) / 8;

        // now work in full words directly from input
        for (int i = 0; i < words; i++, offset += 8)
        {
            registers[wordIndex] ^= (input[offset]) |
                ((ulong)input[offset + 1] << 8 * 1) |
                ((ulong)input[offset + 2] << 8 * 2) |
                ((ulong)input[offset + 3] << 8 * 3) |
                ((ulong)input[offset + 4] << 8 * 4) |
                ((ulong)input[offset + 5] << 8 * 5) |
                ((ulong)input[offset + 6] << 8 * 6) |
                 ((ulong)input[offset + 7] << 8 * 7);

            if (++wordIndex == (SHA3_SPONGE_WORDS - capacityWords))
            {
                KeccakF();
                wordIndex = 0;
            }
        }

        // Add remaining odd bytes
        while (offset < input.Length)
        {
            saved |= (ulong)input[offset++] << (byteIndex++ * 8);
        }
    }

    private int WriteTail(ReadOnlySpan<byte> input)
    {
        // 0...7 -- how much is needed to have a word
        int old_tail = (8 - byteIndex) & 7;

        if (input.Length < old_tail)
        {
            // have no complete word or haven't started
            // the word yet
            foreach (var b in input)
            {
                saved |= (ulong)b << (byteIndex++ * 8);
            }
            return input.Length;
        }

        if (old_tail > 0)
        {
            for (int i = 0; i < old_tail; ++i)
            {
                saved |= (ulong)input[i] << (byteIndex++ * 8);
            }

            // now ready to add saved to the sponge

            registers[wordIndex] ^= saved;

            byteIndex = 0;
            saved = 0;

            if (++wordIndex == (SHA3_SPONGE_WORDS - capacityWords))
            {
                KeccakF();
                wordIndex = 0;
            }

            return old_tail;
        }

        // No offset
        return 0;
    }

    public void Digest(Span<byte> hash)
    {
        if (hash.Length != HashSz)
        {
            throw new InvalidOperationException("Target buffer size doesn't match the expected " + HashSz + " bytes");
        }

        /// This is simply the 'update' with the padding block.
        /// The padding block is 0x01 || 0x00* || 0x80. First 0x01 and last 0x80 
        /// bytes are always present, but they can be the same byte.

        // Append 2-bit suffix 01, per SHA-3 spec. Instead of 1 for padding we
        //  use 1<<2 below. The 0x02 below corresponds to the suffix 01.
        //  Overall, we feed 0, then 1, and finally 1 to start padding. Without
        //  M || 01, we would simply use 1 to start padding.

        ulong t;

        if (IsKeccak)
        {
            // Keccak version
            t = ((ulong)1) << (byteIndex * 8);
        }
        else
        {
            // SHA3 version
            t = ((ulong)(0x02 | (1 << 2))) << (byteIndex * 8);
        }

        registers[wordIndex] ^= saved ^ t;
        registers[SHA3_SPONGE_WORDS - capacityWords - 1] ^= 0x8000000000000000UL;

        KeccakF();

        // Revert byte order on BE machines
        //  Considering that Itanium is dead, this is unlikely to ever be useful
        if (!BitConverter.IsLittleEndian)
        {
            for (int i = 0; i < SHA3_SPONGE_WORDS; ++i)
            {
                registers[i] = (ulong)IPAddress.HostToNetworkOrder((long)registers[i]);
            }
        }

        MemoryMarshal.Cast<ulong, byte>(registers).Slice(0, hash.Length).CopyTo(hash);

        // Reset hasher state
        Reset();
    }

    public byte[] Digest()
    {
        byte[] hash = new byte[HashSz];
        Digest(hash);
        return hash;
    }

    private unsafe void KeccakF()
    {
        ulong x, a_10_;
        ulong bc0, bc1, bc2, bc3, bc4;

        ulong x0, x1, x2, x3, x4;
        ulong t0, t1, t2, t3, t4;

        for (int round = 0; round < 24; ++round)
        {
            // Theta
            bc0 = words[0] ^ words[5 + 0] ^ words[10 + 0] ^ words[15 + 0] ^ words[20 + 0];
            bc1 = words[1] ^ words[5 + 1] ^ words[10 + 1] ^ words[15 + 1] ^ words[20 + 1];
            bc2 = words[2] ^ words[5 + 2] ^ words[10 + 2] ^ words[15 + 2] ^ words[20 + 2];
            bc3 = words[3] ^ words[5 + 3] ^ words[10 + 3] ^ words[15 + 3] ^ words[20 + 3];
            bc4 = words[4] ^ words[5 + 4] ^ words[10 + 4] ^ words[15 + 4] ^ words[20 + 4];

            t0 = (bc0 << 1) ^ (bc0 >>> (64 - 1)) ^ bc3;
            t1 = (bc1 << 1) ^ (bc1 >>> (64 - 1)) ^ bc4;
            t2 = (bc2 << 1) ^ (bc2 >>> (64 - 1)) ^ bc0;
            t3 = (bc3 << 1) ^ (bc3 >>> (64 - 1)) ^ bc1;
            t4 = (bc4 << 1) ^ (bc4 >>> (64 - 1)) ^ bc2;

            //theta (xorring part) + rho + pi
            words[0] ^= t1;
            x = words[1] ^ t2; a_10_ = (x << 1) | (x >>> (64 - 1));
            x = words[6] ^ t2; words[1] = (x << 44) | (x >>> (64 - 44));
            x = words[9] ^ t0; words[6] = (x << 20) | (x >>> (64 - 20));
            x = words[22] ^ t3; words[9] = (x << 61) | (x >>> (64 - 61));

            x = words[14] ^ t0; words[22] = (x << 39) | (x >>> (64 - 39));
            x = words[20] ^ t1; words[14] = (x << 18) | (x >>> (64 - 18));
            x = words[2] ^ t3; words[20] = (x << 62) | (x >>> (64 - 62));
            x = words[12] ^ t3; words[2] = (x << 43) | (x >>> (64 - 43));
            x = words[13] ^ t4; words[12] = (x << 25) | (x >>> (64 - 25));

            x = words[19] ^ t0; words[13] = (x << 8) | (x >>> (64 - 8));
            x = words[23] ^ t4; words[19] = (x << 56) | (x >>> (64 - 56));
            x = words[15] ^ t1; words[23] = (x << 41) | (x >>> (64 - 41));
            x = words[4] ^ t0; words[15] = (x << 27) | (x >>> (64 - 27));
            x = words[24] ^ t0; words[4] = (x << 14) | (x >>> (64 - 14));

            x = words[21] ^ t2; words[24] = (x << 2) | (x >>> (64 - 2));
            x = words[8] ^ t4; words[21] = (x << 55) | (x >>> (64 - 55));
            x = words[16] ^ t2; words[8] = (x << 45) | (x >>> (64 - 45));
            x = words[5] ^ t1; words[16] = (x << 36) | (x >>> (64 - 36));
            x = words[3] ^ t4; words[5] = (x << 28) | (x >>> (64 - 28));

            x = words[18] ^ t4; words[3] = (x << 21) | (x >>> (64 - 21));
            x = words[17] ^ t3; words[18] = (x << 15) | (x >>> (64 - 15));
            x = words[11] ^ t2; words[17] = (x << 10) | (x >>> (64 - 10));
            x = words[7] ^ t3; words[11] = (x << 6) | (x >>> (64 - 6));
            x = words[10] ^ t1; words[7] = (x << 3) | (x >>> (64 - 3));
            words[10] = a_10_;

            // Chi
            for (int j = 0; j < 25; j += 5)
            {
                x0 = words[j + 0];
                x1 = words[j + 1];
                x2 = words[j + 2];
                x3 = words[j + 3];
                x4 = words[j + 4];
                words[j + 0] = x0 ^ ((~x1) & x2);
                words[j + 1] = x1 ^ ((~x2) & x3);
                words[j + 2] = x2 ^ ((~x3) & x4);
                words[j + 3] = x3 ^ ((~x4) & x0);
                words[j + 4] = x4 ^ ((~x0) & x1);
            }

            //iota
            words[0] ^= rndc[round];
        }
    }

    public void Dispose()
    {
        Reset();
    }
}
