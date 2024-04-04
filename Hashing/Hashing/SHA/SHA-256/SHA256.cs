using Wheel.Hashing.SHA.SHA256.Internal;
using System.Runtime.InteropServices;
using System.Net;
using System.Runtime.CompilerServices;

namespace Wheel.Hashing.SHA.SHA256;

[SkipLocalsInit]
[StructLayout(LayoutKind.Explicit)]
internal struct SHA256Base : IHasher
{
    /// <summary>
    /// Current data block length in bytes
    /// </summary>
    [FieldOffset(0)]
    private int blockLen = 0;

    /// <summary>
    /// Output length
    /// </summary>
    [FieldOffset(4)]
    private readonly int digestSz;

    /// <summary>
    /// Total input length in bits
    /// </summary>
    [FieldOffset(8)]
    private ulong bitLen = 0;

    /// <summary>
    /// Pending block data to transform
    /// </summary>
    [FieldOffset(16)]
    private InternalSHA256Block pendingBlock = new();

    /// <summary>
    /// Current hashing state
    /// </summary>
    [FieldOffset(16 + InternalSHA256Block.TypeByteSz)]
    private InternalSHA256State state = new();

    /// <summary>
    /// Initial state to be used by Reset()
    /// </summary>
    [FieldOffset(16 + InternalSHA256Block.TypeByteSz + InternalSHA256State.TypeByteSz)]
    private InternalSHA256State initState;

    /// <summary>
    /// Size of structure in bytes
    /// </summary>
    public const int TypeByteSz = 2 * sizeof(uint) + sizeof(ulong) + InternalSHA256Block.TypeByteSz + InternalSHA256State.TypeByteSz * 2;

    public int HashSz => digestSz;

    public SHA256Base(in InternalSHA256State constants, int outSz)
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
    /// Get SHA256 hash as a new byte array
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
            int needed = 64 - blockLen;

            // Either entire remaining byte stream or merely a needed chunk of it
            ReadOnlySpan<byte> toWrite = input.Slice(i, (remaining < needed) ? remaining : needed);

            // Write data at current index
            toWrite.CopyTo(
                pendingBlock.Slice(blockLen, toWrite.Length)
            );

            i += toWrite.Length;
            blockLen += toWrite.Length;

            if (blockLen == 64)
            {
                // End of the block
                Transform();
                bitLen += 512;
                blockLen = 0;
            }
        }
    }

    private void Transform()
    {
        // Initialize with first 16 words filled from the
        // pending block and reverted to big endian
        InternalSHA256Round wordPad = new(pendingBlock);

        // Remaining 48 blocks
        for (int i = 16; i < 64; ++i)
        {
            wordPad.registers[i] = InternalSHA256Ops.SIG1(wordPad.registers[i - 2]) + wordPad.registers[i - 7] + InternalSHA256Ops.SIG0(wordPad.registers[i - 15]) + wordPad.registers[i - 16];
        }

        InternalSHA256State loc = state;

        for (int i = 0; i < 64; ++i)
        {
            uint t1 = loc.h + InternalSHA256Ops.SIGMA1(loc.e) + InternalSHA256Ops.CHOOSE(loc.e, loc.f, loc.g) + InternalSHA256Constants.K.registers[i] + wordPad.registers[i];
            uint t2 = InternalSHA256Ops.SIGMA0(loc.a) + InternalSHA256Ops.MAJ(loc.a, loc.b, loc.c);

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
        int i = blockLen;
        int end = (blockLen < 56) ? 56 : 64;
        pendingBlock.bytes[i++] = 0x80; // Append a bit 1
        pendingBlock.Slice(i, end - i).Clear(); // Set the rest to padding zeros

        if (blockLen >= 56)
        {
            Transform();
            unsafe
            {
                uint lastWord = pendingBlock.lastWord;
                pendingBlock.Reset();
                pendingBlock.lastWord = lastWord;
            }
        }

        // Append to the padding the total message's
        // length in bits and transform.
        bitLen += (ulong)blockLen * 8;
        pendingBlock.lastDWord = (ulong)IPAddress.HostToNetworkOrder((long)bitLen);
        Transform();

        // Reverse byte ordering to get final hashing result
        state.Revert();
    }

    public void Dispose()
    {
        Reset();
    }
}

[StructLayout(LayoutKind.Explicit)]
public struct SHA256 : IHasher
	{
    [FieldOffset(0)]
    private SHA256Base ctx = new (InternalSHA256Constants.init_state_256, 32);

    /// <summary>
    /// Size of structure in bytes
    /// </summary>
    public const int TypeByteSz = SHA256Base.TypeByteSz;

    public SHA256()
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
        SHA256 hasher = new();
        hasher.Update(input);
        return hasher.Digest();
    }

    public static void Hash(Span<byte> digest, ReadOnlySpan<byte> input)
    {
        SHA256 hasher = new();
        hasher.Update(input);
        Span<byte> hash = stackalloc byte[hasher.HashSz];
        hasher.Digest(hash);
        hash.Slice(0, digest.Length).CopyTo(digest);
    }
    #endregion
}

[StructLayout(LayoutKind.Explicit)]
public struct SHA224 : IHasher
{
    [FieldOffset(0)]
    private SHA256Base ctx = new(InternalSHA256Constants.init_state_224, 28);

    /// <summary>
    /// Size of structure in bytes
    /// </summary>
    public const int TypeByteSz = SHA256Base.TypeByteSz;

    public SHA224()
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
        SHA224 hasher = new();
        hasher.Update(input);
        return hasher.Digest();
    }

    public static void Hash(Span<byte> digest, ReadOnlySpan<byte> input)
    {
        SHA224 hasher = new();
        hasher.Update(input);
        hasher.Digest(digest);
    }
    #endregion
}
