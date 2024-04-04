using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Hashing.RIPEMD.Internal;

namespace Wheel.Hashing.RIPEMD;

[SkipLocalsInit]
[StructLayout(LayoutKind.Explicit)]
public struct RIPEMD160 : IHasher
{
    [FieldOffset(0)]
    private int bytesLo = 0;

    [FieldOffset(4)]
    private int bytesHi = 0;

    [FieldOffset(8)]
    private InternalRIPEMDState state = InternalRIPEMDConstants.ripemd_init_state;

    [FieldOffset(12 + InternalRIPEMDBlock.TypeByteSz)]
    private InternalRIPEMDBlock block = new();

    public RIPEMD160()
    {
    }

    public readonly int HashSz => 20;

    public byte[] Digest()
    {
        byte[] hash = new byte[20];
        Digest(hash);
        return hash;
    }

    public void Digest(Span<byte> digest)
    {
        InternalRIPEMDOps.Finish(ref state, ref block, bytesLo, bytesHi);
        state.Store(digest);
        Reset(); // In case it's sensitive
    }

    public void Reset()
    {
        bytesLo = 0;
        bytesHi = 0;
        state = InternalRIPEMDConstants.ripemd_init_state;
        block.Reset();
    }

    public static byte[] Hash(ReadOnlySpan<byte> input)
    {
        RIPEMD160 hasher = new();
        hasher.Update(input);
        return hasher.Digest();
    }

    public static void Hash(Span<byte> digest, ReadOnlySpan<byte> input)
    {
        RIPEMD160 hasher = new();
        hasher.Update(input);
        hasher.Digest(digest);
    }

    public void Update(ReadOnlySpan<byte> input)
    {
        int len = input.Length;

        // Update bitcount
        int t = bytesLo;
        if ((bytesLo = t + len) < t)
        {
            // Carry from low to high
            ++bytesHi;
        }

        // Bytes already in key
        int i = t % 64;

        // i is always less than block size
        if (64 - i > len)
        {
            input.CopyTo(
                block.Slice(i, input.Length)
            );
            return;
        }

        // Distance from the beginning
        // of the input array
        int offset = 0;

        if (i > 0)
        {
            // First chunk is an odd size
            var oddChunk = input.Slice(offset, 64 - i);
            oddChunk.CopyTo(
                block.Slice(i, oddChunk.Length)
            );
            InternalRIPEMDOps.Compress(ref state, block);
            offset += 64 - i;
            len -= 64 - i;
        }

        while (len >= 64)
        {
            // Process data in 64-byte chunks
            var chunk = input.Slice(offset, 64);
            chunk.CopyTo(
                block.Slice(i, chunk.Length)
            );
            InternalRIPEMDOps.Compress(ref state, block);
            offset += 64;
            len -= 64;
        }

        if (len > 0)
        {
            // Handle any remaining bytes of data.
            var tail = input.Slice(offset, len);
            tail.CopyTo(
                block.Slice(0, tail.Length)
            );
        }
    }

    public void Dispose()
    {
        Reset();
    }
}

