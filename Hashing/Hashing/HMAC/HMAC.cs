using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Hashing;
using Wheel.Hashing.HMAC;

namespace Hashing.Hashing.HMAC;

/// <summary>
/// Generic HMAC context
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 0)]
public struct HMAC<Hasher> : IMac where Hasher : unmanaged, IHasher
{
    private Hasher inside;
    private Hasher outside;

    // For key pre-hashing
    private Hasher prehasher;

    #region For Reinit()
    private Hasher inside_reinit;
    private Hasher outside_reinit;
    #endregion

    private bool initialized;

    public readonly int HashSz => inside.HashSz;

    public HMAC() {
        inside = outside = prehasher = inside_reinit = outside_reinit = new();
        initialized = false;
    }

    public readonly IMac Clone()
    {
        return this;
    }

    [SkipLocalsInit]
    public void Digest(Span<byte> mac)
    {
        if (!initialized)
        {
            throw new InvalidOperationException("Trying to get a Digest() result from the uninitialized HMAC structure. Please call the Init() method first.");
        }
        Span<byte> mac_temp = stackalloc byte[inside.HashSz];
        inside.Digest(mac_temp);
        outside.Update(mac_temp);
        outside.Digest(mac_temp);
        mac_temp[..mac.Length].CopyTo(mac);
        Reset();
    }

    public void Dispose()
    {
        initialized = false;
        inside.Reset();
        outside.Reset();
        inside_reinit.Reset();
        outside_reinit.Reset();
    }

    [SkipLocalsInit]
    public void Init(ReadOnlySpan<byte> key)
    {
        int keySz;

        Span<byte> key_used = stackalloc byte[prehasher.BlockSz];
        Span<byte> block_opad = stackalloc byte[prehasher.BlockSz];
        Span<byte> block_ipad = stackalloc byte[prehasher.BlockSz];

        if (key.Length == inside.BlockSz)
        {
            key.CopyTo(key_used);
            keySz = inside.BlockSz;
        }
        else
        {
            if (key.Length > prehasher.BlockSz)
            {
                keySz = prehasher.HashSz;
                prehasher.Reset();
                prehasher.Update(key);
                prehasher.Digest(key_used.Slice(0, prehasher.HashSz));
            }
            else
            {
                key.CopyTo(key_used);
                keySz = key.Length;
            }

            int fill = prehasher.BlockSz - keySz;

            block_ipad.Slice(keySz, fill).Fill(0x36);
            block_opad.Slice(keySz, fill).Fill(0x5c);
        }

        for (int i = 0; i < keySz; ++i)
        {
            block_ipad[i] = (byte)(key_used[i] ^ 0x36);
            block_opad[i] = (byte)(key_used[i] ^ 0x5c);
        }

        inside.Reset();
        outside.Reset();

        inside.Update(block_ipad);
        outside.Update(block_opad);

        // for Reset()
        inside_reinit = inside;
        outside_reinit = outside;

        // Allow update/digest calls
        initialized = true;
    }

    public void Reset()
    {
        inside = inside_reinit;
        outside = outside_reinit;
    }

    public void Update(ReadOnlySpan<byte> input)
    {
        if (!initialized)
        {
            throw new InvalidOperationException("Trying to update the uninitialized HMAC structure. Please call the Init() method first.");
        }
        inside.Update(input);
    }
}

