using Wheel.Crypto.Symmetric.AES.Internal;

namespace Wheel.Crypto.Symmetric.AES;

/// <summary>
/// Encapsulated symmetric encryption key
/// </summary>
public ref struct AESKey
{
    internal ReadOnlySpan<byte> data;
    public const int TypeByteSz = 4 * AESCTR.Nk;

    /// <summary>
    /// Initialize by keeping a slice of provided key buffer.
    /// No data actually being copied.
    /// </summary>
    /// <param name="key">Secret data</param>
    public AESKey(in ReadOnlySpan<byte> key)
    {
        data = key.Slice(0, TypeByteSz);
    }

    internal readonly byte this[int index] => data[index];

    public static implicit operator AESKey(in ReadOnlySpan<byte> key)
    {
        return new AESKey(key);
    }
}
