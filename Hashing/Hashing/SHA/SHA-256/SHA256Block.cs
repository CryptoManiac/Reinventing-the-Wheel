using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Wheel.Hashing.SHA.SHA256.Internal;

/// <summary>
/// Represents the block data for the 256-bit family of SHA functions
/// </summary>
[StructLayout(LayoutKind.Explicit)]
internal struct InternalSHA256Block
{
    /// <summary>
    /// Shortcut for making slices of the internal storage
    /// </summary>
    /// <param name="start">Offset of slice start position</param>
    /// <param name="length">Number of bytes</param>
    /// <returns>A slice of bytes that can be written to</returns>
    public readonly Span<byte> Slice(int start, int length)
    {
        return bytes.Slice(start, length);
    }

    /// <summary>
    /// Set to zero
    /// </summary>
    public void Reset()
    {
        bytes.Clear();
    }

    /// <summary>
    /// Size of structure in memory when treated as a collection of bytes
    /// </summary>
    public const int TypeByteSz = 64;

    /// <summary>
    /// Size of structure in memory when treated as a collection of uint values
    /// </summary>
    public const int TypeUintSz = TypeByteSz / sizeof(uint);

    /// <summary>
    /// Access to individual bytes
    /// </summary>
    [FieldOffset(0)]
    private unsafe fixed byte data[TypeByteSz];

    /// <summary>
    /// Safe access to bytes
    /// </summary>
    public readonly unsafe Span<byte> bytes
    {
        get
        {
            fixed (byte* ptr = &data[0])
            {
                return new Span<byte>(ptr, TypeByteSz);
            }
        }
    }

    /// <summary>
    /// Special case: Public access to the last 32-bit integer for the finalization function
    /// </summary>
    [FieldOffset(60)]
    public uint lastWord;

    /// <summary>
    /// Special case: Public access to the last double word (64-bit) for length addition
    /// </summary>
    [FieldOffset(56)]
    public ulong lastDWord;
}
