using System.Runtime.InteropServices;

namespace Wheel.Hashing.SHA.SHA512.Internal;

/// <summary>
/// Represents the block data for the 512-bit family of SHA functions
/// </summary>
[StructLayout(LayoutKind.Explicit)]
internal struct InternalSHA512Block
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
    public const int TypeByteSz = 128;

    /// <summary>
    /// Size of structure in memory when treated as a collection of ulong values
    /// </summary>
    public const int TypeUlongSz = TypeByteSz / sizeof(ulong);

    /// <summary>
    /// Buffer for the individuab block bytes
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
    /// Special case: Public access to the last 64-bit integer for the finalization function
    /// </summary>
    [FieldOffset(120)]
    public ulong lastLong;

    /// <summary>
    /// Special case: Public access to the last QWord for length addition
    /// </summary>
    [FieldOffset(112)]
    public UInt128 lastQWord;
}
