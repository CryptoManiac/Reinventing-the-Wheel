using System.Net;
using System.Runtime.InteropServices;
namespace Wheel.Hashing.SHA.SHA256.Internal;

/// <summary>
/// Represents the round context data for the 256-bit family of SHA functions
/// </summary>
[StructLayout(LayoutKind.Explicit)]
internal struct InternalSHA256Round
{
    /// <summary>
    /// Instantiate from array or a variable number of arguments
    /// </summary>
    /// <param name="uints"></param>
    /// <exception cref="ArgumentOutOfRangeException"></exception>
    public InternalSHA256Round(params uint[] uints)
    {
        if (uints.Length != TypeUintSz)
        {
            throw new ArgumentOutOfRangeException(nameof(uints), uints.Length, "Must provide " + TypeUintSz + " arguments exactly");
        }

        uints.CopyTo(registers);
    }

    /// <summary>
    /// Initialize first 16 registers from the provided block and revert them
    /// </summary>
    /// <param name="block">A context to provide 16 registers</param>
    internal InternalSHA256Round(in InternalSHA256Block block)
    {
        SetBlock(block);
        RevertBlock();
    }

    /// <summary>
    /// Set first 16 registers from the provided container
    /// </summary>
    /// <param name="block">A context to provide 16 registers</param>
    private void SetBlock(in InternalSHA256Block block)
    {
        block.bytes.CopyTo(
            MemoryMarshal.Cast<uint, byte>(registers)
        );
    }

    /// <summary>
    /// Revert the byte order for the first 16 state registers
    /// </summary>
    private void RevertBlock()
    {
        for (int i = 0; i < InternalSHA256Block.TypeUintSz; ++i)
        {
            registers[i] = (uint)IPAddress.HostToNetworkOrder((int)registers[i]);
        }
    }

    /// <summary>
    /// Set to zero
    /// </summary>
    public void Reset()
    {
        registers.Clear();
    }

    /// <summary>
    /// Safe access to registers
    /// </summary>
    public readonly unsafe Span<uint> registers
    {
        get
        {
            fixed (uint* ptr = &words[0])
            {
                return new Span<uint>(ptr, TypeUintSz);
            }
        }
    }

    /// <summary>
    /// Size of structure in memory when treated as a collection of uint values
    /// </summary>
    public const int TypeUintSz = 64;

    // <summary>
    /// Size of structure in memory when treated as a collection of bytes
    /// </summary>
    public const int TypeByteSz = TypeUintSz * sizeof(uint);

    /// <summary>
    /// Fixed size buffer for registers
    /// </summary>
    [FieldOffset(0)]
    private unsafe fixed uint words[TypeUintSz];
}
