using System.Runtime.InteropServices;

namespace Wheel.Crypto.Symmetric.AES.Internal;

/// <summary>
/// View buffer as either block or state
/// </summary>
internal ref struct AESBuffer
{
    private readonly Span<AESBlock> _block;
    private readonly Span<State> _state;

    public AESBlock Block
    {
        readonly get => _block[0];
        set => _block[0] = value;
    }

    public State State
    {
        readonly get => _state[0];
        set => _state[0] = value;
    }

    /// <summary>
    /// AES block view structure which can be worked
    /// with as both AES block and AES state
    /// </summary>
    /// <param name="buffer">Region of memory to work with</param>
    /// <exception cref="InvalidOperationException">When the buffer size does't match the AES block size</exception>
    public AESBuffer(Span<byte> buffer)
    {
        if (buffer.Length != AESBlock.TypeByteSz)
        {
            throw new InvalidOperationException("Incorrect block buffer size");
        }

        _block = MemoryMarshal.Cast<byte, AESBlock>(buffer);
        _state = MemoryMarshal.Cast<byte, State>(buffer);
    }

    public static implicit operator AESBuffer(Span<byte> buffer)
    {
        return new AESBuffer(buffer);
    }
}