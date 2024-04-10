namespace EdDSA_Mehdi.Internal.BaseTypes;

public struct M256
{
    private unsafe fixed U32 _words[8];

    public unsafe Span<U32> words
    {
        get
        {
            fixed(U32* ptr = &_words[0])
            {
                return new Span<U32>(ptr, 8);
            }
        }
    }

    public unsafe U32 this[int index]
    {
        get => words[index];
        set => words[index] = value;
    }

    public M256(ReadOnlySpan<U32> words)
    {
        words.CopyTo(this.words);
    }

    public static implicit operator M256(ReadOnlySpan<U32> words)
    {
        return new(words);
    }
}

public struct M256V_U8
{
    private unsafe fixed U8 _bytes[32];

    public unsafe Span<U8> bytes
    {
        get
        {
            fixed(U8* ptr = &_bytes[0])
            {
                return new Span<U8>(ptr, 32);
            }
        }
    }

    public unsafe U8 this[int index]
    {
        get => bytes[index];
        set => bytes[index] = value;
    }

    public M256V_U8(ReadOnlySpan<U8> words)
    {
        words.CopyTo(this.bytes);
    }

    public static implicit operator M256V_U8(ReadOnlySpan<U8> bytes)
    {
        return new(bytes);
    }
}
