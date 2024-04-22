namespace Wheel.Crypto.Elliptic.EllipticCommon;

/// <summary>
/// Choose between two spans by either zero or non-zero index, without branching
/// </summary>
public ref struct Picker
{
    unsafe readonly ulong* s0;
    unsafe readonly ulong* s1;
    unsafe fixed int sizes[2];

    public unsafe Picker(Span<ulong> s0, Span<ulong> s1)
    {
        fixed (void* ptr = s0)
        {
            this.s0 = (ulong*) ptr;
        }
        fixed (void* ptr = s1)
        {
            this.s1 = (ulong*) ptr;
        }

        sizes[0] = s0.Length;
        sizes[1] = s1.Length;
    }
    public unsafe readonly Span<ulong> this[int index]
    {
        get {
            ulong** arr = stackalloc ulong*[2] { s0, s1 };
            int i = index % 2;
            return new(arr[i], sizes[i]);
        }
    }
    public readonly Span<ulong> this[ulong index]
    {
        get => this[Convert.ToInt32(index)];
    }

    public readonly Span<ulong> this[bool index]
    {
        get => this[Convert.ToInt32(index)];
    }
}

/// <summary>
/// Choose between two spans by either zero or non-zero index
/// </summary>
public ref struct ReadOnlyPicker
{
    unsafe readonly ulong* s0;
    unsafe readonly ulong* s1;
    unsafe fixed int sizes[2];

    public unsafe ReadOnlyPicker(ReadOnlySpan<ulong> s0, ReadOnlySpan<ulong> s1)
    {
        fixed (void* ptr = s0)
        {
            this.s0 = (ulong*)ptr;
        }
        fixed (void* ptr = s1)
        {
            this.s1 = (ulong*)ptr;
        }

        sizes[0] = s0.Length;
        sizes[1] = s1.Length;
    }
    public unsafe readonly ReadOnlySpan<ulong> this[int index]
    {
        get
        {
            ulong** arr = stackalloc ulong*[2] { s0, s1 };
            return new(arr[index % 2], sizes[index % 2]);
        }
    }
    public readonly ReadOnlySpan<ulong> this[ulong index]
    {
        get => this[Convert.ToInt32(index)];
    }

    public readonly ReadOnlySpan<ulong> this[bool index]
    {
        get => this[Convert.ToInt32(index)];
    }
}

