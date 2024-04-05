namespace Wheel.Crypto.Elliptic.EllipticCommon;

/// <summary>
/// Choose between two spans by either zero or non-zero index
/// </summary>
/// <typeparam name="T">Index type (comparable value)</typeparam>
public readonly ref struct Picker
{
    readonly Span<ulong> s0;
    readonly Span<ulong> s1;
    public Picker(Span<ulong> s0, Span<ulong> s1)
    {
        this.s0 = s0;
        this.s1 = s1;
    }
    public readonly Span<ulong> this[int index]
    {
        get => index == 0 ? s0 : s1;
    }
    public readonly Span<ulong> this[ulong index]
    {
        get => index == 0 ? s0 : s1;
    }
    public readonly Span<ulong> this[bool index]
    {
        get => index ? s1 : s0;
    }
}

/// <summary>
/// Choose between two spans by either zero or non-zero index
/// </summary>
/// <typeparam name="T">Index type (comparable value)</typeparam>
public readonly ref struct ReadOnlyPicker
{
    readonly ReadOnlySpan<ulong> s0;
    readonly ReadOnlySpan<ulong> s1;
    public ReadOnlyPicker(ReadOnlySpan<ulong> s0, ReadOnlySpan<ulong> s1)
    {
        this.s0 = s0;
        this.s1 = s1;
    }
    public readonly ReadOnlySpan<ulong> this[int index]
    {
        get => index == 0 ? s0 : s1;
    }
    public readonly ReadOnlySpan<ulong> this[ulong index]
    {
        get => index == 0 ? s0 : s1;
    }
    public readonly ReadOnlySpan<ulong> this[bool index]
    {
        get => index ? s1 : s0;
    }
}

