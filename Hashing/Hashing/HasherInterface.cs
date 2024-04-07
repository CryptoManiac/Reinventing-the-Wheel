namespace Wheel.Hashing;

public interface IHasher : IDisposable
{
    public int HashSz { get; }
    public int BlockSz { get; }
    public void Reset();
    public byte[] Digest();
    public void Digest(Span<byte> hash);
    public void Update(ReadOnlySpan<byte> input);
}
