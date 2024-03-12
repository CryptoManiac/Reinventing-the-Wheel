namespace Wheel.Crypto.Hashing
{
	public interface IHasher
	{
        public int HashSz { get; }
        public void Reset();
        public byte[] Digest();
        public void Digest(Span<byte> hash);
        public void Update(ReadOnlySpan<byte> input);
    }
}

