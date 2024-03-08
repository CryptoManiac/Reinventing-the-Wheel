namespace Wheel.Crypto.Hashing
{
	public interface IHasher
	{
        public void Reset();
        public byte[] Digest();
        public void Digest(Span<byte> hash);
        public void Update(byte[] input);
    }
}

