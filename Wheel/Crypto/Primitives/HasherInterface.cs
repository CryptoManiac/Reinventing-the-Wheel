namespace Wheel.Crypto.Primitives
{
	public interface IHasherInterface
	{
        public void Reset();
        public byte[] Digest();
        public void Digest(Span<byte> hash);
        public void Update(byte[] input);
    }
}

