using System;
namespace Wheel.Crypto.Hashing.HMAC
{
    /// <summary>
    /// HMAC interface. Yes, I know that its the name is very funny.
    /// </summary>
	public interface IMac
	{
        public int HashSz { get; }
        public void Reset(in ReadOnlySpan<byte> key);
        public void Reinit();
        public void Digest(Span<byte> hash);
        public void Update(ReadOnlySpan<byte> input);
    }
}

