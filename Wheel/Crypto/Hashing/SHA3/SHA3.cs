using Wheel.Crypto.Hashing.SHA3.Internal;

namespace Wheel.Crypto.Hashing.SHA3
{
    public struct SHA3_256 : IHasher
    {
        private IHasher ctx = new Keccak(256, false);

        public SHA3_256()
        {
        }

        #region Pass-through methods
        public int HashSz => ctx.HashSz;
        public byte[] Digest() => ctx.Digest();
        public void Digest(Span<byte> hash) => ctx.Digest(hash);
        public void Reset() => ctx.Reset();
        public void Update(byte[] input) => ctx.Update(input);
        #endregion

        #region Static methods
        public static byte[] Hash(byte[] input)
        {
            SHA3_256 hasher = new();
            hasher.Update(input);
            return hasher.Digest();
        }

        public static void Hash(Span<byte> digest, byte[] input)
        {
            SHA3_256 hasher = new();
            hasher.Update(input);
            hasher.Digest(digest);
        }
        #endregion
    }

    public struct SHA3_384 : IHasher
    {
        private IHasher ctx = new Keccak(384, false);

        public SHA3_384()
        {
        }

        #region Pass-through methods
        public int HashSz => ctx.HashSz;
        public byte[] Digest() => ctx.Digest();
        public void Digest(Span<byte> hash) => ctx.Digest(hash);
        public void Reset() => ctx.Reset();
        public void Update(byte[] input) => ctx.Update(input);
        #endregion

        #region Static methods
        public static byte[] Hash(byte[] input)
        {
            SHA3_384 hasher = new();
            hasher.Update(input);
            return hasher.Digest();
        }

        public static void Hash(Span<byte> digest, byte[] input)
        {
            SHA3_384 hasher = new();
            hasher.Update(input);
            hasher.Digest(digest);
        }
        #endregion
    }

    public struct SHA3_512 : IHasher
    {
        private IHasher ctx = new Keccak(512, false);

        public SHA3_512()
        {
        }

        #region Pass-through methods
        public int HashSz => ctx.HashSz;
        public byte[] Digest() => ctx.Digest();
        public void Digest(Span<byte> hash) => ctx.Digest(hash);
        public void Reset() => ctx.Reset();
        public void Update(byte[] input) => ctx.Update(input);
        #endregion

        #region Static methods
        public static byte[] Hash(byte[] input)
        {
            SHA3_512 hasher = new();
            hasher.Update(input);
            return hasher.Digest();
        }

        public static void Hash(Span<byte> digest, byte[] input)
        {
            SHA3_512 hasher = new();
            hasher.Update(input);
            hasher.Digest(digest);
        }
        #endregion
    }

    public struct Keccak_256 : IHasher
    {
        private IHasher ctx = new Keccak(256, true);

        public Keccak_256()
        {
        }

        #region Pass-through methods
        public int HashSz => ctx.HashSz;
        public byte[] Digest() => ctx.Digest();
        public void Digest(Span<byte> hash) => ctx.Digest(hash);
        public void Reset() => ctx.Reset();
        public void Update(byte[] input) => ctx.Update(input);
        #endregion

        #region Static methods
        public static byte[] Hash(byte[] input)
        {
            Keccak_256 hasher = new();
            hasher.Update(input);
            return hasher.Digest();
        }

        public static void Hash(Span<byte> digest, byte[] input)
        {
            Keccak_256 hasher = new();
            hasher.Update(input);
            hasher.Digest(digest);
        }
        #endregion
    }

    public struct Keccak_384 : IHasher
    {
        private IHasher ctx = new Keccak(384, true);

        public Keccak_384()
        {
        }

        #region Pass-through methods
        public int HashSz => ctx.HashSz;
        public byte[] Digest() => ctx.Digest();
        public void Digest(Span<byte> hash) => ctx.Digest(hash);
        public void Reset() => ctx.Reset();
        public void Update(byte[] input) => ctx.Update(input);
        #endregion

        #region Static methods
        public static byte[] Hash(byte[] input)
        {
            Keccak_384 hasher = new();
            hasher.Update(input);
            return hasher.Digest();
        }

        public static void Hash(Span<byte> digest, byte[] input)
        {
            Keccak_384 hasher = new();
            hasher.Update(input);
            hasher.Digest(digest);
        }
        #endregion
    }

    public struct Keccak_512 : IHasher
    {
        private IHasher ctx = new Keccak(512, true);

        public Keccak_512()
        {
        }

        #region Pass-through methods
        public int HashSz => ctx.HashSz;
        public byte[] Digest() => ctx.Digest();
        public void Digest(Span<byte> hash) => ctx.Digest(hash);
        public void Reset() => ctx.Reset();
        public void Update(byte[] input) => ctx.Update(input);
        #endregion

        #region Static methods
        public static byte[] Hash(byte[] input)
        {
            Keccak_512 hasher = new();
            hasher.Update(input);
            return hasher.Digest();
        }

        public static void Hash(Span<byte> digest, byte[] input)
        {
            Keccak_512 hasher = new();
            hasher.Update(input);
            hasher.Digest(digest);
        }
        #endregion
    }
}
