using Wheel.Crypto.Hashing.SHA3.Internal;

namespace Wheel.Crypto.Hashing.SHA3
{
    public class SHA3_256 : Keccak
    {
        public SHA3_256() : base(256, false)
        {
        }

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
    }

    public class SHA3_384 : Keccak
    {
        public SHA3_384() : base(384, false)
        {
        }

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
    }

    public class SHA3_512 : Keccak
    {
        public SHA3_512() : base(512, false)
        {
        }

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
    }

    public class Keccak_256 : Keccak
    {
        public Keccak_256() : base(256, true)
        {
        }

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
    }

    public class Keccak_384 : Keccak
    {
        public Keccak_384() : base(384, true)
        {
        }

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
    }

    public class Keccak_512 : Keccak
    {
        public Keccak_512() : base(512, true)
        {
        }

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
    }
}
