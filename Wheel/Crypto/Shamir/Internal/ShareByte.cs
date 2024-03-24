namespace Wheel.Crypto.Shamir.Internal
{
    internal struct ShareByte
    {
        private byte value;

        public ShareByte()
        {
            value = 0;
        }

        public ShareByte(byte value)
        {
            this.value = value;
        }

        public static implicit operator ShareByte(byte n)
        {
            return new ShareByte(n);
        }

        public static implicit operator ShareByte(int n)
        {
            if (byte.MinValue > n || byte.MaxValue < n)
            {
                throw new InvalidDataException("Invalid assignment");
            }
            return new ShareByte((byte)n);
        }

        public static implicit operator byte(ShareByte c)
        {
            return c.value;
        }

        public static ShareByte operator ^(ShareByte a, ShareByte b)
        {
            return (byte)(a.value ^ b.value);
        }

        public static ShareByte operator *(ShareByte a, ShareByte b)
        {
            if (a.value == 0 || b.value == 0)
            {
                return 0;
            }
            int t = GroupFieldMath.logs[a.value].value + GroupFieldMath.logs[b.value].value;
            if (t > 255)
            {
                t -= 255;
            }
            return GroupFieldMath.exponents[t];
        }

        public static bool operator !=(ShareByte a, ShareByte b)
        {
            return a.value != b.value;
        }

        public static bool operator ==(ShareByte a, ShareByte b)
        {
            return a.value == b.value;
        }

        public static ShareByte operator ~(ShareByte a)
        {
            byte y = GroupFieldMath.logs[a.value].value, x;
            x = (byte)(255 - y);
            return GroupFieldMath.exponents[x];
        }

        public static ShareByte operator /(ShareByte a, ShareByte b)
        {
            byte c = ~b;
            return a * c;
        }

        public override readonly string ToString()
        {
            return value.ToString("X2");
        }

        public override readonly bool Equals(object? obj)
        {
            return obj is ShareByte coordinate &&
                   value == coordinate.value;
        }

        public override readonly int GetHashCode()
        {
            return HashCode.Combine(value);
        }
    }
}

