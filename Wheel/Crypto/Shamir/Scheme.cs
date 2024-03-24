using Wheel.Crypto.Hashing.HMAC.SHA2;
using Wheel.Crypto.Hashing.Derivation;
using Wheel.Crypto.Shamir.Internal;

namespace Wheel.Crypto.Shamir
{
    public class Scheme
    {
        private int n, k;

        public Scheme(int members, int threshold)
        {
            n = members;
            k = threshold;
        }

        public Share[] createShares(Span<byte> secret)
        {   
            // With threshold = K shares we will need N * SECRET_LENGTH bytes of the random data
            Span<byte> randomBytes = stackalloc byte[secret.Length * k];

            // We presume that PBKDF2 output is equivalent to the uniform random distribution
            PBKDF2.Derive<HMAC_SHA512>(randomBytes, secret, secret, 1024);

            Share[] allShares = new Share[n];
            for (int i = 0; i < n; ++i)
            {
                allShares[i] = new Share(secret.Length);
            }

            for (int secretIdx = 0; secretIdx < secret.Length; ++secretIdx)
            {
                ShareByte[] coefficients = new ShareByte[k];
                coefficients[0] = secret[secretIdx];
                for (int i = 1; i < k; i++)
                {
                    coefficients[i] = randomBytes[secretIdx * i];
                }

                SharePoint temp = new();
                ShareByte x, y;

                for (int i = 0; i < n; i++)
                {
                    x = (byte)(i + 1);
                    y = 0;

                    for (int j = 0; j < k; j++)
                    {
                        y ^= coefficients[j] * GroupFieldMath.Pow(x, j);
                    }

                    temp.X = x;
                    temp.Y = y;

                    allShares[i][secretIdx] = temp;
                }
            }

            return allShares;
        }

        public int getSecret(Span<byte> secret, Share[] Kshares)
        {
            if (Kshares.Length < k)
            {
                throw new InvalidOperationException("You need at least " + k + " shares to reconstruct a secret");
            }

            int secretSize = Kshares[0].Length;
            if (secretSize > secret.Length)
            {
                return secretSize;
            }

            Share curr_shares = new Share(k);
            for (int di = 0; di < secretSize; di++)
            {
                for (int i = 0; i < k; i++)
                {
                    curr_shares[i] = Kshares[i][di];
                }
                secret[di] = GroupFieldMath.Interpolation(curr_shares);
            }
            return secretSize;
        }
    }
}


