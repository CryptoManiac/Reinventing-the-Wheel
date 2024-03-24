using Wheel.Crypto.Hashing.HMAC.SHA2;
using Wheel.Crypto.Hashing.Derivation;
using Wheel.Crypto.Shamir.Internal;

namespace Wheel.Crypto.Shamir
{
    public class Sharing
    {
        public int Participants { get; private set; }
        public int Threshold { get; private set; }

        /// <summary>
        /// Construct the new secret sharing scheme object
        /// </summary>
        /// <param name="participants">Total number of participants</param>
        /// <param name="threshold">Number of participants required to reconstruct the secret</param>
        /// <exception cref="ArgumentOutOfRangeException">When the number of participants is too big or the threshold is incorrect</exception>
        public Sharing(int participants, int threshold)
        {
            if (participants > 254)
            {
                throw new ArgumentOutOfRangeException(nameof(participants), participants, "There can be no more than 254 participants");
            }

            if (threshold > participants)
            {
                throw new ArgumentOutOfRangeException(nameof(threshold), threshold, "Having threshold greater than number of participants doesn't make any sense");
            }

            Participants = participants;
            Threshold = threshold;
        }

        /// <summary>
        /// Construct new shares from a given secret
        /// </summary>
        /// <param name="secret">Byte array or Span</param>
        /// <returns>Array of share objects</returns>
        public Share[] CreateShares(ReadOnlySpan<byte> secret)
        {
            // With threshold = K shares we will need up to K * SECRET_LENGTH bytes of the random data
            Span<byte> randomBytes = stackalloc byte[secret.Length * Threshold];

            // We presume that PBKDF2 output is equivalent to the uniform random distribution
            PBKDF2.Derive<HMAC_SHA512>(randomBytes, secret, secret, 4096);

            Share[] all = new Share[Participants];

            for (int i = 0; i < Participants; ++i)
            {
                all[i] = new Share(secret.Length);
            }

            for (int secretIdx = 0; secretIdx < secret.Length; ++secretIdx)
            {
                ShareByte[] coefficients = new ShareByte[Threshold];
                coefficients[0] = secret[secretIdx];
                for (int i = 1; i < Threshold; i++)
                {
                    coefficients[i] = randomBytes[secretIdx * i];
                }

                for (int i = 0; i < Participants; ++i)
                {
                    ShareByte x = i + 1, y = 0;
                    for (int j = 0; j < Threshold; ++j)
                    {
                        y ^= coefficients[j] * GroupFieldMath.Pow(x, j);
                    }
                    all[i][secretIdx] = new SharePoint(x, y);
                }
            }

            return all;
        }

        /// <summary>
        /// Merge shares to reconstruct a secret
        /// </summary>
        /// <param name="secret">Reconstructed secret</param>
        /// <param name="shares">Array of share objects to process</param>
        /// <returns>Required result buffer length</returns>
        /// <exception cref="InvalidOperationException">If there are not enough shares</exception>
        public int MergeShares(Span<byte> secret, Share[] shares)
        {
            if (shares.Length < Threshold)
            {
                throw new InvalidOperationException("At least " + Threshold + " shares are needed");
            }

            int secretSize = shares[0].Length;
            if (secretSize > secret.Length)
            {
                return secretSize;
            }

            Share mergedPoints = new(Threshold);
            for (int di = 0; di < secretSize; ++di)
            {
                for (int i = 0; i < Threshold; i++)
                {
                    mergedPoints[i] = shares[i][di];
                }
                secret[di] = GroupFieldMath.Interpolation(mergedPoints);
            }
            return secretSize;
        }
    }
}


