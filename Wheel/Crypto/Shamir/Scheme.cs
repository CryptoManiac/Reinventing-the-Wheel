using Wheel.Crypto.AES;
using Wheel.Crypto.Hashing.HMAC.SHA2;
using Wheel.Crypto.Hashing.Derivation;
using Wheel.Crypto.Shamir.Internal;
using System.Runtime.InteropServices;

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
        /// Split combined secret memory into constituent parts
        /// </summary>
        /// <param name="aesKey"></param>
        /// <param name="aesIV"></param>
        /// <param name="cipherText"></param>
        /// <param name="expandedSecret"></param>
        private static void SplitCombined(out Span<byte> aesKey, out Span<byte> aesIV, out Span<byte> cipherText, Span<byte> expandedSecret)
        {
            aesKey = expandedSecret.Slice(0, 32);
            aesIV = expandedSecret.Slice(32, AESBlock.TypeByteSz);
            cipherText = expandedSecret.Slice(aesKey.Length + aesIV.Length);
        }

        /// <summary>
        /// Construct new shares from a given secret
        /// </summary>
        /// <param name="secret">Byte array or Span</param>
        /// <returns>Array of share objects</returns>
        public Share[] CreateShares(ReadOnlySpan<byte> secret)
        {
            // Allocate memory for the expanded secret (AES encryption key + AES IV + encrypted secret blocks)
            Span<byte> expandedSecret = stackalloc byte[32 + AESBlock.TypeByteSz + EncryptSecret(null, secret, null, null)];
            SplitCombined(out Span<byte> aesKey, out Span<byte> aesIV, out Span<byte> cipherText, expandedSecret);

            // Derive encryption keys
            DeriveKeys(aesKey, aesIV, secret);

            // Encrypt secret
            EncryptSecret(cipherText, secret, aesKey, aesIV);

            // With threshold = K shares we will need up to K * SECRET_LENGTH bytes of the random data
            Span<byte> randomBytes = stackalloc byte[expandedSecret.Length * Threshold];

            // We presume that PBKDF2 output is equivalent to the uniform random distribution
            // 128 iterations are more than enough here
            PBKDF2.Derive<HMAC_SHA512>(randomBytes, aesIV, aesKey, 128);

            Share[] all = new Share[Participants];

            for (int i = 0; i < Participants; ++i)
            {
                all[i] = new Share(expandedSecret.Length);
            }

            for (int secretIdx = 0; secretIdx < expandedSecret.Length; ++secretIdx)
            {
                ShareByte[] coefficients = new ShareByte[Threshold];
                coefficients[0] = expandedSecret[secretIdx];
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

            int extendedSecretSize = shares[0].Length;
            int cipherTextSize = extendedSecretSize - 32 - AESBlock.TypeByteSz;

            if (cipherTextSize > secret.Length)
            {
                return cipherTextSize;
            }

            // Allocate memory for the expanded secret (AES encryption key + AES IV + encrypted secret blocks)
            Span<byte> expandedSecret = stackalloc byte[extendedSecretSize];

            Share mergedPoints = new(Threshold);
            for (int di = 0; di < extendedSecretSize; ++di)
            {
                for (int i = 0; i < Threshold; i++)
                {
                    mergedPoints[i] = shares[i][di];
                }
                expandedSecret[di] = GroupFieldMath.Interpolation(mergedPoints);
            }

            SplitCombined(out Span<byte> aesKey, out Span<byte> aesIV, out Span<byte> cipherText, expandedSecret);

            // Decrypt and return the number of written bytes
            int secretSz = DecryptSecret(secret, cipherText, aesKey, aesIV);

            // Not needed anymore
            expandedSecret.Clear();

            return secretSz;
        }

        #region AES-256-CTR
        /// <summary>
        /// Expand and encrypt secret with AES-256-CTR
        /// </summary>
        /// <param name="result">Encrypted secret data</param>
        /// <param name="secret">Secret to encrypt</param>
        /// <param name="key">Encryption key (derived by PBKDF2)</param>
        /// <param name="iv">Initial vector (derived by HMAC)</param>
        /// <returns>Number of bytes (required for / written to) result</returns>
        private static int EncryptSecret(Span<byte> result, ReadOnlySpan<byte> secret, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
        {
            int reqSz = AESBlock.GetBlocksWithPadding(secret.Length) * AESBlock.TypeByteSz;
            if (reqSz > result.Length)
            {
                // Must provide enough space to accomodate
                // AES-CTR-256(secret + padding) output
                return reqSz;
            }

            AESContext ctx = new(key, iv);
            Span<AESBlock> blocks = MemoryMarshal.Cast<byte, AESBlock>(result);
            secret.CopyTo(result);
            AESBlock.FillPaddingBlock(ref blocks[blocks.Length - 1], secret.Length);
            ctx.ProcessBlocks(blocks);
            return reqSz;
        }

        /// <summary>
        /// Decrypt secret with AES-256-CTR
        /// </summary>
        /// <param name="result">Decrypted secret data</param>
        /// <param name="secret">Secret to decrypt</param>
        /// <param name="key">Encryption key (provided by merged shares)</param>
        /// <param name="iv">Initial vector (provided by merged shares)</param>
        /// <returns>Number of bytes (required for / written to) result</returns>
        private static int DecryptSecret(Span<byte> result, ReadOnlySpan<byte> cipherText, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
        {
            int reqSz = cipherText.Length;
            if (reqSz > result.Length)
            {
                // Must provide enough space to accomodate
                // AES-CTR-256(secret + padding) output
                return reqSz;
            }

            AESContext ctx = new(key, iv);
            Span<AESBlock> blocks = MemoryMarshal.Cast<byte, AESBlock>(result);
            cipherText.CopyTo(result);
            ctx.ProcessBlocks(blocks);

            // Return actual data length (without padding)
            return reqSz - AESBlock.GetPaddingLen(blocks[blocks.Length - 1]);
        }
        #endregion

        #region RNG
        private static void DeriveKeys(Span<byte> aesKey, Span<byte> aesIV, ReadOnlySpan<byte> secret)
        {
            // "Shamir" in ASCII
            Span<byte> shamirTag = stackalloc byte[] { 0x53, 0x68, 0x61, 0x6d, 0x69, 0x72 };

            // First of all, derive AES encryption key and IV
            PBKDF2.Derive<HMAC_SHA512>(aesKey, shamirTag, secret, 1024);
            PBKDF2.Derive<HMAC_SHA384>(aesIV, shamirTag, secret, 1024);
        }
        #endregion
    }
}


