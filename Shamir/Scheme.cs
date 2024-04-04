using Wheel.Crypto.Symmetric.AES;
using Wheel.Hashing.HMAC.SHA2;
using Wheel.Hashing.Derivation;
using Wheel.Crypto.Shamir.Internal;
using System.Runtime.InteropServices;

namespace Wheel.Crypto.Shamir;

/// <summary>
/// Shamir's secret sharing context
/// </summary>
public class Sharing
{

    /// <summary>
    /// Total number of participants
    /// </summary>
    public int Participants { get; private set; }

    /// <summary>
    /// Recovery quorum
    /// </summary>
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

    #region Encrypted shares splitting and merging
    /// <summary>
    /// Create encrypted shares
    /// </summary>
    /// <param name="secret"></param>
    /// <param name="seed"></param>
    /// <returns></returns>
    public Share[] CreateEncryptedShares(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> seed)
    {
        // Buffer for IV + encrypted secret
        Span<byte> expanded = stackalloc byte[AESBlock.TypeByteSz + EncryptSecret(null, secret, null, null)];
        SplitCombined(out Span<byte> aesIV, out Span<byte> cipherText, expanded);

        // IV = HMAC(seed, secret)
        HMAC_SHA512 hasher = new();
        hasher.Init(seed);
        hasher.Update(secret);
        hasher.Digest(aesIV);
        hasher.Dispose();

        // Key = PBKDF2(seed, IV)
        Span<byte> aesKey = stackalloc byte[32];
        PBKDF2.Derive<HMAC_SHA512>(aesKey, seed, aesIV, 4096);

        // IV + Encrypted secret
        EncryptSecret(cipherText, secret, aesKey, aesIV);
        aesKey.Clear();

        // Split the IV + encrypted secret pair
        return CreateShares(expanded);
    }

    /// <summary>
    /// Merge and decrypt the password protected shares
    /// </summary>
    /// <param name="result"></param>
    /// <param name="shares"></param>
    /// <param name="seed"></param>
    /// <returns></returns>
    /// <exception cref="InvalidDataException">When the resulting plaintext hash doesn't math the expected value</exception>
    public int MergeEncrypted(Span<byte> result, Share[] shares, ReadOnlySpan<byte> seed)
    {
        // IV + encrypted secret
        Span<byte> expanded = stackalloc byte[MergeShares(null, shares)];

        // First 16 bytes of secret are the initializing vector
        //  which is not returned to user
        int secretSz = expanded.Length - AESBlock.TypeByteSz;

        if (secretSz > result.Length)
        {
            // Prepare for the worst outcome:
            //  all cipherText blocks are filled
            return secretSz;
        }

        MergeShares(expanded, shares);
        SplitCombined(out Span<byte> aesIV, out Span<byte> cipherText, expanded);

        // Take a slice of just enough bytes to write the decrypted secret
        Span<byte> plainText = result.Slice(0, secretSz);

        // Key = PBKDF2(seed, IV)
        Span<byte> aesKey = stackalloc byte[32];
        PBKDF2.Derive<HMAC_SHA512>(aesKey, seed, aesIV, 4096);

        // Decrypt and truncate padding bytes
        secretSz = DecryptSecret(plainText, cipherText, aesKey, aesIV);
        plainText = plainText.Slice(0, secretSz);
        aesKey.Clear();

        // Calculate HMAC and compare it with IV for the intergity check
        // IV = HMAC(seed, secret)
        Span<byte> aesIVCheck = stackalloc byte[AESBlock.TypeByteSz];
        HMAC_SHA512 hasher = new();
        hasher.Init(seed);
        hasher.Update(plainText);
        hasher.Digest(aesIVCheck);
        hasher.Dispose();

        if (!aesIV.SequenceEqual(aesIVCheck))
        {
            plainText.Clear();
            throw new InvalidDataException("Reconstructed secret hash mismatch (incorrect password? corrupt shares?)");
        }

        return secretSz;
    }
    #endregion

    /// <summary>
    /// Split combined secret memory into constituent parts
    /// </summary>
    /// <param name="aesIV"></param>
    /// <param name="cipherText"></param>
    /// <param name="expanded"></param>
    private static void SplitCombined(out Span<byte> aesIV, out Span<byte> cipherText, Span<byte> expanded)
    {
        aesIV = expanded.Slice(0, AESBlock.TypeByteSz);
        cipherText = expanded.Slice(aesIV.Length);
    }

    #region Raw secret splitting and merging implementation
    /// <summary>
    /// Construct new shares from a given secret
    /// </summary>
    /// <param name="secret">Byte array or Span</param>
    /// <returns>Array of share objects</returns>
    public Share[] CreateShares(ReadOnlySpan<byte> secret)
    {
        // "Shamir" in ASCII
        Span<byte> shamirTag = stackalloc byte[] { 0x53, 0x68, 0x61, 0x6d, 0x69, 0x72 };

        // With threshold = K shares we will need up to K * SECRET_LENGTH bytes of the random data
        Span<ShareByte> garbage = stackalloc ShareByte[secret.Length * Threshold];

        // Use PBKDF2 to generate some deterministic garbage from the secret
        // The random data is required to be uniform and unpredictable, so the PBKDF2 is just what we need here
        PBKDF2.Derive<HMAC_SHA384>(MemoryMarshal.Cast<ShareByte, byte>(garbage), shamirTag, secret, 128);

        Share[] generated = new Share[Participants];

        for (int i = 0; i < Participants; ++i)
        {
            generated[i] = new(secret.Length);
        }

        Span<ShareByte> coefficients = stackalloc ShareByte[Threshold];

        for (int secretIdx = 0; secretIdx < secret.Length; ++secretIdx)
        {
            coefficients[0] = secret[secretIdx];
            for (int i = 1; i < Threshold; ++i)
            {
                coefficients[i] = garbage[secretIdx * i];
            }

            for (int shareIdx = 0; shareIdx < Participants; ++shareIdx)
            {
                ShareByte x = (byte)(shareIdx + 1);
                ShareByte y = 0;

                for (int thresholdIdx = 0; thresholdIdx < Threshold; ++thresholdIdx)
                {
                    y ^= coefficients[thresholdIdx] * GroupFieldMath.Pow(x, thresholdIdx);
                }

                generated[shareIdx][secretIdx] = new(x, y);
            }
        }

        coefficients.Clear();

        return generated;
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

        int secretSz = shares[0].Length;

        if (secretSz > secret.Length)
        {
            return secretSz;
        }

        foreach(var share in shares)
        {
            if (share.Length != secretSz)
            {
                // All shares must have the identical size
                throw new InvalidDataException("Inconsistent share set detected");
            }
        }

        Span<SharePoint> merged = stackalloc SharePoint[Threshold];
        for (int secretIdx = 0; secretIdx < secretSz; ++secretIdx)
        {
            for (int shareIdx = 0; shareIdx < Threshold; ++shareIdx)
            {
                merged[shareIdx] = shares[shareIdx][secretIdx];
            }
            secret[secretIdx] = GroupFieldMath.Interpolation(merged);
        }

        merged.Clear();

        return secretSz;
    }
    #endregion

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
        Span<AESBlock> blocks = MemoryMarshal.Cast<byte, AESBlock>(result.Slice(0, reqSz));
        secret.CopyTo(result);
        AESBlock.FillPaddingBlock(ref blocks[blocks.Length - 1], secret.Length);
        ctx.ProcessBlocks(blocks);
        ctx.Dispose();
        return reqSz;
    }

    /// <summary>
    /// Decrypt secret with AES-256-CTR
    /// </summary>
    /// <param name="result">Decrypted secret data</param>
    /// <param name="cipherText">Secret to decrypt</param>
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

        Span<AESBlock> blocks = MemoryMarshal.Cast<byte, AESBlock>(result.Slice(0, cipherText.Length));
        cipherText.CopyTo(result);
        ctx.ProcessBlocks(blocks);
        ctx.Dispose();
        // Return actual data length (without padding)
        return reqSz - AESBlock.GetPaddingLen(blocks[blocks.Length - 1]);
    }
    #endregion
}


