using System.Text;
using Hashing.Hashing.HMAC;
using Wheel.Crypto.Elliptic.EdDSA;
using Wheel.Crypto.Elliptic.EllipticCommon;
using Wheel.Hashing.HMAC;
using Wheel.Hashing.SHA.SHA256;
using Wheel.Hashing.SHA.SHA512;

namespace Wheel.Test.EdDSA;

/// <summary>
/// Runs a set of predetermined actions such as key derivation, message signing and signature verification,
///  validating the results
/// </summary>
public class EdDSATest
{
    readonly EdCurve curve;
    readonly EdPrivateKey secretKey;
    readonly EdPublicKey publicKey;

    /// <summary>
    /// Calculate SHA256 of the ASCII string
    /// </summary>
    /// <param name="message"></param>
    private static byte[] GetSigningHash(string message)
    {
        // Empty for tests
        byte[] message_hash = new byte[32];
        SHA256.Hash(message_hash, Encoding.ASCII.GetBytes(message));
        return message_hash;
    }

    /// <summary>
    /// Create test for given curve instance and the "standard" ED25519 seed
    /// </summary>
    /// <param name="curve">ECCurve instance</param>
    /// <param name="secret_seed">Seed to derive the secret from</param>
    public EdDSATest(EdCurve curve, string secret_seed)
    {
        this.curve = curve;

        #region Derive secret and public keys
        curve.ExpandSeed(
            out secretKey,
            Convert.FromHexString(secret_seed)
        );

        if (!secretKey.ComputePublicKey(out publicKey))
        {
            throw new SystemException("Computation of the public key has failed");
        }
        #endregion
    }

    /// <summary>
    /// Create test for given curve instance and secret parameters
    /// </summary>
    /// <param name="curve">ECCurve instance</param>
    /// <param name="secret_seed">Seed to derive the secret from</param>
    /// <param name="personalization">Personalization for seed</param>
    /// <param name="secret_key_number">Secret sequence</param>
    public EdDSATest(EdCurve curve, string secret_seed, string personalization, int secret_key_number)
    {
        this.curve = curve;

        #region Derive secret and public keys
        curve.GenerateDeterministicSecret<HMAC<SHA512>>(
            out secretKey,
            Encoding.ASCII.GetBytes(secret_seed),
            Encoding.ASCII.GetBytes(personalization),
            secret_key_number
        );

        if (!secretKey.ComputePublicKey(out publicKey))
        {
            throw new SystemException("Computation of the public key has failed");
        }
        #endregion
    }

    /// <summary>
    /// Compare calculated keys with the provided examples and throw on mismatch
    /// </summary>
    /// <param name="expectedSecret"></param>
    /// <param name="expectedCompressed"></param>
    /// <param name="expectedUncompressed"></param>
    public void ExpectedKeys(string tag, string expectedSecret, string expectedPublicKey)
    {
        #region Key calculation results
        string secret;
        string public_key;
        double entropy;
        #endregion

        #region Serialization of keys
        {
            byte[] _secret_key = new byte[curve.PrivateKeySize];
            byte[] _public_key = new byte[curve.CompressedPublicKeySize];

            if (!secretKey.Serialize(_secret_key))
            {
                throw new SystemException("Serialization of the secret key has failed");
            }

            if (!publicKey.Serialize(_public_key))
            {
                throw new SystemException("Serialization of the public key has failed");
            }

            secret = Convert.ToHexString(_secret_key);
            public_key = Convert.ToHexString(_public_key);
            entropy = Entropy.Estimate(_secret_key);
        }
        #endregion

        Console.WriteLine("{0} private key: {1}", tag, secret);
        Console.WriteLine("{0} private key entropy: {1}", tag, entropy);
        Console.WriteLine("{0} public key: {1}", tag, public_key);

        #region Results comparison
        if (expectedSecret != secret)
        {
            throw new SystemException("Private key mismatch");
        }

        if (expectedPublicKey != public_key)
        {
            throw new SystemException("Uncompressed public key mismatch");
        }
        #endregion
    }

    /// <summary>
    /// Deterministically sign message using the given HMAC implementation
    ///  and show error on mismatch with the expected result
    /// </summary>
    /// <typeparam name="HMAC_IMPL">HMAC implementation</typeparam>
    /// <param name="message">Message to sign</param>
    /// <param name="expected">Expected signature</param>
    public void ExpectedDERSignature<HMAC_IMPL>(string tag, string message, string expected) where HMAC_IMPL : unmanaged, IMac
    {
        byte[] signingHash = GetSigningHash(message);

        #region Sign
        if (!secretKey.SignDeterministic<HMAC_IMPL>(out DERSignature derSig, signingHash))
        {
            throw new SystemException("Signing failed");
        }
        #endregion

        #region Encode signature
        string signature;
        {
            byte[] _signature = new byte[curve.DERSignatureSize];
            int encodedSz = derSig.Encode(_signature);
            if (encodedSz > _signature.Length)
            {
                throw new Exception("Signature buffer is too short");
            }
            // Truncate the excessive bytes
            _signature = _signature.Take(encodedSz).ToArray();
            signature = Convert.ToHexString(_signature);
        }
        #endregion

        var oldColour = Console.ForegroundColor;
        bool isOk = expected == signature;

        Console.ForegroundColor = isOk ? ConsoleColor.Green : ConsoleColor.Red;
        Console.WriteLine("{0}: {1} {2}", tag, signature, isOk ? "OK" : expected);
        Console.ForegroundColor = oldColour;
    }

    /// <summary>
    /// Deterministically sign message using the given HMAC implementation
    ///  and show error on mismatch with the expected result
    /// </summary>
    /// <typeparam name="HMAC_IMPL">HMAC implementation</typeparam>
    /// <param name="message">Message to sign</param>
    /// <param name="expected">Expected signature</param>
    public void ExpectedCompactSignature<HMAC_IMPL>(string tag, string message, string expected) where HMAC_IMPL : unmanaged, IMac
    {
        byte[] signingHash = GetSigningHash(message);

        #region Sign
        if (!secretKey.SignDeterministic<HMAC_IMPL>(out CompactSignature derSig, signingHash))
        {
            throw new SystemException("Signing failed");
        }
        #endregion

        #region Encode signature
        string signature;
        {
            byte[] _signature = new byte[curve.DERSignatureSize];
            int encodedSz = derSig.Encode(_signature);
            if (encodedSz > _signature.Length)
            {
                throw new Exception("Signature buffer is too short");
            }
            // Truncate the excessive bytes
            _signature = _signature.Take(encodedSz).ToArray();
            signature = Convert.ToHexString(_signature);
        }
        #endregion

        var oldColour = Console.ForegroundColor;
        bool isOk = expected == signature;

        Console.ForegroundColor = isOk ? ConsoleColor.Green : ConsoleColor.Red;
        Console.WriteLine("{0}: {1} {2}", tag, signature, isOk ? "OK" : expected);
        Console.ForegroundColor = oldColour;
    }

    /// <summary>
    /// Verify signature for given message and throw on the failure
    /// </summary>
    /// <param name="toCheck">Signature to decode and check</param>
    /// <param name="message">Message to check the signature for</param>
    /// <exception cref="SystemException"></exception>
    public void VerifyCompactSignature(string toCheck, string message)
    {
        byte[] signingHash = GetSigningHash(message);
        byte[] signature = Convert.FromHexString(toCheck);
        Console.Write(toCheck);

        if (!publicKey.VerifySignature(new CompactSignature(curve, signature), signingHash))
        {
            throw new SystemException("Signature check failed");
        }

        // Success
        Console.WriteLine(" OK");
    }

    /// <summary>
    /// Verify signature for given message and throw on the failure
    /// </summary>
    /// <param name="toCheck">Signature to decode and check</param>
    /// <param name="message">Message to check the signature for</param>
    /// <exception cref="SystemException"></exception>
    public void VerifyDERSignature(string toCheck, string message)
    {
        byte[] signingHash = GetSigningHash(message);
        byte[] signature = Convert.FromHexString(toCheck);
        Console.Write(toCheck);

        if (!publicKey.VerifySignature(new DERSignature(curve, signature), signingHash))
        {
            throw new SystemException("Signature check failed");
        }

        // Success
        Console.WriteLine(" OK");
    }

    /// <summary>
    /// Sign the message nondeterministically and check
    /// the result, throwing on the failure to do so
    /// </summary>
    /// <param name="message">Message to sign</param>
    public void CheckNonDeterministic(string message)
    {
        byte[] signingHash = GetSigningHash(message);

        #region Sign
        // Try signing until the signing will succeed
        DERSignature derSig;
        while (!secretKey.Sign(out derSig, signingHash)) ;
        #endregion

        #region Encode
        byte[] signature = new byte[curve.DERSignatureSize];
        {
            int encodedSz = derSig.Encode(signature);
            if (encodedSz > signature.Length)
            {
                throw new Exception("Signature buffer is too short");
            }
            // Truncate unused space
            signature = signature.Take(encodedSz).ToArray();
        }
        #endregion

        #region Decode and check
        DERSignature derDecoded = new(curve, signature);
        if (!publicKey.VerifySignature(derDecoded, signingHash))
        {
            throw new SystemException("Failed to check the generated signature");
        }
        #endregion

        #region Encode and compare the results
        byte[] signature2 = new byte[curve.DERSignatureSize];
        {
            int encodedSz = derSig.Encode(signature2);
            if (encodedSz > signature2.Length)
            {
                throw new Exception("Signature buffer is too short");
            }
            // Truncate unused space
            signature2 = signature2.Take(encodedSz).ToArray();
        }

        if (!signature.SequenceEqual(signature2))
        {
            Console.WriteLine("Signature 1: {0}", Convert.ToHexString(signature));
            Console.WriteLine("Signature 2: {0}", Convert.ToHexString(signature2));

            throw new SystemException("Encoded and decoded signature mismatch");
        }
        #endregion

        Console.WriteLine("{0} OK", Convert.ToHexString(signature));
    }
}
