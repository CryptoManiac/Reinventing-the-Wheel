using System.Text;
using Wheel.Crypto.Elliptic.ECDSA;
using Wheel.Crypto.Elliptic.EllipticCommon;
using Wheel.Hashing.HMAC;
using Wheel.Hashing.HMAC.SHA2;
using Wheel.Hashing.SHA.SHA256;

string message = "aaa";

// Should give these results:
// SECP256R1 private key: DB395A4721E3698864A50BBDBC5D12EFDE180237713AC2A692E4349FDBBC09E0
// SECP256R1 public key: 048D61DED99E550773BB1E5A1E4E434D86ABD6BA218EF75F299A156956AEFFC626C33D8ED80692B9C209219BB95E8BB8A4116A35B04860415DAA79D8B4ED498584
// SECP256R1 compressed public key: 028D61DED99E550773BB1E5A1E4E434D86ABD6BA218EF75F299A156956AEFFC626
string secret_seed = "The quick brown fox jumps over the lazy dog";
string personalization = "For signing tests";
int secret_key_number = 0;

// Must be valid, check here: http://kjur.github.io/jsrsasign/sample/sample-ecdsa.html (select SECP256R1 curve and SHA256withECDSA algorithm)
SortedDictionary<string, string> vectors = new()
{
    {  "HMAC_SHA224", "30440220450F93A9AFA20931F222D52FD597F0A9466662DBEA5B9665AC9AA8D07EAA5B8A02206B7E4B2ED89CF6638C559E30F73E9EC93E86920A661735A8566D7C1CC7EE6479"},
    {  "HMAC_SHA256", "30440220699A5B279D6B6B45693477EA34F37D1C01D7B87018A6372E9B5C98E9FDE3676B0220197A0714999FB553F5F9CF98F54138445E1D6EB7ABBA4DACE1C3D2B2626C20FD"},
    {  "HMAC_SHA512", "3045022100A5AC79737DDF3A680FE09D64BF573342CCBCDF7AC078C68A89A508A6085C2C4302207CDFA8E61CA5285624BB5DB1C028966393B34A2A57C9FD6A87925E978ACC42F3"},
};

// Some signatures which have been made by this script: http://kjur.github.io/jsrsasign/sample/sample-ecdsa.html
List<string> signaturesToCheck = new()
{
    // Positive R and S:
    "304402206d886e373ecc7f777992b62938fd5c36dcd019a51483b14f7636427936ad4fd7022058e805bbc38220452772d43188ebf631b942c40fdab2af61c9be20908acfd9d2",
    "304402203a81279f22cb4cbfb30b1c0e79daf1cb2412324c28dca8a3a3df75ab45dc19b7022006c15677795bbe6bf0f51a2a49941ab9e0fd439039fa651eb036e3a3372221b7",
    "304402206ed9aface5c6b3a064df1e85f2e616ad8ff3901caab90407104d9a8fd0433bbb0220334d642369fd2fe820b2b90a279e05f47fa77f7a2d15ec3b563696a6412d63ac",
    "304402202610eff08959cbd611010cc249b1be5f62b37d40397c4a4874fa149708b7a5ae02202edde508c9bbfd234a023fb5639bbe4e693f2ad00275336fd0b6cefa6aa26821",
    "3044022062743bd832bfa753f3a61245cbeec485d5249be973e23fb7092b65feada6c7bb02202afd2e5594b4061b00e49f128dfbd0d549eea79f0371d2751959c14298bec09c",
    "3044022035b054f68c4d93225892fb3b6ee5e67744e7322af0ca3a074153c164ba8ede1902203c1cff6196c44704c551620e51caed9b8e5764629916ae0692d70388105f0374",
    "3044022006f5d526813067139ef8ce2deb9bb8be40f70976b82bc43dfd8b4dbf3e1e34ca022002326e7083d536dbd8ed02b23a51f1a9cc086517368e8ba7de99e00ba4d28912",

    // These are failing because R and/or S are negative:
    "3045022020af00d00c8b02191b636d2574a37719e182cb4147478a0a32ed91204d952ab6022100df00e2cdec9a0fba05ddb26b67703b119c094efc485681478c79af306a327311",
    "304502203045c295a394549858b4c692b6f6d74f8c4b378dcf32701d0632143b2713f765022100a11a9509553911d3c614a78eaacdfa63052c4c2e6e138386c6a070300360ca73",
    "30450220382f2f67b1cba50b5892dbabe523488cea469892fc11edb4f836ffd21535df67022100f6df4054c07b62520af71446eb3c6275bc0a03e76ac5b6ad621b5f164c3731f4",
    "3045022056dac37e213a278c64c5e7d4d3b6fbcca5bc34f96faee9926de8d636b5649fd00221009281d65882e92715e22181f9dd2369d2c596b806563cd4c8e9fd835e847b84b0",
    "3045022045128e59a249d5c8b7c83c88003a2f010a5d08174c8e40d746a6fcd68c78e5ab022100aa579a8fda24ba156298c5d87993cc0fbb6ffcb4692934fbe08c7674f9374ace",
    "30450220404c3701d88fd908adfb0d56f3db60fbb458fdbf6bd6da5a0484d0c96d04b31b0221008a4cccc51862c0faa472cb5d1b839a1694feadd0749d69b412f9182d739c61cd",
    "30450221008688c922f046b4b4a918bcf75cbf5af220b3911337566fe21ade01ec4b54c51502206c21aa70c086476d6dba8586b5305004f3bb5418e57adb7ea7abcdc1b0ccad01",

    // Both R and S are negative:
    "3046022100c70c42aa1f23214192373d8bd6f61687f76a5615dc0acb96df888e5378d29fcb022100a31b6d0dbca4bf7c44c17fd2e06e078195be3ac4988d108907fe6890db85a911",
    "3046022100c9ae6fdb8d0f5bbdbc5e38c499a6bc9fb5e2d0193536e373d283e48320ae7f3c022100a900ae72584d408a83ec0ba8ffe84804e0fffca9aa9067bf43ed12cbacf5fdea",
    "3046022100f426e756844e2fbd0d66d27b490d6d4df9e57ffb419c4c5042353b0083c90405022100e301dda3025aac1d6408e0d8029e9f84354beb9784f27bdea830343c23168975",
    "3046022100b61528bf4925ad5c4915ceaf72389115d8f4eecea9433c7df7748a24144e899902210087718d38f7467bf8ea30cca010e88b2bc8e6964a10dc8aadd4fba9c334f23201",
    "3046022100f811ebf484e1b0e96b4cb30a9bcbef27020d599b7b5eb68c6f30bb7100601c44022100c27490e8e765b656bd5d73065ab9108d0dba29d729b0b7e8588904a66720730c",
    "3046022100854da1cf693a5c47d7f683220e0afa65833c108d320dd230e11ce447f0e952fe022100db7a4727e94760c70e14954eccae185b7b5e6e18e23f0bf09d635bdfe32f81ce",

    // R is negative:
    "30450221008688c922f046b4b4a918bcf75cbf5af220b3911337566fe21ade01ec4b54c51502206c21aa70c086476d6dba8586b5305004f3bb5418e57adb7ea7abcdc1b0ccad01",
    "30450221009c944bde7412d81310d590127da007f401fcaa7a84fce60039dc814a9c829f1a02203b72453b6e5f4d0dc67439e3ebc35f94b9ce62db769e7230a192cf5deaed4ab5",
    "3045022100de5c6b0f4678e33a898d9ad558c7806eb6cf4bbca66d999462172422b3ce21e202200f5c9da6bf61dfbda65da5c3ca283970def56eea1c35e145c3186f08c7404c42"
};

static int SignData<HMAC_IMPL>(Span<byte> signature, IPrivateKey sk, string message, ECCurve curve) where HMAC_IMPL : unmanaged, IMac
{
    // Empty for tests
    Span<byte> message_hash = stackalloc byte[32];
    SHA256.Hash(message_hash, Encoding.ASCII.GetBytes(message));

    if (!sk.SignDeterministic<HMAC_IMPL>(out DERSignature derSig, message_hash))
    {
        throw new SystemException("Signing failed");
    }

    int encodedSz = derSig.Encode(signature);
    if (encodedSz > signature.Length)
    {
        throw new Exception("Signature buffer is too short");
    }

    return encodedSz;
}

static int SignDataNonDeterministic<HMAC_IMPL>(Span<byte> signature, IPrivateKey sk, string message, ICurve curve) where HMAC_IMPL : unmanaged, IMac
{
    // Empty for tests
    Span<byte> message_hash = stackalloc byte[32];
    SHA256.Hash(message_hash, Encoding.ASCII.GetBytes(message));

    // Try signing until the signing will succeed
    DERSignature derSig;
    while (!sk.Sign<HMAC_IMPL>(out derSig, message_hash)) ;

    int encodedSz = derSig.Encode(signature);
    if (encodedSz > signature.Length)
    {
        throw new Exception("Signature buffer is too short");
    }

    return encodedSz;
}

static bool VerifySignature(ReadOnlySpan<byte> signature, string message, ReadOnlySpan<byte> public_key, ECCurve curve)
{
    Span<byte> message_hash = stackalloc byte[32];
    SHA256.Hash(message_hash, Encoding.ASCII.GetBytes(message));
    return curve.MakePublicKey(public_key).VerifySignature(new DERSignature(curve, signature), message_hash);
}

void CompareSig(string algorithm, Span<byte> signature)
{
    var oldColour = Console.ForegroundColor;
    string signatureHex = Convert.ToHexString(signature);
    string expectedHex = vectors[algorithm];
    bool isOk = expectedHex == signatureHex;

    Console.ForegroundColor = isOk ? ConsoleColor.Green : ConsoleColor.Red;
    Console.WriteLine("{0}: {1} {2}", algorithm, signatureHex, isOk ? "OK" : expectedHex);
    Console.ForegroundColor = oldColour;
}

ECCurve curve = ECCurve.Get_SECP256R1();

// Derive new secret key
curve.GenerateDeterministicSecret<HMAC_SHA512>(out ECPrivateKey secretKey, Encoding.ASCII.GetBytes(secret_seed), Encoding.ASCII.GetBytes(personalization), secret_key_number);

if (!secretKey.ComputePublicKey(out IPublicKey publicKey))
{
    throw new SystemException("Computation of the public key has failed");
}

Span<byte> secret_key = stackalloc byte[curve.PrivateKeySize];
Span<byte> public_key_uncompressed = stackalloc byte[curve.UncompressedPublicKeySize];
Span<byte> public_key_compressed = stackalloc byte[curve.CompressedPublicKeySize];

if (!secretKey.Serialize(secret_key))
{
    throw new SystemException("Serialization of the secret key has failed");
}

if (!publicKey.Compress(public_key_compressed))
{
    throw new SystemException("Compression of the public key has failed");
}

if (!publicKey.Serialize(public_key_uncompressed))
{
    throw new SystemException("Serialization of the public key has failed");
}

Console.WriteLine("SECP256R1 private key: {0}", Convert.ToHexString(secret_key));
Console.WriteLine("SECP256R1 public key: 04{0}", Convert.ToHexString(public_key_uncompressed));
Console.WriteLine("SECP256R1 compressed public key: {0}", Convert.ToHexString(public_key_compressed));
Console.WriteLine("Message to sign: {0}", message);

Span<byte> signature = stackalloc byte[curve.DERSignatureSize];

Console.WriteLine("Deterministic SECP256R1 signatures:");

int sha224SigSz = SignData<HMAC_SHA224>(signature, secretKey, message, curve);

if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}

CompareSig("HMAC_SHA224", signature.Slice(0, sha224SigSz));

int sha256SigSz = SignData<HMAC_SHA256>(signature, secretKey, message, curve);
if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}

CompareSig("HMAC_SHA256", signature.Slice(0, sha256SigSz));

int sha512SigSz = SignData<HMAC_SHA512>(signature, secretKey, message, curve);

if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}

CompareSig("HMAC_SHA512", signature.Slice(0, sha512SigSz));

Console.WriteLine("DER decoding and verification tests:");
foreach (var sHex in signaturesToCheck)
{
    Console.Write(sHex);
    var testSig = Convert.FromHexString(sHex);
    if (!VerifySignature(testSig, message, public_key_uncompressed, curve))
    {
        throw new SystemException("Signature verification failure");
    }
    Console.WriteLine(" OK");
}

Console.WriteLine("Non-deterministic signing tests:");

sha224SigSz = SignDataNonDeterministic<HMAC_SHA224>(signature, secretKey, message, curve);
Console.Write("HMAC_SHA224: {0}", Convert.ToHexString(signature.Slice(0, sha224SigSz)));

if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}
Console.WriteLine(" OK");

sha256SigSz = SignDataNonDeterministic<HMAC_SHA256>(signature, secretKey, message, curve);
Console.Write("HMAC_SHA256: {0}", Convert.ToHexString(signature.Slice(0, sha256SigSz)));

if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}
Console.WriteLine(" OK");

sha512SigSz = SignDataNonDeterministic<HMAC_SHA512>(signature, secretKey, message, curve);
Console.Write("HMAC_SHA512: {0}", Convert.ToHexString(signature.Slice(0, sha512SigSz)));

if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}
Console.WriteLine(" OK");
