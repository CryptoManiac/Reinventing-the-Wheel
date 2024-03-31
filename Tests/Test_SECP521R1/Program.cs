using System.Text;
using Wheel.Crypto.Elliptic.ECDSA;
using Wheel.Crypto.Elliptic.EllipticCommon;
using Wheel.Hashing.HMAC;
using Wheel.Hashing.HMAC.SHA2;
using Wheel.Hashing.SHA.SHA256;

string message = "aaa";

// Should give these results:
// SECP521R1 private key: 01A3D607E4D8C8333F3F00364003773A6153A449E2284133448984B366B79E4C37B01B74CEB11E27A20383F17087292381653E31EAF8E217653084E1E83A2FF8E2FF
// SECP521R1 public key: 04006575A24E2EBDA0A4570AB50B95BA0495AFD88EC56BBA246CC3416730B650AA22460BCB7458E698534D7B147D243C7A77A130DB384561F8E5649EC1C7B2281C2EBD00545EC495DA16B62B063D29824A4D278F1ED213363AFB0EEABB31439B58E1847279E00CCFDA2CB90617A05806C19685CC19C1468AD24629D67A487FC9D0FC91315A
// SECP521R1 compressed public key: 02006575A24E2EBDA0A4570AB50B95BA0495AFD88EC56BBA246CC3416730B650AA22460BCB7458E698534D7B147D243C7A77A130DB384561F8E5649EC1C7B2281C2EBD
string secret_seed = "The quick brown fox jumps over the lazy dog";
string personalization = "For signing tests";
int secret_key_number = 0;

// Must be valid, check here: http://kjur.github.io/jsrsasign/sample/sample-ecdsa.html (select SECP521R1 curve and SHA256withECDSA algorithm)
SortedDictionary<string, string> vectors = new()
{
    {  "HMAC_SHA224", "3081880242014B11A301320466281DD974DF5A4C827163FA5AE00E497399A309CA1980D245C79BAA78EF45E3E48FA3992A2A08FD4C9D413D2886919B6515F4521CA39FC1CAE5210242008399EC3A31F5EF1A8BD4070336DBF70AAB262910DAA45DE72784A46C99F40C8307DFF297F8103B90A81ACDF68D1D25C432FD51979B6C6277854A8F0A7A9225061B"},
    {  "HMAC_SHA256", "308188024200231B04A26F33CC2D55E9A791280679C30D0CBCE1D69D9D0F9F663CAC9865F26F5D69C7BFDCDBF76B1764C6630E705DEE1FC905309AE912D34A7FDB0DFB1963B877024200D32B44E80AB659C19A12B90C7B0DD8A5251F9D30D0B253403A90ED2A370C33BD22FB2B3F2A953F4610D3EA8ACC9F96065AF3DB288D25444FC37167548C51075D09"},
    {  "HMAC_SHA512", "3081880242008E6003B44091EF2D33C0BAC733DD860B9A682F43BDF154766C223177290DD31F6F0560C53B9E1B48FB371A2512415A650693D0B873F805DFA98B15B5DCB1B034A2024200A92566F098B5754F5684529A0326B811E1370FE0EBDB36D1A0ABFB8BC307097AC5CBF5F903A7F853669E07049107CCEEC122CEBA85217B2973F168308C09320330"},
};

// Some signatures which have been made by this script: http://kjur.github.io/jsrsasign/sample/sample-ecdsa.html
List<string> signaturesToCheck = new()
{
    "308186024121b93d1c23c41a33f13397cbc5da9d234917796e3b392a88677b01cf76b57560acb3664da8230aa43d96aa84901c93bcc35c00aec3b6bbb8e5acc3fb216128f47c02410e38823dbe187eb70df3f7110ca856d6f4b4525b027e239df6d37733ebbdefea401096f1a1d522950f9ca9735deedb62e4584af6e017aa7df277d3d8f996d56088",
    "30818602415bd765173c04a97689a7b1151befb0970bc4a2f1a659c2b24bb8310fb9fec66fb3f3360263fa21916a7598fa315380ca1b02c22a8e053d17237dd53c51a19a679502412a9f9a582cf4cc9c731f7bbbeab96e8345170fa4b626cc4f946d326b817f745588ed4dbeead1916b97f0c5dea8dd43bf2b9633d9a13f2041debe6292e38676a177",
    "30818602415f6a49b921e9c1076980267d88ac9772e37502e86e9482cba4fff1ded955aed0c12e04a2ea6fbee69829d14c506c534225572877eda20901205f93b72f357e96bd024173227019d40faa683986b660c1838cd488e7cc7514aa6191b875475aa3245ab02215800c90cc94fa4ada7178298b5786c4756ef5ca74a00ef8cd9966a1f19c82eb",
    "308186024134b259690b3644511112bf958d3d38ff6ba6668173f1af854f0f313dfb1c05706f9011c0b025cc3d79a249b9dd6e579f9f23d3313e95d2de91a692f1a8bed5e5e502417537117552dccfadf7daf7075a3bc2076a20d35e60cd576672c93adfc5e8d56d29877cf7ddfd8da915b97d82e8a94989f5963a33da48fe9f6d7828ae5d5482d125",
    "308187024201a55d8870d2c399491b70e62c5f42dc24e22c1a6c7764fa754d7045ecf481fb442bde3a61110817f939ea479ef9bc602994b0ed599780144e3160127f1e409285940241751702ce9564bb6dc0828d3c66efa4e7f5d26dce9ef4dbc45340b9f23e2c0546f3314a068e7be5b748683730782955e53d6eef95fc0d7b0f9d70754610617a6701",
    "308187024201f9a5eb2451af255817063a6fe6211198a02e842ef8d09561143934c47fafe16e8523d0dee873ee3fd513182438a9827bb6c29d33f9f27b78c9e1c019514b774f8402415320dfbb2de67a888e60b525ee86dc20c50d0ce408f1e54ec443c7d327e3cb2b3a18c10c528ace70b60a91ef7eb321dd05c646103eea53293c46da7ec0db68de1c",
    "30818802420198299ee655e6a1585d05e231a4bbd90aa85797fc504afa9af149a5eee6ccd9e3d4ed6e4128b349eb4ed04f6a0a0c7cc9efa83d34a249ddcb67a5845107dd459ea40242011706c5f7e74def03a161acbe3663eba717532a69660413b5a28cdc3ed86d842d0fff38cb8776f0142a7f4411564b63ee2386f70b450badb9d2fda94315ded90178",
    "308188024201586a90f23e0aa266f46dbe594ef21f8823787799e2c7729fbe9aecc59a37256c79c9d1b37c285e1cf7f8cdf7708bce0dc08819dfb35df2d4b6c8d2744fed4c98af0242018a0d4a472a8a82a23816151cca9d61f1dd609694d6a359c7b2abfcf80f06a607c04a6a81cd44872c2c77bd57e60f37853210f2da0876374a9af5d183a4a7dbd7e5",
    "308188024201374f452df60a1e1fb2361171f4b11a5d36aa3254b545430ec523052130e2697eb2b23959f815e02e2242cc62f00e94cf61465559ef4d6bfd463d609a010d693089024201360223ccd51ce08f29fb3416dd493de4ba254d92956b41f2a2a8fd51f6c08ab7c6a084ad3415d272e87c3af724229b7af5084cb052c3680c827c4034795d928732",
};

static void SignData<HMAC_IMPL>(Span<byte> signature, IPrivateKey sk, string message, ECCurve curve) where HMAC_IMPL : unmanaged, IMac
{
    // Empty for tests
    Span<byte> message_hash = stackalloc byte[32];
    SHA256.Hash(message_hash, Encoding.ASCII.GetBytes(message));

    if (!sk.SignDeterministic<HMAC_IMPL>(out DERSignature derSig, message_hash))
    {
        throw new SystemException("Signing failed");
    }

    if (signature.Length < derSig.Encode(signature))
    {
        throw new Exception("Signature buffer is too short");
    }
}

static void SignDataNonDeterministic<HMAC_IMPL>(Span<byte> signature, IPrivateKey sk, string message, ICurve curve) where HMAC_IMPL : unmanaged, IMac
{
    // Empty for tests
    Span<byte> message_hash = stackalloc byte[32];
    SHA256.Hash(message_hash, Encoding.ASCII.GetBytes(message));

    // Try signing until the signing will succeed
    DERSignature derSig;
    while (!sk.Sign<HMAC_IMPL>(out derSig, message_hash)) ;

    if (signature.Length < derSig.Encode(signature))
    {
        throw new Exception("Signature buffer is too short");
    }
}

static bool VerifySignature(ReadOnlySpan<byte> signature, string message, ReadOnlySpan<byte> public_key, ECCurve curve, bool nonCanonical=false)
{
    Span<byte> message_hash = stackalloc byte[32];
    SHA256.Hash(message_hash, Encoding.ASCII.GetBytes(message));
    return curve.MakePublicKey(public_key).VerifySignature(new DERSignature(curve, signature, nonCanonical), message_hash);
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

ECCurve curve = ECCurve.Get_SECP521R1();

// Derive new secret key
curve.GenerateDeterministicSecret<HMAC_SHA512>(out IPrivateKey secretKey, Encoding.ASCII.GetBytes(secret_seed), Encoding.ASCII.GetBytes(personalization), secret_key_number);

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

Console.WriteLine("SECP521R1 private key: {0}", Convert.ToHexString(secret_key));
Console.WriteLine("SECP521R1 public key: 04{0}", Convert.ToHexString(public_key_uncompressed));
Console.WriteLine("SECP521R1 compressed public key: {0}", Convert.ToHexString(public_key_compressed));
Console.WriteLine("Message to sign: {0}", message);

Span<byte> signature = stackalloc byte[curve.DERSignatureSize];

Console.WriteLine("Deterministic SECP521R1 signatures:");

SignData<HMAC_SHA224>(signature, secretKey, message, curve);

if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}

CompareSig("HMAC_SHA224", signature);

SignData<HMAC_SHA256>(signature, secretKey, message, curve);
if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}

CompareSig("HMAC_SHA256", signature);


SignData<HMAC_SHA512>(signature, secretKey, message, curve);

if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}

CompareSig("HMAC_SHA512", signature);

Console.WriteLine("Canonical DER decoding and verification tests:");
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

SignDataNonDeterministic<HMAC_SHA224>(signature, secretKey, message, curve);
Console.Write("HMAC_SHA224: {0}", Convert.ToHexString(signature));

if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}
Console.WriteLine(" OK");

SignDataNonDeterministic<HMAC_SHA256>(signature, secretKey, message, curve);
Console.Write("HMAC_SHA256: {0}", Convert.ToHexString(signature));

if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}
Console.WriteLine(" OK");

SignDataNonDeterministic<HMAC_SHA512>(signature, secretKey, message, curve);
Console.Write("HMAC_SHA512: {0}", Convert.ToHexString(signature));

if (!VerifySignature(signature, message, public_key_uncompressed, curve))
{
    throw new SystemException("Signature verification failure");
}
Console.WriteLine(" OK");
