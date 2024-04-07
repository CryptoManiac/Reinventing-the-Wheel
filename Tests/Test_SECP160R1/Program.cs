// Message for signing
using Hashing.Hashing.HMAC;
using Wheel.Crypto.Elliptic.ECDSA;
using Wheel.Hashing.SHA.SHA256;
using Wheel.Hashing.SHA.SHA512;
using Wheel.Test.ECDSA;

string message = "aaa";

// Should give these results:
// SECP160R1 private key: 00F0D58A83B58E16142278FDD076070D969A958989
// SECP160R1 public key: 0400103346CA120480B2671E14C82AEBE8E64CB2DD40002B885B503445D96242BD01AD91C3CF8D35931A67
// SECP160R1 compressed public key: 0300103346CA120480B2671E14C82AEBE8E64CB2DD40
string secret_seed = "The quick brown fox jumps over the lazy dog";
string personalization = "For signing tests";
int secret_key_number = 0;

List<string> signaturesToCheck = new()
{
};

SECPCurve curve = SECPCurve.Get_SECP160R1();
ECDSATest check = new(curve, secret_seed, personalization, secret_key_number);

check.ExpectedKeys(
    curve.name.ToString(),
    "00F0D58A83B58E16142278FDD076070D969A958989",
    "0300103346CA120480B2671E14C82AEBE8E64CB2DD40",
    "0400103346CA120480B2671E14C82AEBE8E64CB2DD40002B885B503445D96242BD01AD91C3CF8D35931A67"
);

check.ExpectedSignature<HMAC<SHA224>>("HMAC_SHA224", message, "302E02150093066992E3B8BA8533013C87A93DDD6BD1D6B42202150020B1D1FEFE53696CB6338E5CF8B9745624307126");
check.ExpectedSignature<HMAC<SHA256>>("HMAC_SHA256", message, "302E021500FA7117B79213B9E24D3E402A58E77381B303924D02150014AF98513E9DEC867A3AD0D63F831F292B20122B");
check.ExpectedSignature<HMAC<SHA512>>("HMAC_SHA512", message, "302E021500F8813D59513113DE6CE1E2CA8907D9F3CFC6939B02150074E582076012CDC2E27467A23EF233799810997A");

check.CheckNonDeterministic(message);
check.CheckNonDeterministic(message);
check.CheckNonDeterministic(message);

foreach (var toCheck in signaturesToCheck)
{
    check.VerifySignature(toCheck, message);
}
