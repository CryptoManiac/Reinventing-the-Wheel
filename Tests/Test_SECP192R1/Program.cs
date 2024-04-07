// Message for signing
using Hashing.Hashing.HMAC;
using Wheel.Crypto.Elliptic.ECDSA;
using Wheel.Hashing.SHA.SHA256;
using Wheel.Hashing.SHA.SHA512;
using Wheel.Test.ECDSA;

string message = "aaa";

// Should give these results:
// SECP192R1 private key: DB395A4721E3698864A50BBDBC5D12EFDE180237713AC2A6
// SECP192R1 public key: 04FD6177B9BBE18050768E91C49E6356D9794610D440A173B7BEEFCC68D8A2A458BDFC9635D7233450B28468F628DE0B1B
// SECP192R1 compressed public key: 03FD6177B9BBE18050768E91C49E6356D9794610D440A173B7
string secret_seed = "The quick brown fox jumps over the lazy dog";
string personalization = "For signing tests";
int secret_key_number = 0;

List<string> signaturesToCheck = new()
{
};

SECPCurve curve = SECPCurve.Get_SECP192R1();
ECDSATest check = new(curve, secret_seed, personalization, secret_key_number);

check.ExpectedKeys(
    curve.name.ToString(),
    "DB395A4721E3698864A50BBDBC5D12EFDE180237713AC2A6",
    "02C9B6C7B016E66481AD68E6D0CA25873B2AAA05114D04E378D293B51F",
    "04C9B6C7B016E66481AD68E6D0CA25873B2AAA05114D04E378D293B51F5760C12069FC901B74079199FE3F43E95C34E930D132D7D9CBBD67FE"
);

check.ExpectedSignature<HMAC<SHA224>>("HMAC_SHA224", message, "303402182906CC50E59E7B3DF561D53D487688D16FC1A93E4AC8FEA5021839FDF89CB117B4FD29C7C740D004C5DBAB87A20B1811C092");
check.ExpectedSignature<HMAC<SHA256>>("HMAC_SHA256", message, "3035021900D083DB2550A670AA222133CC9E640E321E5CE38C0EA5119202182EAC62438E5ECDB8E330C2E2F3042E25CF689525F6E225B7");
check.ExpectedSignature<HMAC<SHA512>>("HMAC_SHA512", message, "3035021900C91D5102F2DFD5E8CA1F8558AA9A4B5D0FDC83F4AD694C2E0218242ECB529B283C2F8257AEFCC2590D0726C7D87A99757F29");

check.CheckNonDeterministic(message);
check.CheckNonDeterministic(message);
check.CheckNonDeterministic(message);

foreach (var toCheck in signaturesToCheck)
{
    check.VerifySignature(toCheck, message);
}
