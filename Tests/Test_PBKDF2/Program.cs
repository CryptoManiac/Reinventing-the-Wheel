using Wheel.Hashing.HMAC.SHA2;
using Wheel.Hashing.Derivation;

/**

PBKDF2 HMAC-SHA256 Test Vectors

Input:
  P = "password" (8 octets)
  S = "salt" (4 octets)
  c = 1
  dkLen = 32

Output:
  DK = 12 0f b6 cf fc f8 b3 2c
       43 e7 22 52 56 c4 f8 37
       a8 65 48 c9 2c cc 35 48
       08 05 98 7c b7 0b e1 7b (32 octets)


Input:
  P = "password" (8 octets)
  S = "salt" (4 octets)
  c = 2
  dkLen = 32

Output:
  DK = ae 4d 0c 95 af 6b 46 d3
       2d 0a df f9 28 f0 6d d0
       2a 30 3f 8e f3 c2 51 df
       d6 e2 d8 5a 95 47 4c 43 (32 octets)


Input:
  P = "password" (8 octets)
  S = "salt" (4 octets)
  c = 4096
  dkLen = 32

Output:
  DK = c5 e4 78 d5 92 88 c8 41
       aa 53 0d b6 84 5c 4c 8d
       96 28 93 a0 01 ce 4e 11
       a4 96 38 73 aa 98 13 4a (32 octets)


Input:
  P = "password" (8 octets)
  S = "salt" (4 octets)
  c = 16777216
  dkLen = 32

Output:
  DK = cf 81 c6 6f e8 cf c0 4d
       1f 31 ec b6 5d ab 40 89
       f7 f1 79 e8 9b 3b 0b cb
       17 ad 10 e3 ac 6e ba 46 (32 octets)


Input:
  P = "passwordPASSWORDpassword" (24 octets)
  S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets)
  c = 4096
  dkLen = 40

Output:
  DK = 34 8c 89 db cb d3 2b 2f
       32 d8 14 b8 11 6e 84 cf
       2b 17 34 7e bc 18 00 18
       1c 4e 2a 1f b8 dd 53 e1
       c6 35 51 8c 7d ac 47 e9 (40 octets)


Input:
  P = "pass\0word" (9 octets)
  S = "sa\0lt" (5 octets)
  c = 4096
  dkLen = 16

Output:
  DK = 89 b6 9d 05 16 f8 29 89
       3c 69 62 26 65 0a 86 87 (16 octets)
*/

List<Tuple<string, string, int, int, string>> vectors_256 = new()
{
    new("password"                 ,   "salt"                                ,  1,          32, "120FB6CFFCF8B32C43E7225256C4F837A86548C92CCC35480805987CB70BE17B" ),
    new("password"                 ,   "salt"                                ,  2,          32, "AE4D0C95AF6B46D32D0ADFF928F06DD02A303F8EF3C251DFD6E2D85A95474C43" ),
    new("password"                 ,   "salt"                                ,  4096,       32, "C5E478D59288C841AA530DB6845C4C8D962893A001CE4E11A4963873AA98134A" ),
    new("password"                 ,   "salt"                                ,  16777216,   32, "CF81C66FE8CFC04D1F31ECB65DAB4089F7F179E89B3B0BCB17AD10E3AC6EBA46" ),
    new("passwordPASSWORDpassword" ,  "saltSALTsaltSALTsaltSALTsaltSALTsalt" ,  4096,       40, "348C89DBCBD32B2F32D814B8116E84CF2B17347EBC1800181C4E2A1FB8DD53E1C635518C7DAC47E9" ),
    new("pass\0word"               ,   "sa\0lt"                              ,  4096,       16, "89B69D0516F829893C696226650A8687" ),
};


/**

PBKDF2 HMAC-SHA512 Test Vectors

Input:
  P = "password"
  S = "salt"
  c = 1
  dkLen = 64

Output:
  DK = 86 7f 70 cf 1a de 02 cf 
       f3 75 25 99 a3 a5 3d c4 
       af 34 c7 a6 69 81 5a e5 
       d5 13 55 4e 1c 8c f2 52 
       c0 2d 47 0a 28 5a 05 01 
       ba d9 99 bf e9 43 c0 8f 
       05 02 35 d7 d6 8b 1d a5 
       5e 63 f7 3b 60 a5 7f ce 


Input:
  P = "password"
  S = "salt"
  c = 2
  dkLen = 64

Output:
  DK = e1 d9 c1 6a a6 81 70 8a 
       45 f5 c7 c4 e2 15 ce b6 
       6e 01 1a 2e 9f 00 40 71 
       3f 18 ae fd b8 66 d5 3c 
       f7 6c ab 28 68 a3 9b 9f 
       78 40 ed ce 4f ef 5a 82 
       be 67 33 5c 77 a6 06 8e 
       04 11 27 54 f2 7c cf 4e 


Input:
  P = "password"
  S = "salt"
  c = 4096
  dkLen = 64

Output:
  DK = d1 97 b1 b3 3d b0 14 3e 
       01 8b 12 f3 d1 d1 47 9e 
       6c de bd cc 97 c5 c0 f8 
       7f 69 02 e0 72 f4 57 b5 
       14 3f 30 60 26 41 b3 d5 
       5c d3 35 98 8c b3 6b 84 
       37 60 60 ec d5 32 e0 39 
       b7 42 a2 39 43 4a f2 d5 


Input:
  P = "passwordPASSWORDpassword"
  S = "saltSALTsaltSALTsaltSALTsaltSALTsalt"
  c = 4096
  dkLen = 64

Output:
  DK = 8c 05 11 f4 c6 e5 97 c6 
       ac 63 15 d8 f0 36 2e 22 
       5f 3c 50 14 95 ba 23 b8 
       68 c0 05 17 4d c4 ee 71 
       11 5b 59 f9 e6 0c d9 53 
       2f a3 3e 0f 75 ae fe 30 
       22 5c 58 3a 18 6c d8 2b 
       d4 da ea 97 24 a3 d3 b8 
*/

List<Tuple<string, string, int, int, string>> vectors_512 = new()
{
    new("password"                 ,   "salt"                                 ,  1,     64, "867F70CF1ADE02CFF3752599A3A53DC4AF34C7A669815AE5D513554E1C8CF252C02D470A285A0501BAD999BFE943C08F050235D7D68B1DA55E63F73B60A57FCE"),
    new("password"                 ,   "salt"                                 ,  2,     64, "E1D9C16AA681708A45F5C7C4E215CEB66E011A2E9F0040713F18AEFDB866D53CF76CAB2868A39B9F7840EDCE4FEF5A82BE67335C77A6068E04112754F27CCF4E"),
    new("password"                 ,   "salt"                                 ,  4096,  64, "D197B1B33DB0143E018B12F3D1D1479E6CDEBDCC97C5C0F87F6902E072F457B5143F30602641B3D55CD335988CB36B84376060ECD532E039B742A239434AF2D5"),
    new("passwordPASSWORDpassword" ,  "saltSALTsaltSALTsaltSALTsaltSALTsalt"  ,  4096,  64, "8C0511F4C6E597C6AC6315D8F0362E225F3C501495BA23B868C005174DC4EE71115B59F9E60CD9532FA33E0F75AEFE30225C583A186CD82BD4DAEA9724A3D3B8"),
};

Span<byte> buffer = stackalloc byte[128];

Console.WriteLine("Testing PBKDF2-HMAC-SHA-256 against test vectors:");

int i = 0;
foreach (var (password, salt, iterations, keySize, expected) in vectors_256)
{
    var secret = buffer.Slice(0, keySize);

    PBKDF2.Derive<HMAC_SHA256>(secret, password, salt, iterations);

    Console.WriteLine("Derived key with hmac-sha256, vector {0}: ", ++i);
    Console.WriteLine("Calculated:\t{0}\nExpected:\t{1}", Convert.ToHexString(secret), expected);
}

Console.WriteLine("Testing PBKDF2-HMAC-SHA-512 against test vectors:");

int j = 0;
foreach (var (password, salt, iterations, keySize, expected) in vectors_512)
{
    var secret = buffer.Slice(0, keySize);

    PBKDF2.Derive<HMAC_SHA512>(secret, password, salt, iterations);

    Console.WriteLine("Derived key with hmac-sha512, vector {0}: ", ++j);
    Console.WriteLine("Calculated:\t{0}\nExpected:\t{1}", Convert.ToHexString(secret), expected);
}
