using Wheel.Crypto.SHA;

/*
ByteVec4.Test();
ByteVec8.Test();
ByteVec16.Test();
ByteVec32.Test();
ByteVec64.Test();
WordVec2.Test();
WordVec4.Test();
WordVec8.Test();
WordVec16.Test();
WordVec64.Test();
*/

byte[] hash1 = new byte[32];
SHA256 hasher1 = new();
hasher1.Update(new byte[66]);
hasher1.Digest(ref hash1);
Console.WriteLine("{0}", Convert.ToHexString(hash1));
hasher1.Reset();
hasher1.Update(new byte[32] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 });
hasher1.Digest(ref hash1);
Console.WriteLine("{0}", Convert.ToHexString(hash1));

byte[] hash2 = new byte[64];
SHA512 hasher2 = new();
hasher2.Update(new byte[66]);
hasher2.Digest(ref hash2);
Console.WriteLine("{0}", Convert.ToHexString(hash2));
hasher2.Reset();
hasher2.Update(new byte[32] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 });
hasher2.Digest(ref hash2);
Console.WriteLine("{0}", Convert.ToHexString(hash2));
