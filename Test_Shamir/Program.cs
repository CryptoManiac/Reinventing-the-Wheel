using Wheel.Crypto.Shamir;
using System.Text;

string secretString = "The quick brown fox jumps over the lazy dog";

Console.WriteLine("Original secret string: {0}", secretString);

byte[] secret = Encoding.ASCII.GetBytes(secretString);

Sharing scheme = new(8, 5);

var shares = scheme.CreateShares(secret);

foreach (var s in shares)
{
    Console.WriteLine("Share # {0} : {1}", s.Index, Convert.ToHexString(s.Raw));
}

Span<byte> reconstructed = stackalloc byte[scheme.MergeShares(null, shares)];
int secretLen = scheme.MergeShares(reconstructed, shares);
reconstructed = reconstructed.Slice(0, secretLen);

Console.WriteLine("Reconstructed secret: {0}", Encoding.ASCII.GetString(reconstructed));
