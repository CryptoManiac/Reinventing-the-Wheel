using Wheel.Crypto.Shamir;

byte[] secret = System.Text.Encoding.ASCII.GetBytes("The quick brown fox jumps over the lazy dog");

Scheme scheme = new(8, 5);

var shares = scheme.createShares(secret);

foreach (var s in shares)
{
    Console.WriteLine("----------------");
    Console.WriteLine("Share # {0}", s[0].X);
    foreach (var point in s.AsSpan) {
        Console.WriteLine("{0} {1}", point.X, point.Y);
    }
}

byte[] reconstructed = new byte[scheme.getSecret(null, shares)];
scheme.getSecret(reconstructed, shares);

Console.WriteLine(System.Text.Encoding.ASCII.GetString(reconstructed));
