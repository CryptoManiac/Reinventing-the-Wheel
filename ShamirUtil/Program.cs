using System.Text;
using CommandLine;
using Wheel.Crypto.Shamir;
using Wheel.Encoders;

public class CommandLineOptions
{
    [Option('n', "number", Required = true, HelpText = "Number of participants")]
    public int Participants { get; set; }

    [Option('t', "threshold", Required = true, HelpText = "Quorum to recover a secret")]
    public int Threshold { get; set; }

    [Option('c', "command", Required = true, HelpText = "Command to execute, either \"split\" or \"merge\"")]
    public required string Command { get; set; }

    [Option("secret", Required = true, HelpText = "Secret file path")]
    public required string Secret { get; set; }

    [Option("shares", Required = true, HelpText = "Shares file path")]
    public required string Shares { get; set; }

    [Option("password", HelpText = "Encryption password")]
    public string? Password { get; set; }
}

static class ShamirUtil
{
    private static void Split(CommandLineOptions o)
    {
        if (File.Exists(o.Shares))
        {
            throw new InvalidOperationException("Specified shares file already exists");
        }

        var info = new FileInfo(o.Secret);

        if (!info.Exists)
        {
            throw new InvalidOperationException("Specified secrets file doesn't exist");
        }

        // This doesn't mean that it would be wise
        //  to generate 1M share or secret files
        if (info.Length > 125000)
        {
            throw new InvalidOperationException("Secrets file is unreasonably big");
        }

        Console.WriteLine("Executiong split command for configuration {0}-of-{1}", o.Threshold, o.Participants);

        Base58Codec b58 = new();
        Sharing scheme = new(o.Participants, o.Threshold);

        var secret = File.ReadAllBytes(o.Secret);

        Share[] chunks = scheme.CreateEncryptedShares(secret, Encoding.ASCII.GetBytes(o.Password ?? string.Empty));

        using (StreamWriter sharesFile = new StreamWriter(o.Shares))
        {
            foreach (var share in chunks)
            {
                var data = share.Raw;
                Span<char> encoded = new char[b58.Encode(null, data)];
                int b58Len = b58.Encode(encoded, data);
                encoded = encoded.Slice(0, b58Len);
                sharesFile.WriteLine(encoded);
            }
        }

        Console.WriteLine("Done, shares are written into {0}", o.Shares);
    }

    private static void Merge(CommandLineOptions o)
    {
        if (File.Exists(o.Secret))
        {
            throw new InvalidOperationException("Specified secrets file already exists");
        }

        var info = new FileInfo(o.Shares);

        if (!info.Exists)
        {
            throw new InvalidOperationException("Specified shares file doesn't exist");
        }

        // This doesn't mean that it would be wise
        //  to generate 1M share or secret files
        if (info.Length > 1000000)
        {
            throw new InvalidOperationException("Shares file is unreasonably big");
        }

        Console.WriteLine("Executiong merge command for configuration {0}-of-{1}", o.Threshold, o.Participants);

        Base58Codec b58 = new();
        Sharing scheme = new(o.Participants, o.Threshold);
        List<Share> collected = new();

        using (StreamReader sharesFile = new StreamReader(o.Shares))
        {
            while(true)
            {
                string? encoded = sharesFile.ReadLine();
                if (encoded == null)
                {
                    break;
                }

                Span<byte> decoded = new byte[b58.Decode(null, encoded)];
                if (0 == decoded.Length)
                {
                    throw new InvalidDataException("Truncated share found");
                }

                int shareSz = b58.Decode(decoded, encoded);
                decoded = decoded.Slice(0, shareSz);
                collected.Add(new(decoded));
            }
        }

        Share[] shares = collected.ToArray();
        Span<byte> reconstructed = stackalloc byte[scheme.MergeShares(null, shares)];
        int recSz = scheme.MergeEncrypted(reconstructed, shares, Encoding.ASCII.GetBytes(o.Password ?? string.Empty));

        reconstructed = reconstructed.Slice(0, recSz);

        File.WriteAllBytes(o.Secret, reconstructed.ToArray());

        Console.WriteLine("Done, secret is written into {0}", o.Secret);
    }

    public static void Main(params string[] args)
    {
        Parser.Default.ParseArguments<CommandLineOptions>(args).WithParsed<CommandLineOptions>(o => {
            switch(o.Command.ToLower())
            {
                case "merge": Merge(o); return;
                case "split": Split(o); return;
                default: throw new ArgumentException("Unsupported command");
            }
        });
    }
}
