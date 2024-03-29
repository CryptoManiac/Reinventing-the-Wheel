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

    [Option("verbose", HelpText = "Be verbose about what is going on", Default = false)]
    public bool Verbose { get; set; }
}

static class ShamirUtil
{
    private static void Split(CommandLineOptions o)
    {
        if (File.Exists(o.Shares))
        {
            Console.Error.WriteLine("Specified shares file already exists");
            Environment.Exit(-1);
        }

        var info = new FileInfo(o.Secret);

        if (!info.Exists)
        {
            Console.Error.WriteLine("Specified secrets file doesn't exist");
            Environment.Exit(-2);
        }

        // This doesn't mean that it would be wise
        //  to generate 1M share or secret files
        if (info.Length > 125000)
        {
            Console.Error.WriteLine("Secrets file is unreasonably big");
            Environment.Exit(-3);
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

                if (o.Verbose)
                {
                    Console.WriteLine("# Generated share for participant #{0}", share.Index);
                    Console.WriteLine(encoded.ToString());
                }

                sharesFile.WriteLine(encoded);
            }
        }

        Console.WriteLine("Done, shares are written into {0}", o.Shares);
    }

    private static void Merge(CommandLineOptions o)
    {
        if (File.Exists(o.Secret))
        {
            Console.Error.WriteLine("Specified secrets file already exists");
            Environment.Exit(-4);
        }

        var info = new FileInfo(o.Shares);

        if (!info.Exists)
        {
            Console.Error.WriteLine("Specified shares file doesn't exist");
            Environment.Exit(-5);
        }

        // This doesn't mean that it would be wise
        //  to generate 1M share or secret files
        if (info.Length > 1000000)
        {
            Console.Error.WriteLine("Shares file is unreasonably big");
            Environment.Exit(-6);
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
                    if (collected.Count < scheme.Threshold)
                    {
                        Console.Error.WriteLine("Not enough shares for the recovery quorum, you have {0} while the requirement is {1}", collected.Count, scheme.Threshold);
                        Environment.Exit(-8);
                    }
                    break;
                }

                Span<byte> decoded = new byte[b58.Decode(null, encoded)];
                if (0 == decoded.Length)
                {
                    Console.Error.WriteLine("Truncated share found");
                    Environment.Exit(-9);
                }

                int shareSz = b58.Decode(decoded, encoded);
                decoded = decoded.Slice(0, shareSz);

                Share share = new(decoded);

                if (o.Verbose)
                {
                    Console.WriteLine("# Read share of participant #{0}", share.Index);
                    Console.WriteLine(encoded.ToString());
                }

                collected.Add(share);

                if (collected.Count >= scheme.Threshold)
                {
                    if (o.Verbose) {
                        Console.WriteLine("Collected just enough shares to fill the quorum");
                    }
                    //  no need to proceed further
                    break;
                }
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
                case "merge":
                    Merge(o); return;
                case "split":
                    Split(o); return;
                default:
                    Console.Error.WriteLine("You must specify operation type by setting the --command option");
                    Environment.Exit(-10);
                    return;
            }
        });
    }
}
