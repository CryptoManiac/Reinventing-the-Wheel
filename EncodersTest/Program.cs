using Wheel.Encoders;

// Sample data from this wiki page: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
Span<byte> dataToEncode = stackalloc byte[] { 0x00, 0xf5, 0x4a, 0x58, 0x51, 0xe9, 0x37, 0x2b, 0x87, 0x81, 0x0a, 0x8e, 0x60, 0xcd, 0xd2, 0xe7, 0xcf, 0xd8, 0x0b, 0x6e, 0x31, 0xc7, 0xf1, 0x8f, 0xe8 };
string b58expected = "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs";

Console.WriteLine("Data to encode: {0}", Convert.ToHexString(dataToEncode));

/// Instantiate new codec
Base58Codec codec = new Base58Codec();

/// Buffer for base58 encoding result
Span<char> b58chr = stackalloc char[codec.Encode(null, dataToEncode)];

{
    int encoded = codec.Encode(b58chr, dataToEncode);
    b58chr = b58chr.Slice(0, encoded);
}

if (!b58chr.SequenceEqual(b58expected))
{
    throw new SystemException("Encoded string mismatch");
}

Console.WriteLine("Encoding result: {0}", b58chr.ToString());

/// Buffer for base58 decoding result
Span<byte> b58data = stackalloc byte[codec.Decode(null, b58chr)];

{
    int decoded = codec.Decode(b58data, b58chr);
    b58data = b58data.Slice(0, decoded);
}

if (!b58data.SequenceEqual(dataToEncode))
{
    throw new SystemException("Decoded data mismatch");
}

Console.WriteLine("Decoding result: {0}", Convert.ToHexString(b58data));



