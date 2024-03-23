using Wheel.Encoders;

Bech32 bech32 = new();

Span<char> hrp = stackalloc char[Bech32.MaxHRPSize];
Span<byte> data = stackalloc byte[Bech32.MaxBECH32Size];
Span<char> encoding_buffer = stackalloc char[Bech32.MaxBECH32Size * 3];

List<Tuple<string, Bech32.DecodingResult>> vectors = new()
{
    new(
        "A12UEL5L",
        Bech32.DecodingResult.success
        ),
    new(
        "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
        Bech32.DecodingResult.success
        ),
    new(
        "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
        Bech32.DecodingResult.success
        ),
    new(
        "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
        Bech32.DecodingResult.success
        ),
    new(
        "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
        Bech32.DecodingResult.success
        ),
    new(
        "?1ezyfcl",
        Bech32.DecodingResult.success
        ),
    new(" 1nwldj5",
        Bech32.DecodingResult.nonPrintableCharacter
        ),
    new(
        "\u007f1axkwrx",
        Bech32.DecodingResult.nonPrintableCharacter
        ),
    new(
        "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
        Bech32.DecodingResult.stringLengthExceeded
        ),
    new(
        "pzry9x0s0muk",
        Bech32.DecodingResult.noChecksumMarker
        ),
    new(
        "1pzry9x0s0muk",
        Bech32.DecodingResult.incorrectHrpSize
        ),
    new(
        "x1b4n0q5v",
        Bech32.DecodingResult.invalidCharacter
        ),
    new(
        "li1dgmt3",
        Bech32.DecodingResult.incorrectChecksumSize
        ),
    new(
        "de1lg7wt\u00ff",
        Bech32.DecodingResult.nonPrintableCharacter
        ),
    new(
        "10a06t8",
        Bech32.DecodingResult.stringLengthTruncated
        ),
    new(
        "1qzzfhee",
        Bech32.DecodingResult.incorrectHrpSize
        ),
};

int n = 0;
foreach(var (vector, expected) in vectors)
{
    Console.WriteLine("Test {0}", ++n);
    Console.WriteLine("Decoding [{0}]\nThe expected result: [{1}]", vector, expected);

    var decodingResult = bech32.Decode(hrp, data, out (int, int) decodingSz, vector);
    if (decodingResult != expected)
    {
        throw new SystemException("Expected[" + expected + "] got [" + decodingResult + "]");
    }

    // Additional check for the successful results:
    //  Encode again and compare the output
    if (decodingResult == Bech32.DecodingResult.success)
    {
        var (hrpSz, dataSz) = decodingSz;
        var hrpToEncode = hrp.Slice(0, hrpSz);
        var dataToEncode = data.Slice(0, dataSz);

        Console.WriteLine("Encoding [{0}] (length={1}) with HRP = {2}", Convert.ToHexString(dataToEncode), dataToEncode.Length, hrpToEncode.ToString());

        var encodingResult = bech32.Encode(encoding_buffer, out int encodedSz, hrpToEncode, dataToEncode);

        if (encodingResult != Bech32.EncodingResult.success)
        {
            throw new SystemException("Encoding error: [" + encodingResult + "]");
        }

        string recoded = encoding_buffer.Slice(0, encodedSz).ToString();

        Console.WriteLine("Encoded bech32 string: [{0}]", recoded);

        if (recoded != vector.ToLower()) {
            throw new SystemException("Encoding error: encoded string mismatch");
        }
    }
}
