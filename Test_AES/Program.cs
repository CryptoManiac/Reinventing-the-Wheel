using Wheel.Crypto.AES;
using System.Text;
using System.Runtime.InteropServices;

ReadOnlySpan<byte> key = stackalloc byte[32] {
      0x26, 0x18, 0xbb, 0x1d, 0xa0, 0xd1, 0x93, 0xfe
    , 0x95, 0x5b, 0x98, 0x1f, 0x3d, 0x84, 0x92, 0x2b
    , 0xa6, 0xd2, 0x77, 0xc0, 0x6c, 0x19, 0xfb, 0x4e
    , 0x32, 0x60, 0x7a, 0xb4, 0x6d, 0x68, 0xe6, 0x43
};

ReadOnlySpan<byte> iv = stackalloc byte[16]
{
      0x6e, 0xb7, 0x92, 0xf5, 0xcb, 0x23, 0x47, 0x9d
    , 0x08, 0xac, 0x70, 0x8e, 0xe4, 0xdf, 0x0c, 0x76
};

byte[] dataToEncrypt = Encoding.ASCII.GetBytes("The quick brown fox jumps over the lazy dog");

AESContext ctx = new AESContext(key, iv);

// Allocate required number of blocks (data + padding)
Span<AESBlock> blocks = stackalloc AESBlock[AESBlock.GetBlocksWithPadding(dataToEncrypt.Length)];

// block data as bytes
Span<byte> blockBytes = MemoryMarshal.Cast<AESBlock, byte>(blocks);

// Fill the data
dataToEncrypt.CopyTo(blockBytes);

// Write padding bytes to last block
AESBlock.FillPaddingBlock(ref blocks[blocks.Length - 1], dataToEncrypt.Length);

Console.WriteLine("Plaintext bytes: {0}", Convert.ToHexString(blockBytes.Slice(0, dataToEncrypt.Length)));
Console.WriteLine("Plaintext string: {0}", Encoding.ASCII.GetString(blockBytes.Slice(0, dataToEncrypt.Length)));

// Encrypt data with the configured Key and IV
ctx.ProcessBlocks(blocks);

Console.WriteLine("Ciphertext bytes: {0}", Convert.ToHexString(blockBytes));

// Reset the context
ctx.Init(key, iv);

// Decryption is done with the same algorithm
ctx.ProcessBlocks(blocks);

// Padding is written in the last block
int paddingLength = AESBlock.GetPaddingLen(blocks[blocks.Length - 1]);

// Slice out the last [paddingLength] bytes to get the original data
var decryptedData = blockBytes.Slice(0, blockBytes.Length - paddingLength);

if (!decryptedData.SequenceEqual(dataToEncrypt))
{
    // Algorithm bug
    throw new SystemException("Decrypted data mismatch");
}

Console.WriteLine("Decrypted bytes: {0}", Convert.ToHexString(decryptedData));
Console.WriteLine("Decrypted string: {0}", Encoding.ASCII.GetString(decryptedData));
