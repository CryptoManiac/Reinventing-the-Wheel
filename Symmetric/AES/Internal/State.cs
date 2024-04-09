using System.Runtime.InteropServices;

namespace Wheel.Crypto.Symmetric.AES.Internal;

/// <summary>
/// State word entry
/// </summary>
[StructLayout(LayoutKind.Explicit)]
internal struct StateWord
{
    [FieldOffset(0)] internal unsafe fixed byte data[TypeByteSz];
    internal const int TypeByteSz = 4;

    /// <summary>
    /// Shifts the 4 bytes in a word to the left once
    ///  [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
    /// </summary>
    internal unsafe void RotWord()
    {
        byte tmp = data[0];
        data[0] = data[1];
        data[1] = data[2];
        data[2] = data[3];
        data[3] = tmp;
    }

    /// <summary>
    /// SubWord() is a function that takes a four-byte input word and
    /// applies the S-box to each of the four bytes to produce an output word.
    /// </summary>
    internal unsafe void SubWord()
    {
        data[0] = AESCTR.sbox[data[0]];
        data[1] = AESCTR.sbox[data[1]];
        data[2] = AESCTR.sbox[data[2]];
        data[3] = AESCTR.sbox[data[3]];
    }
}

/// <summary>
/// State, array holding the intermediate results during decryption.
/// </summary>
[StructLayout(LayoutKind.Explicit)]
internal struct State
{
    [FieldOffset(0)] internal unsafe fixed byte data[TypeWordSz * StateWord.TypeByteSz];
    internal const int TypeWordSz = 4;

    /// <summary>
    /// This function adds the round key to state.
    /// The round key is added to the state by an XOR function.
    /// </summary>
    /// <param name="round"></param>
    /// <param name="RoundKey"></param>
    internal unsafe void AddRoundKey(byte round, in AESRoundKey RoundKey)
    {
        fixed (void* ptr = &this)
        {
            StateWord* words = (StateWord*)ptr;
            for (byte i = 0; i < 4; ++i)
            {
                for (byte j = 0; j < 4; ++j)
                {
                    words[i].data[j] ^= RoundKey.data[(round * AESCTR.Nb * 4) + (i * AESCTR.Nb) + j];
                }
            }
        }
    }

    /// <summary>
    /// The SubBytes Function Substitutes the values in the
    /// state matrix with values in an S-box.
    /// </summary>
    internal unsafe void SubBytes()
    {
        fixed (void* ptr = &this)
        {
            StateWord* words = (StateWord*)ptr;
            for (byte i = 0; i < 4; ++i)
            {
                for (byte j = 0; j < 4; ++j)
                {
                    words[j].data[i] = AESCTR.sbox[words[j].data[i]];
                }
            }
        }
    }

    /// <summary>
    /// The ShiftRows() function shifts the rows in the state to the left.
    /// Each row is shifted with different offset.
    /// Offset = Row number. So the first row is not shifted.
    /// </summary>
    internal unsafe void ShiftRows()
    {
        byte temp;
        fixed (void* ptr = &this)
        {
            StateWord* words = (StateWord*)ptr;

            // Rotate first row 1 column to left
            temp = words[0].data[1];
            words[0].data[1] = words[1].data[1];
            words[1].data[1] = words[2].data[1];
            words[2].data[1] = words[3].data[1];
            words[3].data[1] = temp;

            // Rotate second row 2 columns to left
            temp = words[0].data[2];
            words[0].data[2] = words[2].data[2];
            words[2].data[2] = temp;

            temp = words[1].data[2];
            words[1].data[2] = words[3].data[2];
            words[3].data[2] = temp;

            // Rotate third row 3 columns to left
            temp = words[0].data[3];
            words[0].data[3] = words[3].data[3];
            words[3].data[3] = words[2].data[3];
            words[2].data[3] = words[1].data[3];
            words[1].data[3] = temp;
        }
    }

    private static byte XTime(byte x)
    {
        return (byte)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
    }

    /// <summary>
    /// MixColumns function mixes the columns of the state matrix
    /// </summary>
    internal unsafe void MixColumns()
    {
        fixed (void* ptr = &this)
        {
            StateWord* words = (StateWord*)ptr;
            for (byte i = 0; i < 4; ++i)
            {
                byte t = words[i].data[0];
                byte Tmp = (byte)(words[i].data[0] ^ words[i].data[1] ^ words[i].data[2] ^ words[i].data[3]);
                byte Tm = (byte)(words[i].data[0] ^ words[i].data[1]);
                Tm = XTime(Tm);
                words[i].data[0] ^= (byte)(Tm ^ Tmp);
                Tm = (byte)(words[i].data[1] ^ words[i].data[2]);
                Tm = XTime(Tm);
                words[i].data[1] ^= (byte)(Tm ^ Tmp);
                Tm = (byte)(words[i].data[2] ^ words[i].data[3]);
                Tm = XTime(Tm);
                words[i].data[2] ^= (byte)(Tm ^ Tmp);
                Tm = (byte)(words[i].data[3] ^ t);
                Tm = XTime(Tm);
                words[i].data[3] ^= (byte)(Tm ^ Tmp);
            }
        }
    }

    /// <summary>
    /// Cipher is the main function that encrypts the PlainText.
    /// </summary>
    /// <param name="RoundKey"></param>
    internal void Cipher(in AESRoundKey RoundKey)
    {
        // Add the First round key to the state before starting the rounds.
        AddRoundKey(0, RoundKey);

        // There will be Nr rounds.
        // The first Nr-1 rounds are identical.
        // These Nr rounds are executed in the loop below.
        // Last one without MixColumns()
        for (byte round = 1;; ++round)
        {
            SubBytes();
            ShiftRows();
            if (round == AESCTR.Nr)
            {
                break;
            }

            MixColumns();
            AddRoundKey(round, RoundKey);
        }

        // Add round key to last round
        AddRoundKey(AESCTR.Nr, RoundKey);
    }
}