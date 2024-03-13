using Wheel.Crypto.Hashing.HMAC;
using System.Text;

namespace Wheel.Crypto.Hashing.Derivation
{
	public static class PBKDF2
    {
		/// <summary>
		/// Derive new key using provided HMAC function
		/// </summary>
		/// <param name="key">Span where generated private key will be written. Its length is used by algorithm as key length parameter.</param>
		/// <param name="mac">Function which should return HMAC instance after getting called with byte array as an argument</param>
		/// <param name="password"></param>
		/// <param name="salt"></param>
		/// <param name="c">Number of hashing iterations</param>
		public static void Derive<MAC_IMPL>(Span<byte> key, string password, string salt, int c) where MAC_IMPL : struct, IMac
		{
            byte[] password_bytes = Encoding.ASCII.GetBytes(password);
            byte[] salt_bytes = Encoding.ASCII.GetBytes(salt);

            /* Compute HMAC state after processing P and S. */
            MAC_IMPL PShctx = new();
            PShctx.Init(password_bytes);
			PShctx.Update(salt_bytes);

            int HashSz = PShctx.HashSz;
            Span<byte> U = stackalloc byte[HashSz];
            Span<byte> T = stackalloc byte[HashSz];
            Span<byte> ivec = stackalloc byte[4];

            /* Iterate through the blocks. */
            for (int i = 0; i * HashSz < key.Length; ++i)
			{
                /* Generate INT(i + 1). */
                be32enc(ivec, (uint)(i + 1));

                /* Compute U_1 = PRF(P, S || INT(i)). */
                MAC_IMPL hctx = PShctx;
                hctx.Update(ivec);
                hctx.Digest(U);

                /* T_i = U_1 ... */
                U.CopyTo(T);

                for (int j = 2; j <= c; j++)
                {
                    /* Compute U_j. */
                    hctx.Init(password_bytes);
                    hctx.Update(U);
                    hctx.Digest(U);

                    /* ... xor U_j ... */
                    for (int k = 0; k < HashSz; k++)
                    {
                        T[k] ^= U[k];
                    }
                }

                /* Copy as many bytes as necessary into buf. */
                int clen = key.Length - i * HashSz;
                if (clen > HashSz)
                {
                    clen = HashSz;
                }

                var src = T.Slice(0, clen);
                var target = key.Slice(i * HashSz);

                src.CopyTo(target);
            }

            /* Clean PShctx, since we never called _Final on it. */
            PShctx.Reset();
        }

        private static void be32enc(Span<byte> p, uint x)
        {
            p[3] = (byte)(x & 0xff);
            p[2] = (byte)((x >> 8) & 0xff);
            p[1] = (byte)((x >> 16) & 0xff);
            p[0] = (byte)((x >> 24) & 0xff);
        }
    }
}

