using System;
using System.Runtime.InteropServices;
using Wheel.Crypto.Hashing.SHA.SHA256;
using Wheel.Crypto.Hashing.SHA.SHA256.Internal;
using Wheel.Crypto.Hashing.SHA.SHA512;
using Wheel.Crypto.Hashing.SHA.SHA512.Internal;

namespace Wheel.Crypto.Hashing.HMAC.SHA2
{
	[StructLayout(LayoutKind.Explicit)]
	public struct SHA256_HMAC : IMac
	{
		[FieldOffset(0)]
		private SHA256 ctx_inside = new();

        [FieldOffset(SHA256.TypeByteSz)]
        private SHA256 ctx_outside = new();

        #region For Reinit()
        [FieldOffset(SHA256.TypeByteSz * 2)]
        private SHA256 ctx_inside_reinit = new();

        [FieldOffset(SHA256.TypeByteSz * 3)]
        private SHA256 ctx_outside_reinit = new();
        #endregion

        public int HashSz => ctx_outside.HashSz;

        public SHA256_HMAC(in ReadOnlySpan<byte> key)
        {
            Reset(key);
        }

        public void Reset(in ReadOnlySpan<byte> key)
        {
            int keySz;

            Span<byte> key_used = stackalloc byte[ctx_outside.HashSz];
            Span<byte> block_opad = stackalloc byte[InternalSHA256Block.TypeByteSz];
            Span<byte> block_ipad = stackalloc byte[InternalSHA256Block.TypeByteSz];

            if (key.Length == InternalSHA256Block.TypeByteSz)
            {
                keySz = InternalSHA256Block.TypeByteSz;
                key.CopyTo(key_used);
            }
            else
            {
                if (key.Length > InternalSHA256Block.TypeByteSz)
                {
                    keySz = InternalSHA256Block.TypeByteSz;
                    SHA256.Hash(key_used, key);
                }
                else
                {
                    // key.Length > InternalSHA256Block.TypeByteSz
                    keySz = key.Length;
                    key.CopyTo(key_used);
                }

                int fill = InternalSHA256Block.TypeByteSz - keySz;

                block_ipad.Slice(keySz).Fill(0x36);
                block_opad.Slice(keySz).Fill(0x5c);
            }

            for (int i = 0; i < keySz; i++)
            {
                block_ipad[i] = (byte) (key_used[i] ^ 0x36);
                block_opad[i] = (byte) (key_used[i] ^ 0x5c);
            }

            ctx_inside.Update(block_ipad);
            ctx_outside.Update(block_opad);

            // for Reinit()
            ctx_inside_reinit.Reset(ctx_inside);
            ctx_outside_reinit.Reset(ctx_outside);
        }

        public void Update(ReadOnlySpan<byte> message)
        {
            ctx_inside.Update(message);
        }

        public byte[] Digest()
        {
            byte[] mac = new byte[ctx_inside.HashSz];
            Digest(mac);
            return mac;
        }

        public void Digest(Span<byte> mac)
        {
            Span<byte> digest_inside = stackalloc byte[ctx_inside.HashSz];
            Span<byte> mac_temp = stackalloc byte[ctx_inside.HashSz];

            ctx_inside.Digest(digest_inside);
            ctx_outside.Update(digest_inside);
            ctx_outside.Digest(mac_temp);
            mac_temp.Slice(0, mac.Length).CopyTo(mac);
            Reinit();
        }

        public void Reinit()
        {
            ctx_inside.Reset(ctx_inside_reinit);
            ctx_outside.Reset(ctx_outside_reinit);
        }
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct SHA512_HMAC : IMac
    {
        [FieldOffset(0)]
        private SHA512 ctx_inside = new();

        [FieldOffset(SHA512.TypeByteSz)]
        private SHA512 ctx_outside = new();

        #region For Reinit()
        [FieldOffset(SHA512.TypeByteSz * 2)]
        private SHA512 ctx_inside_reinit = new();

        [FieldOffset(SHA512.TypeByteSz * 3)]
        private SHA512 ctx_outside_reinit = new();
        #endregion

        public int HashSz => ctx_outside.HashSz;

        public SHA512_HMAC(in ReadOnlySpan<byte> key)
        {
            Reset(key);
        }

        public void Reset(in ReadOnlySpan<byte> key)
        {
            int keySz;

            Span<byte> key_used = stackalloc byte[ctx_outside.HashSz];
            Span<byte> block_opad = stackalloc byte[InternalSHA512Block.TypeByteSz];
            Span<byte> block_ipad = stackalloc byte[InternalSHA512Block.TypeByteSz];

            if (key.Length == InternalSHA512Block.TypeByteSz)
            {
                keySz = InternalSHA512Block.TypeByteSz;
                key.CopyTo(key_used);
            }
            else
            {
                if (key.Length > InternalSHA512Block.TypeByteSz)
                {
                    keySz = InternalSHA512Block.TypeByteSz;
                    SHA512.Hash(key_used, key);
                }
                else
                {
                    // key.Length > InternalSHA512Block.TypeByteSz
                    keySz = key.Length;
                    key.CopyTo(key_used);
                }

                int fill = InternalSHA512Block.TypeByteSz - keySz;

                block_ipad.Slice(keySz).Fill(0x36);
                block_opad.Slice(keySz).Fill(0x5c);
            }

            for (int i = 0; i < keySz; i++)
            {
                block_ipad[i] = (byte)(key_used[i] ^ 0x36);
                block_opad[i] = (byte)(key_used[i] ^ 0x5c);
            }

            ctx_inside.Update(block_ipad);
            ctx_outside.Update(block_opad);

            // for Reinit()
            ctx_inside_reinit.Reset(ctx_inside);
            ctx_outside_reinit.Reset(ctx_outside);
        }

        public void Update(ReadOnlySpan<byte> message)
        {
            ctx_inside.Update(message);
        }

        public byte[] Digest()
        {
            byte[] mac = new byte[ctx_inside.HashSz];
            Digest(mac);
            return mac;
        }

        public void Digest(Span<byte> mac)
        {
            Span<byte> digest_inside = stackalloc byte[ctx_inside.HashSz];
            Span<byte> mac_temp = stackalloc byte[ctx_inside.HashSz];

            ctx_inside.Digest(digest_inside);
            ctx_outside.Update(digest_inside);
            ctx_outside.Digest(mac_temp);
            mac_temp.Slice(0, mac.Length).CopyTo(mac);
            Reinit();
        }

        public void Reinit()
        {
            ctx_inside.Reset(ctx_inside_reinit);
            ctx_outside.Reset(ctx_outside_reinit);
        }
    }
}
