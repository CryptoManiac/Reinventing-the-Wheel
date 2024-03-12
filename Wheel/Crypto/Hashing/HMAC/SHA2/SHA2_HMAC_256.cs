using System.Runtime.InteropServices;
using Wheel.Crypto.Hashing.SHA.SHA256;
using Wheel.Crypto.Hashing.SHA.SHA256.Internal;

namespace Wheel.Crypto.Hashing.HMAC.SHA2
{
	[StructLayout(LayoutKind.Explicit)]
	public struct SHA256Base_HMAC : IMac
	{
		[FieldOffset(0)]
		private SHA256Base ctx_inside;

        [FieldOffset(SHA256Base.TypeByteSz)]
        private SHA256Base ctx_outside;

        #region For Reinit()
        [FieldOffset(SHA256Base.TypeByteSz * 2)]
        private SHA256Base ctx_inside_reinit;

        [FieldOffset(SHA256Base.TypeByteSz * 3)]
        private SHA256Base ctx_outside_reinit;
        #endregion

        public readonly int HashSz => ctx_inside.HashSz;

        public SHA256Base_HMAC(in InternalSHA256State constants, int outSz, in ReadOnlySpan<byte> key)
        {
            ctx_inside = new(constants, outSz);
            ctx_outside = new(constants, outSz);
            Reset(key);
        }

        public void Reset(in ReadOnlySpan<byte> key)
        {
            int keySz;

            Span<byte> key_used = stackalloc byte[ctx_inside.HashSz];
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

    public struct HMAC_SHA224 : IMac
    {
        private SHA256Base_HMAC ctx;

        public HMAC_SHA224(ReadOnlySpan<byte> key)
        {
            ctx = new(InternalSHA256Constants.init_state_224, 28, key);
        }

        public int HashSz => ((IMac)ctx).HashSz;
        public void Digest(Span<byte> hash) => ctx.Digest(hash);
        public void Reinit() => ctx.Reinit();
        public void Reset(in ReadOnlySpan<byte> key) => ctx.Reset(key);
        public void Update(ReadOnlySpan<byte> input) => ctx.Update(input);
    }

    public struct HMAC_SHA256 : IMac
    {
        private SHA256Base_HMAC ctx;

        public HMAC_SHA256(ReadOnlySpan<byte> key)
        {
            ctx = new(InternalSHA256Constants.init_state_256, 32, key);
        }

        public int HashSz => ((IMac)ctx).HashSz;
        public void Digest(Span<byte> hash) => ctx.Digest(hash);
        public void Reinit() => ctx.Reinit();
        public void Reset(in ReadOnlySpan<byte> key) => ctx.Reset(key);
        public void Update(ReadOnlySpan<byte> input) => ctx.Update(input);
    }
}
