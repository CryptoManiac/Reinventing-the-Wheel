using System.Runtime.InteropServices;
using Wheel.Crypto.Hashing.SHA.SHA256;
using Wheel.Crypto.Hashing.SHA.SHA256.Internal;

namespace Wheel.Crypto.Hashing.HMAC.SHA2
{
	[StructLayout(LayoutKind.Explicit)]
    internal struct SHA256Base_HMAC : IMac
	{
		[FieldOffset(0)]
		private SHA256Base ctx_inside;

        [FieldOffset(SHA256Base.TypeByteSz)]
        private SHA256Base ctx_outside;

        // For key pre-hashing
        [FieldOffset(SHA256Base.TypeByteSz * 2)]
        private SHA256Base ctx_prehasher;

        #region For Reinit()
        [FieldOffset(SHA256Base.TypeByteSz * 3)]
        private SHA256Base ctx_inside_reinit;

        [FieldOffset(SHA256Base.TypeByteSz * 4)]
        private SHA256Base ctx_outside_reinit;
        #endregion

        public readonly int HashSz => ctx_inside.HashSz;

        public SHA256Base_HMAC(in InternalSHA256State constants, int outSz, in ReadOnlySpan<byte> key)
        {
            ctx_inside = new(constants, outSz);
            ctx_outside = new(constants, outSz);
            ctx_prehasher = new(constants, outSz);
            Reset(key);
        }

        public void Reset(in ReadOnlySpan<byte> key)
        {
            int keySz;

            Span<byte> key_used = stackalloc byte[InternalSHA256Block.TypeByteSz];
            Span<byte> block_opad = stackalloc byte[InternalSHA256Block.TypeByteSz];
            Span<byte> block_ipad = stackalloc byte[InternalSHA256Block.TypeByteSz];

            if (key.Length == InternalSHA256Block.TypeByteSz)
            {
                key.CopyTo(key_used);
                keySz = InternalSHA256Block.TypeByteSz;
            }
            else
            {
                if (key.Length > InternalSHA256Block.TypeByteSz)
                {
                    keySz = ctx_prehasher.HashSz;
                    ctx_prehasher.Reset();
                    ctx_prehasher.Update(key);
                    ctx_prehasher.Digest(key_used.Slice(0, ctx_prehasher.HashSz));
                }
                else
                {
                    key.CopyTo(key_used);
                    keySz = key.Length;
                }

                int fill = InternalSHA256Block.TypeByteSz - keySz;

                block_ipad.Slice(keySz, fill).Fill(0x36);
                block_opad.Slice(keySz, fill).Fill(0x5c);
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
            Span<byte> mac_temp = stackalloc byte[ctx_inside.HashSz];
            ctx_inside.Digest(mac_temp);
            ctx_outside.Update(mac_temp);
            ctx_outside.Digest(mac_temp);
            mac_temp.Slice(0, mac.Length).CopyTo(mac);
            Reset();
        }

        public void Reset()
        {
            ctx_inside.Reset(ctx_inside_reinit);
            ctx_outside.Reset(ctx_outside_reinit);
        }

        public void Dispose()
        {
            ctx_inside.Reset();
            ctx_outside.Reset();
            ctx_inside_reinit.Reset();
            ctx_outside_reinit.Reset();
        }
    }

    public struct HMAC_SHA224 : IMac
    {
        private SHA256Base_HMAC ctx;

        public HMAC_SHA224(ReadOnlySpan<byte> key)
        {
            ctx = new(InternalSHA256Constants.init_state_224, 28, key);
        }

        public int HashSz => ctx.HashSz;
        public void Digest(Span<byte> hash) => ctx.Digest(hash);
        public void Reset() => ctx.Reset();
        public void Reset(in ReadOnlySpan<byte> key) => ctx.Reset(key);
        public void Update(ReadOnlySpan<byte> input) => ctx.Update(input);
        public void Dispose() => ctx.Dispose();
    }

    public struct HMAC_SHA256 : IMac
    {
        private SHA256Base_HMAC ctx;

        public HMAC_SHA256(ReadOnlySpan<byte> key)
        {
            ctx = new(InternalSHA256Constants.init_state_256, 32, key);
        }

        public int HashSz => ctx.HashSz;
        public void Digest(Span<byte> hash) => ctx.Digest(hash);
        public void Reset() => ctx.Reset();
        public void Reset(in ReadOnlySpan<byte> key) => ctx.Reset(key);
        public void Update(ReadOnlySpan<byte> input) => ctx.Update(input);
        public void Dispose() => ctx.Dispose();
    }
}
