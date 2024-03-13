using System.Runtime.InteropServices;
using Wheel.Crypto.Hashing.SHA.SHA512;
using Wheel.Crypto.Hashing.SHA.SHA512.Internal;

namespace Wheel.Crypto.Hashing.HMAC.SHA2
{
	[StructLayout(LayoutKind.Explicit)]
    public struct SHA512Base_HMAC : IMac
    {
        [FieldOffset(0)]
        private SHA512Base ctx_inside = new();

        [FieldOffset(SHA512Base.TypeByteSz)]
        private SHA512Base ctx_outside = new();

        #region For Reset()
        [FieldOffset(SHA512Base.TypeByteSz * 2)]
        private SHA512Base ctx_inside_reinit = new();

        [FieldOffset(SHA512Base.TypeByteSz * 3)]
        private SHA512Base ctx_outside_reinit = new();
        #endregion

        // For key pre-hashing
        [FieldOffset(SHA512Base.TypeByteSz * 4)]
        private SHA512Base ctx_prehasher;

        public int HashSz => ctx_inside.HashSz;

        public SHA512Base_HMAC(in InternalSHA512State constants, int outSz, in ReadOnlySpan<byte> key)
        {
            ctx_inside = new(constants, outSz);
            ctx_outside = new(constants, outSz);
            ctx_prehasher = new(constants, outSz);
            Reset(key);
        }

        public void Reset(in ReadOnlySpan<byte> key)
        {
            int keySz;

            Span<byte> key_used = stackalloc byte[InternalSHA512Block.TypeByteSz];
            Span<byte> block_opad = stackalloc byte[InternalSHA512Block.TypeByteSz];
            Span<byte> block_ipad = stackalloc byte[InternalSHA512Block.TypeByteSz];

            if (key.Length == InternalSHA512Block.TypeByteSz)
            {
                key.CopyTo(key_used);
                keySz = InternalSHA512Block.TypeByteSz;
            }
            else
            {
                if (key.Length > InternalSHA512Block.TypeByteSz)
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

                int fill = InternalSHA512Block.TypeByteSz - keySz;

                block_ipad.Slice(keySz).Fill(0x36);
                block_opad.Slice(keySz).Fill(0x5c);
            }

            for (int i = 0; i < keySz; i++)
            {
                block_ipad[i] = (byte)(key_used[i] ^ 0x36);
                block_opad[i] = (byte)(key_used[i] ^ 0x5c);
            }

            ctx_inside.Reset();
            ctx_inside.Update(block_ipad);

            ctx_outside.Reset();
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
            Reset();
        }

        public void Reset()
        {
            ctx_inside.Reset(ctx_inside_reinit);
            ctx_outside.Reset(ctx_outside_reinit);
        }
    }

    public struct HMAC_SHA512_224 : IMac
    {
        private SHA512Base_HMAC ctx;

        public HMAC_SHA512_224(ReadOnlySpan<byte> key)
        {
            ctx = new(InternalSHA512Constants.init_state_224, 28, key);
        }

        public int HashSz => ctx.HashSz;
        public void Digest(Span<byte> hash) => ctx.Digest(hash);
        public void Reset() => ctx.Reset();
        public void Reset(in ReadOnlySpan<byte> key) => ctx.Reset(key);
        public void Update(ReadOnlySpan<byte> input) => ctx.Update(input);
    }

    public struct HMAC_SHA512_256 : IMac
    {
        private SHA512Base_HMAC ctx;

        public HMAC_SHA512_256(ReadOnlySpan<byte> key)
        {
            ctx = new(InternalSHA512Constants.init_state_256, 32, key);
        }

        public int HashSz => ctx.HashSz;
        public void Digest(Span<byte> hash) => ctx.Digest(hash);
        public void Reset() => ctx.Reset();
        public void Reset(in ReadOnlySpan<byte> key) => ctx.Reset(key);
        public void Update(ReadOnlySpan<byte> input) => ctx.Update(input);
    }

    public struct HMAC_SHA384 : IMac
    {
        private SHA512Base_HMAC ctx;

        public HMAC_SHA384(ReadOnlySpan<byte> key)
        {
            ctx = new(InternalSHA512Constants.init_state_384, 48, key);
        }

        public int HashSz => ctx.HashSz;
        public void Digest(Span<byte> hash) => ctx.Digest(hash);
        public void Reset() => ctx.Reset();
        public void Reset(in ReadOnlySpan<byte> key) => ctx.Reset(key);
        public void Update(ReadOnlySpan<byte> input) => ctx.Update(input);
    }

    public struct HMAC_SHA512 : IMac
    {
        private SHA512Base_HMAC ctx;

        public HMAC_SHA512(ReadOnlySpan<byte> key)
        {
            ctx = new(InternalSHA512Constants.init_state_512, 64, key);
        }

        public int HashSz => ctx.HashSz;
        public void Digest(Span<byte> hash) => ctx.Digest(hash);
        public void Reset() => ctx.Reset();
        public void Reset(in ReadOnlySpan<byte> key) => ctx.Reset(key);
        public void Update(ReadOnlySpan<byte> input) => ctx.Update(input);
    }
}
