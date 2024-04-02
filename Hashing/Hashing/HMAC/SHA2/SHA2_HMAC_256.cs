using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Hashing.SHA.SHA256;
using Wheel.Hashing.SHA.SHA256.Internal;

namespace Wheel.Hashing.HMAC.SHA2
{
	[StructLayout(LayoutKind.Explicit)]
    internal struct SHA256Base_HMAC : IMac
	{
		[FieldOffset(0)]
		private SHA256Base inside;

        [FieldOffset(SHA256Base.TypeByteSz)]
        private SHA256Base outside;

        // For key pre-hashing
        [FieldOffset(SHA256Base.TypeByteSz * 2)]
        private SHA256Base prehasher;

        #region For Reinit()
        [FieldOffset(SHA256Base.TypeByteSz * 3)]
        private SHA256Base inside_reinit;

        [FieldOffset(SHA256Base.TypeByteSz * 4)]
        private SHA256Base outside_reinit;
        #endregion

        [FieldOffset(SHA256Base.TypeByteSz * 5)]
        private bool initialized;

        public readonly int HashSz => inside.HashSz;

        public SHA256Base_HMAC(in InternalSHA256State constants, int outSz)
        {
            inside = outside = prehasher = inside_reinit = outside_reinit = new(constants, outSz);
            initialized = false;
        }

        [SkipLocalsInit]
        public void Init(ReadOnlySpan<byte> key)
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
                    keySz = prehasher.HashSz;
                    prehasher.Reset();
                    prehasher.Update(key);
                    prehasher.Digest(key_used.Slice(0, prehasher.HashSz));
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

            for (int i = 0; i < keySz; ++i)
            {
                block_ipad[i] = (byte) (key_used[i] ^ 0x36);
                block_opad[i] = (byte) (key_used[i] ^ 0x5c);
            }

            inside.Reset();
            outside.Reset();

            inside.Update(block_ipad);
            outside.Update(block_opad);

            // for Reset()
            inside_reinit = inside;
            outside_reinit = outside;

            // Allow update/digest calls
            initialized = true;
        }

        public void Update(ReadOnlySpan<byte> message)
        {
            if (!initialized)
            {
                throw new InvalidOperationException("Trying to update the uninitialized HMAC structure. Please call the Init() method first.");
            }
            inside.Update(message);
        }

        [SkipLocalsInit]
        public void Digest(Span<byte> mac)
        {
            if (!initialized)
            {
                throw new InvalidOperationException("Trying to get a Digest() result from the uninitialized HMAC structure. Please call the Init() method first.");
            }
            Span<byte> mac_temp = stackalloc byte[inside.HashSz];
            inside.Digest(mac_temp);
            outside.Update(mac_temp);
            outside.Digest(mac_temp);
            mac_temp.Slice(0, mac.Length).CopyTo(mac);
            Reset();
        }

        public void Reset()
        {
            inside = inside_reinit;
            outside = outside_reinit;
        }

        public void Dispose()
        {
            initialized = false;
            inside.Reset();
            outside.Reset();
            inside_reinit.Reset();
            outside_reinit.Reset();
        }

        public readonly IMac Clone()
        {
            return this;
        }
    }

    public struct HMAC_SHA224 : IMac
    {
        private SHA256Base_HMAC ctx;

        public HMAC_SHA224()
        {
            ctx = new(InternalSHA256Constants.init_state_224, 28);
        }

        public int HashSz => ctx.HashSz;
        public void Digest(Span<byte> hash) => ctx.Digest(hash);
        public void Reset() => ctx.Reset();
        public void Init(ReadOnlySpan<byte> key) => ctx.Init(key);
        public void Update(ReadOnlySpan<byte> input) => ctx.Update(input);
        public void Dispose() => ctx.Dispose();
        public readonly IMac Clone() => ctx.Clone();
    }

    public struct HMAC_SHA256 : IMac
    {
        private SHA256Base_HMAC ctx;

        public HMAC_SHA256()
        {
            ctx = new(InternalSHA256Constants.init_state_256, 32);
        }

        public int HashSz => ctx.HashSz;
        public void Digest(Span<byte> hash) => ctx.Digest(hash);
        public void Reset() => ctx.Reset();
        public void Init(ReadOnlySpan<byte> key) => ctx.Init(key);
        public void Update(ReadOnlySpan<byte> input) => ctx.Update(input);
        public void Dispose() => ctx.Dispose();
        public readonly IMac Clone() => ctx.Clone();
    }
}
