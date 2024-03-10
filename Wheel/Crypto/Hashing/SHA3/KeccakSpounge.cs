using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Wheel.Crypto.Hashing.SHA3.Internal;

namespace Wheel.Crypto.Hashing.SHA3.Internal
{
    /// <summary>
    /// Access to individual spounge bytes through index operator
    /// </summary>
	[StructLayout(LayoutKind.Explicit)]
    public unsafe struct InternalKeccakSpoungeBytes
    {
        /// <summary>
        /// Index access to individual bytes
        /// </summary>
        /// <param name="key">Byte field index</param>
        /// <returns>Byte value</returns>
        public byte this[uint key]
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            readonly get => GetRegisterByte(key);
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            set => SetRegisterByte(key, value);
        }

        #region Byte access logic
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private readonly byte GetRegisterByte(uint index)
        {
            int byteSz = KeccakConstants.SHA3_SPONGE_WORDS * 8;
            if (0 > index || index >= byteSz)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. " + byteSz * 8 + ") range");
            }
            return data[index];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void SetRegisterByte(uint index, byte value)
        {
            int byteSz = KeccakConstants.SHA3_SPONGE_WORDS * 8;
            if (0 > index || index >= byteSz)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. " + byteSz * 8 + ") range");
            }
            data[index] = value;
        }
        #endregion

        /// <summary>
        /// Dump vector contents
        /// </summary>
        /// <param name="to"></param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public unsafe readonly void Store(Span<byte> to)
        {
            int byteSz = KeccakConstants.SHA3_SPONGE_WORDS * 8;

            if (to.Length > byteSz)
            {
                throw new ArgumentOutOfRangeException(nameof(to), to.Length, "Span must not be longer than " + byteSz + " bytes");
            }

            fixed (void* source = &this)
            {
                new Span<byte>(source, to.Length).CopyTo(to);
            }
        }

        [FieldOffset(0)]
        private fixed byte data[KeccakConstants.SHA3_SPONGE_WORDS * 8];
    }

    /// <summary>
    /// Represents a spounge, an analog of round variables context for SHA3 function
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
	public struct KeccakSpounge
	{
		public KeccakSpounge()
		{
            Reset();
		}

        /// <summary>
        /// Index access to individual registers
        /// </summary>
        /// <param name="key">Field index</param>
        /// <returns>Word value</returns>
        public ulong this[uint key]
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            readonly get => GetRegisterUlong(key);
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            set => SetRegisterUlong(key, value);
        }

        #region Register access logic
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe readonly ulong GetRegisterUlong(uint index)
        {
            if (index >= KeccakConstants.SHA3_SPONGE_WORDS)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. " + KeccakConstants.SHA3_SPONGE_WORDS + ") range");
            }
            return registers[index];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe void SetRegisterUlong(uint index, ulong value)
        {
            if (index >= KeccakConstants.SHA3_SPONGE_WORDS)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. " + KeccakConstants.SHA3_SPONGE_WORDS + ") range");
            }
            registers[index] = value;
        }
        #endregion

        /// <summary>
        /// Set to zero
        /// </summary>
        public unsafe void Reset()
        {
            fixed (void* ptr = &this)
            {
                new Span<byte>(ptr, KeccakConstants.SHA3_SPONGE_WORDS * 8).Clear();
            }
        }

        [FieldOffset(0)]
        private unsafe fixed ulong registers[KeccakConstants.SHA3_SPONGE_WORDS];

        [FieldOffset(0)]
        public InternalKeccakSpoungeBytes bytes;
    }
}

