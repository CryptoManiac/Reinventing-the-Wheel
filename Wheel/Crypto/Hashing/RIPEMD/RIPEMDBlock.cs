using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Wheel.Crypto.Hashing.RIPEMD.Internal
{
    /// <summary>
    /// Access to individual block bytes through index operator
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public struct InternalRIPEMDBlockBytes
    {
        /// <summary>
        /// Index access to individual registers
        /// </summary>
        /// <param name="key">Byte field index [0 .. 63]</param>
        /// <returns>Word value</returns>
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
            if (index >= TypeByteSz)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. " + TypeByteSz + ") range");
            }

            unsafe
            {
                return data[index];
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void SetRegisterByte(uint index, byte value)
        {
            if (index >= TypeByteSz)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. " + TypeByteSz + ") range");
            }

            unsafe
            {
                data[index] = value;
            }
        }
        #endregion

        /// <summary>
        /// Set to zeros
        /// </summary>
        public unsafe void Reset()
        {
            fixed (void* ptr = &this)
            {
                new Span<byte>(ptr, TypeByteSz).Clear();
            }
        }

        /// <summary>
        /// Size of structure in memory when treated as a collection of bytes
        /// </summary>
        public const int TypeByteSz = InternalRIPEMDBlock.TypeByteSz;

        [FieldOffset(0)]
        private unsafe fixed byte data[TypeByteSz];
    }

    /// <summary>
    /// Represents the block data for the RIPEMD-160
    /// Note: Mostly identical to that of SHA-256
    /// </summary>
	[StructLayout(LayoutKind.Explicit)]
    public struct InternalRIPEMDBlock
    {
        /// <summary>
        /// Overwrite the part of value with a sequence of bytes
        /// </summary>
        /// <param name="bytes">Bytes to write</param>
        /// <param name="targetIndex">Offset to write them from the beginning of this vector</param>
        public unsafe void Write(ReadOnlySpan<byte> bytes, uint targetIndex)
        {
            // Target index must have a sane value
            if (targetIndex >= TypeByteSz)
            {
                throw new ArgumentOutOfRangeException(nameof(targetIndex), targetIndex, "targetIndex index must be within [0 .. " + TypeByteSz + ") range");
            }

            // Maximum size is a distance between the
            //  beginning and the vector size
            uint limit = TypeByteSz - targetIndex;

            if (bytes.Length > limit)
            {
                throw new ArgumentOutOfRangeException(nameof(bytes), bytes.Length, "byte sequence is too long");
            }

            fixed (void* ptr = &this)
            {
                Span<byte> target = new((byte*)ptr + targetIndex, bytes.Length);
                bytes.CopyTo(target);
            }
        }

        /// <summary>
        /// Index access to individual registers
        /// </summary>
        /// <param name="key">Field index [0 .. 7]</param>
        /// <returns>Word value</returns>
        public uint this[uint key]
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            readonly get => GetRegisterUint(key);
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            set => SetRegisterUint(key, value);
        }

        #region Register access logic
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private readonly uint GetRegisterUint(uint index)
        {
            if (index >= TypeUintSz)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. " + TypeUintSz + ") range");
            }

            unsafe
            {
                return registers[index];
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void SetRegisterUint(uint index, uint value)
        {
            if (index >= TypeUintSz)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. " + TypeUintSz + ") range");
            }

            unsafe
            {
                registers[index] = value;
            }
        }
        #endregion

        /// <summary>
        /// Set to zero
        /// </summary>
        public void Reset()
        {
            bytes.Reset();
        }

        /// <summary>
        /// Size of structure in memory when treated as a collection of bytes
        /// </summary>
        public const int TypeByteSz = 64;

        /// <summary>
        /// Size of structure in memory when treated as a collection of uint values
        /// </summary>
        public const int TypeUintSz = TypeByteSz / sizeof(uint);

        #region Fixed size buffer for registers
        [FieldOffset(0)]
        private unsafe fixed uint registers[TypeUintSz];
        #endregion

        /// <summary>
        /// Public access to the individual block bytes
        /// </summary>
        [FieldOffset(0)]
        public InternalRIPEMDBlockBytes bytes;

        #region Individual word public access
        [FieldOffset(0)]
        public uint X00;
        [FieldOffset(4)]
        public uint X01;
        [FieldOffset(8)]
        public uint X02;
        [FieldOffset(12)]
        public uint X03;

        [FieldOffset(16)]
        public uint X04;
        [FieldOffset(20)]
        public uint X05;
        [FieldOffset(24)]
        public uint X06;
        [FieldOffset(28)]
        public uint X07;

        [FieldOffset(32)]
        public uint X08;
        [FieldOffset(36)]
        public uint X09;
        [FieldOffset(40)]
        public uint X10;
        [FieldOffset(44)]
        public uint X11;

        [FieldOffset(48)]
        public uint X12;
        [FieldOffset(52)]
        public uint X13;
        [FieldOffset(56)]
        public uint X14;
        [FieldOffset(60)]
        public uint X15;
        #endregion
    }
}

