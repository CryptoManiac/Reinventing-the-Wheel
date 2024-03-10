using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Wheel.Crypto.Hashing.RIPEMD.Internal
{
    /// <summary>
    /// Access to individual block bytes through index operator
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public unsafe struct InternalRIPEMDBlockBytes
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
        private unsafe readonly byte GetRegisterByte(uint index)
        {
            ThrowOrPassByte(index);
            return data[index];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe void SetRegisterByte(uint index, byte value)
        {
            ThrowOrPassByte(index);
            data[index] = value;
        }

        static void ThrowOrPassByte(uint index)
        {
            if (index >= TypeByteSz)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. " + TypeByteSz + ") range");
            }
        }
        #endregion

        /// <summary>
        /// Size of structure in memory when treated as a collection of bytes
        /// </summary>
        static public readonly int TypeByteSz = sizeof(InternalRIPEMDBlockBytes);

        [FieldOffset(0)]
        private fixed byte data[64];
    }

    /// <summary>
    /// Represents the block data for the RIPEMD-160
    /// Note: Mostly identical to that of SHA-256
    /// </summary>
	[StructLayout(LayoutKind.Explicit)]
    public unsafe struct InternalRIPEMDBlock
    {
        /// <summary>
        /// Instantiate from array or a variable number of arguments
        /// </summary>
        /// <param name="uints"></param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public unsafe InternalRIPEMDBlock(params uint[] uints)
        {
            if (uints.Length != TypeUintSz)
            {
                throw new ArgumentOutOfRangeException(nameof(uints), uints.Length, "Must provide " + TypeUintSz + " arguments exactly");
            }

            fixed (void* source = &uints[0])
            {
                fixed (void* target = &this)
                {
                    new Span<byte>(source, TypeByteSz).CopyTo(new Span<byte>(target, TypeByteSz));
                }
            }
        }

        /// <summary>
        /// Instantiate as a copy of the other block
        /// </summary>
        /// <param name="round">Other block</param>
        public unsafe InternalRIPEMDBlock(in InternalRIPEMDBlock block)
        {
            fixed (void* source = &block)
            {
                fixed (void* target = &this)
                {
                    new Span<byte>(source, TypeByteSz).CopyTo(new Span<byte>(target, TypeByteSz));
                }
            }
        }

        /// <summary>
        /// Overwrite the part of value with a sequence of bytes
        /// </summary>
        /// <param name="bytes">Bytes to write</param>
        /// <param name="targetIndex">Offset to write them from the beginning of this vector</param>
        public unsafe void Write(Span<byte> bytes, uint targetIndex)
        {
            uint byteSz = (uint)TypeByteSz;

            // Target index must have a sane value
            if (targetIndex >= byteSz)
            {
                throw new ArgumentOutOfRangeException(nameof(targetIndex), targetIndex, "targetIndex index must be within [0 .. " + byteSz + ") range");
            }

            // Maximum size is a distance between the
            //  beginning and the vector size
            uint limit = byteSz - targetIndex;

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
        private unsafe readonly uint GetRegisterUint(uint index)
        {
            ThrowOrPassUint(index);
            return registers[index];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe void SetRegisterUint(uint index, uint value)
        {
            ThrowOrPassUint(index);
            registers[index] = value;
        }

        static void ThrowOrPassUint(uint index)
        {
            if (index >= TypeUintSz)
            {
                throw new ArgumentOutOfRangeException(nameof(index), index, "Index must be within [0 .. " + TypeUintSz + ") range");
            }
        }
        #endregion

        /// <summary>
        /// Set to zero
        /// </summary>
        public unsafe void Reset()
        {
            fixed (void* ptr = &this)
            {
                new Span<byte>(ptr, TypeByteSz).Clear();
            }
        }

        /// <summary>
        /// Size of structure in memory when treated as a collection of uint values
        /// </summary>
        static public readonly int TypeUintSz = sizeof(InternalRIPEMDBlock) / sizeof(uint);

        /// <summary>
        /// Size of structure in memory when treated as a collection of bytes
        /// </summary>
        static public readonly int TypeByteSz = sizeof(InternalRIPEMDBlock);

        #region Fixed size buffers for actual storage
        [FieldOffset(0)]
        private fixed byte data[64];
        [FieldOffset(0)]
        private fixed uint registers[16];
        #endregion

        /// <summary>
        /// Public access to the individual block bytes
        /// </summary>
        [FieldOffset(0)]
        public InternalRIPEMDBlockBytes bytes;

        #region Individual word public access
        [FieldOffset(0)]
        public uint X00 = 0;
        [FieldOffset(1 * sizeof(uint))]
        public uint X01 = 0;
        [FieldOffset(2 * sizeof(uint))]
        public uint X02 = 0;
        [FieldOffset(3 * sizeof(uint))]
        public uint X03 = 0;

        [FieldOffset(4 * sizeof(uint))]
        public uint X04 = 0;
        [FieldOffset(5 * sizeof(uint))]
        public uint X05 = 0;
        [FieldOffset(6 * sizeof(uint))]
        public uint X06 = 0;
        [FieldOffset(7 * sizeof(uint))]
        public uint X07 = 0;

        [FieldOffset(8 * sizeof(uint))]
        public uint X08 = 0;
        [FieldOffset(9 * sizeof(uint))]
        public uint X09 = 0;
        [FieldOffset(10 * sizeof(uint))]
        public uint X10 = 0;
        [FieldOffset(11 * sizeof(uint))]
        public uint X11 = 0;

        [FieldOffset(12 * sizeof(uint))]
        public uint X12 = 0;
        [FieldOffset(13 * sizeof(uint))]
        public uint X13 = 0;
        [FieldOffset(14 * sizeof(uint))]
        public uint X14 = 0;
        [FieldOffset(15 * sizeof(uint))]
        public uint X15 = 0;
        #endregion
    }
}

