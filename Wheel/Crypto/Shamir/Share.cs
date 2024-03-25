using System;
using System.Runtime.InteropServices;
using Wheel.Crypto.Shamir.Internal;

namespace Wheel.Crypto.Shamir
{
    [StructLayout(LayoutKind.Explicit)]
    internal struct SharePoint
    {
        [FieldOffset(0)]
        public ShareByte X;
        [FieldOffset(1)]
        public ShareByte Y;

        public SharePoint(ShareByte x, ShareByte y)
        {
            X = x;
            Y = y;
        }
    }

    /// <summary>
    /// Share is an array of points
    /// </summary>
    public class Share
    {
        private SharePoint[] Points;

        /// <summary>
        /// Init empty share
        /// </summary>
        /// <param name="secretSize"></param>
        public Share(int secretSize)
        {
            Points = new SharePoint[secretSize];
        }

        public int Index
        {
            get => Points[0].X;
        }

        /// <summary>
        /// Decode share from binary data
        /// </summary>
        /// <param name="encoded"></param>
        /// <exception cref="InvalidDataException"></exception>
        public Share(ReadOnlySpan<byte> encoded)
        {
            if (encoded.Length < 2)
            {
                throw new InvalidDataException("Invalid share data length");
            }

            // Compact share format looks like this:
            // [share index] [coordinate 1] [coorddinate 2] ... [coordinate N]
            // The expanded share format looks like this:
            // [share index] [coordinate 1] [share index] [coorddinate 2] ... [share index] [coordinate N]
            Points = new SharePoint[encoded.Length - 1];
            for (int i = 1; i < encoded.Length; ++i)
            {
                Points[i - 1] = new SharePoint(encoded[0], encoded[i]);
            }
        }

        /// <summary>
        /// Compact encoding of share
        /// </summary>
        public ReadOnlySpan<byte> Raw
        {
            get
            {
                byte[] compact = new byte[Points.Length + 1];
                compact[0] = Points[0].X;
                for (int i = 0; i < Points.Length; ++i)
                {
                    compact[i + 1] = Points[i].Y;
                }
                return compact;
            }
        }

        internal SharePoint this[int index]
        {
            get => Points[index];
            set => Points[index] = value;
        }

        public int Length => Points.Length;
    }
}

