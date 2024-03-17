namespace Wheel.Crypto.Elliptic
{
	public static class ECSig
	{
		/// <summary>
		/// Converts compact signature to DER format.
		/// No-op if the DER buffer is insufficient.
		/// </summary>
		/// <param name="der">Will be filled with DER signature</param>
		/// <param name="compact">Compact signature to serialize</param>
		/// <returns>Length of data written or to be written into DER buffer</returns>
		public static int CompactToDER(ECCurve curve, Span<byte> der, ReadOnlySpan<byte> compact)
        {
			byte lenR = (byte) curve.NUM_BYTES;
            byte lenS = (byte) curve.NUM_BYTES;

			int reqLen = 6 + lenS + lenR;

			if (der.Length >= reqLen)
			{

                der[0] = 0x30;
                der[1] = (byte) (4 + lenS + lenR);
                der[2] = 0x02;
                der[3] = lenR;
                der[4 + lenR] = 0x02;
                der[5 + lenR] = lenS;

				// Split compact signature
                ReadOnlySpan<byte> R = compact.Slice(0, lenR);
                ReadOnlySpan<byte> S = compact.Slice(lenR, lenS);

                // Places where R and S will be written
                Span<byte> R_der = der.Slice(4, lenR);
                Span<byte> S_der = der.Slice(6 + lenR, lenS);

				R.CopyTo(R_der);
				S.CopyTo(S_der);
            }

            return reqLen;
        }

        /// <summary>
        /// Based on parse_der_lax routine from bitcoin distribution
        /// </summary>
        /// <param name="der"></param>
        /// <param name="compact"></param>
        /// <returns></returns>
		public static bool DerToCompact(ReadOnlySpan<byte> input, Span<byte> compact)
		{
            int rpos, rlen, spos, slen;
            int pos = 0;
            int lenbyte;

            int inputlen = input.Length;

            /* Sequence tag byte */
            if (pos == inputlen || input[pos] != 0x30)
            {
                return false;
            }
            pos++;

            /* Sequence length bytes */
            if (pos == inputlen)
            {
                return false;
            }
            lenbyte = input[pos++];
            if ((lenbyte & 0x80) != 0)
            {
                lenbyte -= 0x80;
                if (lenbyte > inputlen - pos)
                {
                    return false;
                }
                pos += lenbyte;
            }

            /* Integer tag byte for R */
            if (pos == inputlen || input[pos] != 0x02)
            {
                return false;
            }
            pos++;

            /* Integer length for R */
            if (pos == inputlen)
            {
                return false;
            }
            lenbyte = input[pos++];
            if (Convert.ToBoolean(lenbyte & 0x80))
            {
                lenbyte -= 0x80;
                if (lenbyte > inputlen - pos)
                {
                    return false;
                }
                while (lenbyte > 0 && input[pos] == 0)
                {
                    pos++;
                    lenbyte--;
                }
                if (lenbyte >= 4)
                {
                    return false;
                }
                rlen = 0;
                while (lenbyte > 0)
                {
                    rlen = (rlen << 8) + input[pos];
                    pos++;
                    lenbyte--;
                }
            }
            else
            {
                rlen = lenbyte;
            }
            if (rlen > inputlen - pos)
            {
                return false;
            }
            rpos = pos;
            pos += rlen;

            /* Integer tag byte for S */
            if (pos == inputlen || input[pos] != 0x02)
            {
                return false;
            }
            pos++;

            /* Integer length for S */
            if (pos == inputlen)
            {
                return false;
            }
            lenbyte = input[pos++];
            if (Convert.ToBoolean(lenbyte & 0x80))
            {
                lenbyte -= 0x80;
                if (lenbyte > inputlen - pos)
                {
                    return false;
                }
                while (lenbyte > 0 && input[pos] == 0)
                {
                    pos++;
                    lenbyte--;
                }
                if (lenbyte >= 4)
                {
                    return false;
                }
                slen = 0;
                while (lenbyte > 0)
                {
                    slen = (slen << 8) + input[pos];
                    pos++;
                    lenbyte--;
                }
            }
            else
            {
                slen = lenbyte;
            }
            if (slen > inputlen - pos)
            {
                return false;
            }
            spos = pos;

            /* Copy R value */
            if (rlen > 32)
            {
                /* Overflow */
                return false;
            }
            else
            {
                input.Slice(rpos, rlen).CopyTo(compact.Slice(32 - rlen));
            }

            /* Copy S value */
            if (slen > 32)
            {
                /* Overflow */
                return false;
            }
            else
            {
                input.Slice(spos, slen).CopyTo(compact.Slice(64 - slen));
            }

            return true;

        }
    }
}

