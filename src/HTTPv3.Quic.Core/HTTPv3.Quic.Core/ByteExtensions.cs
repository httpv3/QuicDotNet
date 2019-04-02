using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic
{
    public static class ByteExtensions
    {
        public static int ToInt32(this byte[] bytes, bool allowAnyInput = false)
        {
            if (!allowAnyInput)
            {
                if (bytes == null || bytes.Length != 4)
                    throw new ArithmeticException("ByteExtensions.ToInt32: Needs 4 bytes.");
            }
            else
            {
                if (bytes == null) return 0;
            }

            int len = Math.Min(bytes.Length, 4);

            int ret = 0;

            for (int i = 0; i < len; i++)
            {
                ret <<= 8;
                ret += bytes[i];
            }

            return ret;
        }
    }
}
