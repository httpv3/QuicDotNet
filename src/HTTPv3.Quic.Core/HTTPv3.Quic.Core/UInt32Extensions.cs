using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic
{
    public static class UInt32Extensions
    {
        public static Span<byte> ToSpan(this uint value, int numBytes = 4)
        {
            var bytes = new byte[numBytes];

            for (int i = numBytes -1; i >= 0; i--)
            {
                bytes[i] = (byte)(value % 256);
                value >>= 8;
            }

            return bytes;
        }
    }
}
