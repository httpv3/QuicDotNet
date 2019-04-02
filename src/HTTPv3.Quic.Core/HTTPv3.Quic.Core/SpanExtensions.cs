using HTTPv3.Quic.Exceptions.Parsing;
using HTTPv3.Quic.Messages.Common;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic
{
    public static class SpanExtensions
    {
        public static Span<byte> ReadNextByte(this Span<byte> bytesIn, out byte byteToRead)
        {
            if (bytesIn.Length < 1) throw new NotEnoughBytesException($"Expecting 1 bytes but only have {bytesIn.Length} bytes left.");

            byteToRead = bytesIn[0];

            return bytesIn.Slice(1);
        }

        public static Span<byte> ReadNextBytes(this Span<byte> bytesIn, int numBytes, out Span<byte> bytesToRead)
        {
            if (bytesIn.Length < numBytes) throw new NotEnoughBytesException($"Expecting {numBytes} bytes but only have {bytesIn.Length} bytes left.");

            bytesToRead = bytesIn.Slice(0, numBytes);

            return bytesIn.Slice(numBytes);
        }

        public static Span<byte> ReadNextNumber(this Span<byte> bytesIn, int numBytes, out uint value)
        {
            if (bytesIn.Length < numBytes) throw new NotEnoughBytesException($"Expecting {numBytes} bytes but only have {bytesIn.Length} bytes left.");

            value = bytesIn.Slice(0, numBytes).ToUInt32();

            return bytesIn.Slice(numBytes);
        }

        public static Span<byte> ReadNextVariableInt(this Span<byte> bytesIn, out int value)
        {
            int bytesUsed;

            VariableLengthInt.ReadOne(bytesIn, out value, out bytesUsed);

            return bytesIn.Slice(bytesUsed);
        }

        public static Span<byte> ReadNextVariableInt(this Span<byte> bytesIn, out ulong value)
        {
            int bytesUsed;

            VariableLengthInt.ReadOne(bytesIn, out value, out bytesUsed);

            return bytesIn.Slice(bytesUsed);
        }

        public static uint ToUInt32(this Span<byte> span, bool isNetworkByteOrder = true)
        {
            int len = span.Length;
            if (len > 4) throw new ArithmeticException($"Cannot convert {len} bytes to UInt32");

            uint num = 0;

            if (isNetworkByteOrder)
            {
                for (int i = 0; i < len; i++)
                {
                    num <<= 8;
                    num |= span[i];
                }

                return num;
            }
            else
            {
                for (int i = len - 1; i >= 0; i--)
                {
                    num <<= 8;
                    num |= span[i];
                }

                return num;
            }
        }
    }
}
