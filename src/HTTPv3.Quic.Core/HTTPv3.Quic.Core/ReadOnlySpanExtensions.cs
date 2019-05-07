using HTTPv3.Quic.Exceptions.Parsing;
using HTTPv3.Quic.Messages.Common;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic
{
    public static class ReadOnlySpanExtensions
    {
        public static ReadOnlySpan<byte> Read(this ReadOnlySpan<byte> bytesIn, out byte byteOut)
        {
            if (bytesIn.Length < 1) throw new NotEnoughBytesException($"Expecting 1 bytes but only have {bytesIn.Length} bytes left.");

            byteOut = bytesIn[0];

            return bytesIn.Slice(1);
        }

        public static ReadOnlySpan<byte> Read(this ReadOnlySpan<byte> bytesIn, int numBytes, out byte[] bytesOut)
        {
            if (bytesIn.Length < numBytes) throw new NotEnoughBytesException($"Expecting {numBytes} bytes but only have {bytesIn.Length} bytes left.");

            bytesOut = bytesIn.Slice(0, numBytes).ToArray();

            return bytesIn.Slice(numBytes);
        }

        public static ReadOnlySpan<byte> Read(this ReadOnlySpan<byte> bytesIn, int numBytes, out ReadOnlySpan<byte> bytesOut)
        {
            if (bytesIn.Length < numBytes) throw new NotEnoughBytesException($"Expecting {numBytes} bytes but only have {bytesIn.Length} bytes left.");

            bytesOut = bytesIn.Slice(0, numBytes);

            return bytesIn.Slice(numBytes);
        }

        public static ReadOnlySpan<byte> Read(this ReadOnlySpan<byte> bytesIn, int numBytes, out ushort value)
        {
            if (bytesIn.Length < numBytes) throw new NotEnoughBytesException($"Expecting {numBytes} bytes but only have {bytesIn.Length} bytes left.");

            value = bytesIn.Slice(0, numBytes).ToUInt16();

            return bytesIn.Slice(numBytes);
        }

        public static ReadOnlySpan<byte> Read(this ReadOnlySpan<byte> bytesIn, int numBytes, out uint value)
        {
            if (bytesIn.Length < numBytes) throw new NotEnoughBytesException($"Expecting {numBytes} bytes but only have {bytesIn.Length} bytes left.");

            value = bytesIn.Slice(0, numBytes).ToUInt32();

            return bytesIn.Slice(numBytes);
        }

        public static ReadOnlySpan<byte> ReadNextTLSVariableLength(this ReadOnlySpan<byte> bytesIn, int lengthNumBytes, out ReadOnlySpan<byte> bytesOut)
        {
            if (bytesIn.Length < lengthNumBytes) throw new NotEnoughBytesException($"Expecting {lengthNumBytes} bytes but only have {bytesIn.Length} bytes left.");

            bytesIn = bytesIn.Read(lengthNumBytes, out uint length);
            if (bytesIn.Length < length) throw new NotEnoughBytesException($"Expecting {length} bytes but only have {bytesIn.Length} bytes left.");

            return bytesIn.Read((int)length, out bytesOut);
        }

        public static ReadOnlySpan<byte> ReadNextVariableInt(this ReadOnlySpan<byte> bytesIn, out int value)
        {
            int bytesUsed;

            VariableLengthInt.ReadOne(bytesIn, out value, out bytesUsed);

            return bytesIn.Slice(bytesUsed);
        }

        public static ReadOnlySpan<byte> ReadNextVariableInt(this ReadOnlySpan<byte> bytesIn, out ulong value)
        {
            int bytesUsed;

            VariableLengthInt.ReadOne(bytesIn, out value, out bytesUsed);

            return bytesIn.Slice(bytesUsed);
        }

        public static ushort ToUInt16(this ReadOnlySpan<byte> span, bool isNetworkByteOrder = true)
        {
            int len = span.Length;
            if (len > 2) throw new ArithmeticException($"Cannot convert {len} bytes to UInt16");

            ushort num = 0;

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

        public static uint ToUInt32(this ReadOnlySpan<byte> span, bool isNetworkByteOrder = true)
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
