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

        public static Span<byte> WriteNextByte(this Span<byte> bufferIn, byte value)
        {
            const int numBytes = 1;

            if (bufferIn.Length < numBytes) throw new NotEnoughBytesException($"Expecting {numBytes} bytes but only have {bufferIn.Length} bytes left.");

            bufferIn[0] = value;

            return bufferIn.Slice(numBytes);
        }

        public static Span<byte> WriteNextBytes(this Span<byte> bufferIn, Span<byte> bytesIn)
        {
            if (bufferIn.Length < bytesIn.Length) throw new NotEnoughBytesException($"Expecting {bytesIn.Length} bytes but only have {bufferIn.Length} bytes left.");

            bytesIn.CopyTo(bufferIn);

            return bufferIn.Slice(bytesIn.Length);
        }

        public static Span<byte> WriteNextNumber(this Span<byte> bufferIn, ushort value)
        {
            const int numBytes = 2;

            if (bufferIn.Length < numBytes) throw new NotEnoughBytesException($"Expecting {numBytes} bytes but only have {bufferIn.Length} bytes left.");

            bufferIn[1] = (byte)(value & 0xFF);
            bufferIn[0] = (byte)((value >>= 8) & 0xFF);

            return bufferIn.Slice(numBytes);
        }

        public static Span<byte> WriteNextNumber(this Span<byte> bufferIn, uint value)
        {
            const int numBytes = 4;

            if (bufferIn.Length < numBytes) throw new NotEnoughBytesException($"Expecting {numBytes} bytes but only have {bufferIn.Length} bytes left.");

            bufferIn[3] = (byte)(value & 0xFF);
            bufferIn[2] = (byte)((value >>= 8) & 0xFF);
            bufferIn[1] = (byte)((value >>= 8) & 0xFF);
            bufferIn[0] = (byte)((value >>= 8) & 0xFF);

            return bufferIn.Slice(numBytes);
        }

        public static Span<byte> WriteNextNumber(this Span<byte> bufferIn, ulong value)
        {
            const int numBytes = 8;

            if (bufferIn.Length < numBytes) throw new NotEnoughBytesException($"Expecting {numBytes} bytes but only have {bufferIn.Length} bytes left.");

            bufferIn[7] = (byte)(value & 0xFF);
            bufferIn[6] = (byte)((value >>= 8) & 0xFF);
            bufferIn[5] = (byte)((value >>= 8) & 0xFF);
            bufferIn[4] = (byte)((value >>= 8) & 0xFF);
            bufferIn[3] = (byte)((value >>= 8) & 0xFF);
            bufferIn[2] = (byte)((value >>= 8) & 0xFF);
            bufferIn[1] = (byte)((value >>= 8) & 0xFF);
            bufferIn[0] = (byte)((value >>= 8) & 0xFF);

            return bufferIn.Slice(numBytes);
        }
    }
}
