using HTTPv3.Quic.Exceptions.Parsing;
using HTTPv3.Quic.Messages.Common;
using System;

namespace HTTPv3.Quic
{
    public static class ReadOnlyMemoryExtensions
    {
        public static ReadOnlyMemory<byte> Read(this ReadOnlyMemory<byte> bytesIn, out byte byteOut)
        {
            if (bytesIn.Length < 1) throw new NotEnoughBytesException($"Expecting 1 bytes but only have {bytesIn.Length} bytes left.");

            byteOut = bytesIn.Span[0];

            return bytesIn.Slice(1);
        }

        public static ReadOnlyMemory<byte> Read(this ReadOnlyMemory<byte> bytesIn, int numBytes, out byte[] bytesOut)
        {
            if (bytesIn.Length < numBytes) throw new NotEnoughBytesException($"Expecting {numBytes} bytes but only have {bytesIn.Length} bytes left.");

            bytesOut = bytesIn.Slice(0, numBytes).ToArray();

            return bytesIn.Slice(numBytes);
        }

        public static ReadOnlyMemory<byte> Read(this ReadOnlyMemory<byte> bytesIn, int numBytes, out ReadOnlyMemory<byte> bytesOut)
        {
            if (bytesIn.Length < numBytes) throw new NotEnoughBytesException($"Expecting {numBytes} bytes but only have {bytesIn.Length} bytes left.");

            bytesOut = bytesIn.Slice(0, numBytes);

            return bytesIn.Slice(numBytes);
        }

        public static ReadOnlyMemory<byte> Read(this ReadOnlyMemory<byte> bytesIn, int numBytes, out ushort value)
        {
            if (bytesIn.Length < numBytes) throw new NotEnoughBytesException($"Expecting {numBytes} bytes but only have {bytesIn.Length} bytes left.");

            value = bytesIn.Slice(0, numBytes).ToUInt16();

            return bytesIn.Slice(numBytes);
        }

        public static ReadOnlyMemory<byte> Read(this ReadOnlyMemory<byte> bytesIn, int numBytes, out uint value)
        {
            if (bytesIn.Length < numBytes) throw new NotEnoughBytesException($"Expecting {numBytes} bytes but only have {bytesIn.Length} bytes left.");

            value = bytesIn.Slice(0, numBytes).ToUInt32();

            return bytesIn.Slice(numBytes);
        }

        public static ReadOnlyMemory<byte> ReadNextTLSVariableLength(this ReadOnlyMemory<byte> bytesIn, int lengthNumBytes, out ReadOnlyMemory<byte> bytesOut)
        {
            if (bytesIn.Length < lengthNumBytes) throw new NotEnoughBytesException($"Expecting {lengthNumBytes} bytes but only have {bytesIn.Length} bytes left.");

            bytesIn = bytesIn.Read(lengthNumBytes, out uint length);
            if (bytesIn.Length < length) throw new NotEnoughBytesException($"Expecting {length} bytes but only have {bytesIn.Length} bytes left.");

            return bytesIn.Read((int)length, out bytesOut);
        }

        public static ReadOnlyMemory<byte> ReadNextVariableInt(this ReadOnlyMemory<byte> bytesIn, out int value)
        {
            int bytesUsed;

            VariableLengthInt.ReadOne(bytesIn.Span, out value, out bytesUsed);

            return bytesIn.Slice(bytesUsed);
        }

        public static ReadOnlyMemory<byte> ReadNextVariableInt(this ReadOnlyMemory<byte> bytesIn, out ulong value)
        {
            int bytesUsed;

            VariableLengthInt.ReadOne(bytesIn.Span, out value, out bytesUsed);

            return bytesIn.Slice(bytesUsed);
        }

        public static ReadOnlyMemory<byte> Skip(this ReadOnlyMemory<byte> bytesIn, in int numBytes)
        {
            return bytesIn.Slice(numBytes);
        }

        public static ushort ToUInt16(this ReadOnlyMemory<byte> bytes, bool isNetworkByteOrder = true)
        {
            return bytes.Span.ToUInt16(isNetworkByteOrder);
        }

        public static uint ToUInt32(this ReadOnlyMemory<byte> bytes, bool isNetworkByteOrder = true)
        {
            return bytes.Span.ToUInt32(isNetworkByteOrder);
        }
    }
}
