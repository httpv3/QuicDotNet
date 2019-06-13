using HTTPv3.Quic.Exceptions.Parsing;
using HTTPv3.Quic.Messages.Common;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Extensions
{
    public static class SpanExtensions
    {
        public static Span<byte> AddPadding(this in Span<byte> bytesIn, in int bytesToPad, in byte paddingByte = 0x0)
        {
            if (bytesToPad < 1)
                return bytesIn;

            bytesIn.Slice(0, bytesToPad).Fill(paddingByte);

            return bytesIn.Slice(bytesToPad);
        }

        public static Span<byte> PadToLength(this in Span<byte> buffer, in int currentLength, in int padToLength, in byte paddingByte = 0x0)
        {
            if (buffer.Length < padToLength) throw new NotEnoughBytesException($"Expecting {padToLength} bytes but only have {buffer.Length} bytes.");

            if (currentLength >= padToLength)
                return buffer.Slice(currentLength);

            return buffer.Slice(currentLength).AddPadding(padToLength - currentLength, paddingByte);
        }

        public static Span<byte> ReadByte(this in Span<byte> bytesIn, out byte byteToRead)
        {
            if (bytesIn.Length < 1) throw new NotEnoughBytesException($"Expecting 1 bytes but only have {bytesIn.Length} bytes left.");

            byteToRead = bytesIn[0];

            return bytesIn.Slice(1);
        }

        public static Span<byte> ReadBytes(this in Span<byte> bytesIn, in int numBytes, out Span<byte> bytesToRead)
        {
            if (bytesIn.Length < numBytes) throw new NotEnoughBytesException($"Expecting {numBytes} bytes but only have {bytesIn.Length} bytes left.");

            bytesToRead = bytesIn.Slice(0, numBytes);

            return bytesIn.Slice(numBytes);
        }

        public static Span<byte> ReadNumber(this in Span<byte> bytesIn, in int numBytes, out uint value)
        {
            if (bytesIn.Length < numBytes) throw new NotEnoughBytesException($"Expecting {numBytes} bytes but only have {bytesIn.Length} bytes left.");

            value = bytesIn.Slice(0, numBytes).ToUInt32();

            return bytesIn.Slice(numBytes);
        }

        public static Span<byte> ReadVariableInt(this in Span<byte> bytesIn, out int value)
        {
            int bytesUsed;

            VariableLengthInt.ReadOne(bytesIn, out value, out bytesUsed);

            return bytesIn.Slice(bytesUsed);
        }

        public static Span<byte> ReadVariableInt(this in Span<byte> bytesIn, out ulong value)
        {
            int bytesUsed;

            VariableLengthInt.ReadOne(bytesIn, out value, out bytesUsed);

            return bytesIn.Slice(bytesUsed);
        }

        public static Span<byte> Subtract(this in Span<byte> first, in Span<byte> second)
        {
            if (first.Length == 0) return first;
            if (second.Length == 0) return first;

            if (!first.Overlaps(second)) throw new DoesntOverlapException("SpanExtensions.Subtract: Spans do not overlap.");

            if (first.Length < second.Length) throw new NotEnoughBytesException($"SpanExtensions.Subtract: First smaller than second. {first.Length} < {second.Length}");

            return first.Slice(0, first.Length - second.Length);
        }

        public static uint ToUInt32(this in Span<byte> span, in bool isNetworkByteOrder = true)
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

        public static Span<byte> Write(this in Span<byte> buffer, in byte value)
        {
            const int numBytes = 1;

            if (buffer.Length < numBytes) throw new NotEnoughBytesException($"Expecting {numBytes} bytes but only have {buffer.Length} bytes left.");

            buffer[0] = value;

            return buffer.Slice(numBytes);
        }

        public static Span<byte> Write(this in Span<byte> buffer, in ReadOnlySpan<byte> bytesIn)
        {
            if (buffer.Length < bytesIn.Length) throw new NotEnoughBytesException($"Expecting {bytesIn.Length} bytes but only have {buffer.Length} bytes left.");

            bytesIn.CopyTo(buffer);

            return buffer.Slice(bytesIn.Length);
        }

        public static Span<byte> Write(this in Span<byte> buffer, in Span<byte> bytesIn)
        {
            if (buffer.Length < bytesIn.Length) throw new NotEnoughBytesException($"Expecting {bytesIn.Length} bytes but only have {buffer.Length} bytes left.");

            bytesIn.CopyTo(buffer);

            return buffer.Slice(bytesIn.Length);
        }

        public static Span<byte> Write(this in Span<byte> buffer, in ushort value) => buffer.Write(value, 2);

        public static Span<byte> Write(this in Span<byte> buffer, in uint value) => buffer.Write(value, 4);

        public static Span<byte> Write(this in Span<byte> buffer, in ulong value) => buffer.Write(value, 8);

        public static Span<byte> Write(this in Span<byte> buffer, in long value, in int lengthNumBytes) => buffer.Write((ulong)value, lengthNumBytes);

        public static Span<byte> Write(this in Span<byte> buffer, ulong value, in int lengthNumBytes)
        {
            if (buffer.Length < lengthNumBytes) throw new NotEnoughBytesException($"Expecting {lengthNumBytes} bytes but only have {buffer.Length} bytes left.");

            for (int i = lengthNumBytes - 1; i >= 0; i--, value >>= 8)
                buffer[i] = (byte)(value & 0xFF);

            return buffer.Slice(lengthNumBytes);
        }

        public static Span<byte> WriteTLSVariableLength(this in Span<byte> buffer, in int lengthNumBytes, in Span<byte> bytesToWrite)
        {
            if (buffer.Length < lengthNumBytes + bytesToWrite.Length) throw new NotEnoughBytesException($"Expecting {lengthNumBytes + bytesToWrite.Length} bytes but only have {buffer.Length} bytes left.");

            return buffer.Write((ulong)bytesToWrite.Length, lengthNumBytes)
                         .Write(bytesToWrite);
        }
    }
}
