using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Common
{
    // IETF quic-transport draft-19
    // 16.  Variable-Length Integer Encoding
    // https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-16
    public class VariableLengthInt
    {
        public const ulong Max1Byte = 63;
        public const ulong Max2Byte = 16383;
        public const ulong Max4Byte = 1073741823;
        public const ulong Max8Byte = 4611686018427387903;

        const ulong ClearLengthMask = 0b0011_1111;

        public static void ReadOne(ReadOnlySpan<byte> bytes, out int value, out int bytesUsed)
        {
            ulong temp;
            ReadOne(bytes, out temp, out bytesUsed);

            if (temp > int.MaxValue) throw new ArithmeticException($"VariableLengthInt.ReadOne: Error trying to squeeze ulong into int");

            value = (int)temp;
        }

        public static void ReadOne(ReadOnlySpan<byte> bytes, out ulong value, out int bytesUsed)
        {
            value = 0;

            int lengthType = bytes[0] >> 6; // Look at first two bits

            if (lengthType == 0)
            {
                bytesUsed = 1;
                value = bytes[0] & ClearLengthMask;
                return;
            }

            if (lengthType == 1)
            {
                bytesUsed = 2;
                if (bytes.Length < bytesUsed) throw new ArithmeticException($"VariableLengthInt.ReadOne: Not enough bytes to read. Expecting {bytesUsed}, but only {bytes.Length} available.");

                value = ((bytes[0] & ClearLengthMask) << 8) + bytes[1];
                return;
            }

            if (lengthType == 2)
                bytesUsed = 4;
            else
                bytesUsed = 8;

            if (bytes.Length < bytesUsed) throw new ArithmeticException($"VariableLengthInt.ReadOne: Not enough bytes to read. Expecting {bytesUsed}, but only {bytes.Length} available.");

            value = bytes[0] & ClearLengthMask;

            for(int i = 1; i < bytesUsed; i++)
            {
                value <<= 8;
                value += bytes[i];
            }
        }

        public static int GetNumberOfBytesNeeded(ulong value)
        {
            if (value <= Max1Byte) return 1;
            if (value <= Max2Byte) return 2;
            if (value <= Max4Byte) return 4;
            if (value <= Max8Byte) return 8;

            return 0; // Value to large to be stored
        }

        public static int Write(ulong value, ref Span<byte> bytes)
        {
            if (value > Max8Byte) throw new ArithmeticException($"VariableLengthInt.Write: Value {value} too large to encode.");

            int numBytes = GetNumberOfBytesNeeded(value);

            if (bytes.Length < numBytes) throw new ArithmeticException($"VariableLengthInt.Write: Cannot fit {numBytes} into {bytes.Length}.");

            for (int i = numBytes - 1; i >= 0; i--)
            {
                bytes[i] = (byte)(value & 0xFF);
                value >>= 8;
            }

            if (numBytes == 2)
                bytes[0] |= 0b0100_0000;
            else if (numBytes == 4)
                bytes[0] |= 0b1000_0000;
            else if (numBytes == 8)
                bytes[0] |= 0b1100_0000;

            return numBytes;
        }
    }
}
