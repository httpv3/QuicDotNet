using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Frames
{
    internal enum FrameType : byte
    {
        Padding = 0x00,
        Ping = 0x01,
        Ack = 0x02,
        AckECN = 0x03,
        ResetStream = 0x04,
        StopSending = 0x05,
        Crypto = 0x06,
        NewToken = 0x07,
        MaxData = 0x10,
        MaxStreamData = 0x11,
        MaxStreamsBiDi = 0x12,
        MaxStreamsUniDi = 0x13,
        DataBlocked = 0x14,
        StreamDataBlocked = 0x15,
        StreamsBlockedBiDi = 0x16,
        StreamsBlockedUniDi = 0x17,
        NewConnectionId = 0x18,
        RetireConnectionId = 0x19,
        PathChallenge = 0x1a,
        PathResponse = 0x1b,
        ConnectionCloseQuic = 0x1c,
        ConnectionCloseApplication = 0x1d,

        Unknown = 0xFF,
    }

    internal static class FrameTypeExtensions
    {
        public static ReadOnlySpan<byte> Read(this in ReadOnlySpan<byte> bytesIn, out FrameType type)
        {
            var ret = bytesIn.Read(out byte val);

            type = ParseValue(val);

            return ret;
        }

        public static FrameType ParseValue(byte value)
        {
            if (Enum.IsDefined(typeof(FrameType), value))
                return (FrameType)value;

            return FrameType.Unknown;
        }

        public static Span<byte> Write(this in Span<byte> buffer, FrameType type)
        {
            return buffer.Write((byte)type);
        }
    }
}
